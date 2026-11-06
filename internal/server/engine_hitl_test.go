package server

// engine_hitl_test.go — P2 HITL engine 半边的 DSN 门控测试：
//   - pause=park（P2-5）：有映射钥匙的任务 Pause 不 cancel 执行上下文，钥匙消费
//     后恢复 cancel 语义；
//   - decide→停靠投递（P2-3）：DeliverHitlDecision 给停靠中的 run 投递签名决定
//     并消费一次性钥匙；无停靠运行 → requiresRerun 劣化；
//   - reaper（P2-4）：到点仍 pending 按 audit 固化策略落 timeout 决定（deny 与
//     allow 两策略）；未到点不动；无停靠运行时清 checkpoint（P2-6 劣化）；
//   - 重领重建（P2-3）：hitlResumeSeed 指纹匹配返回指令并消费钥匙、指纹不匹配
//     P2-6 回退且钥匙保留。

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
)

func hitlEngine(t *testing.T) (*Engine, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	m := &Manager{pg: d, interceptor: intercept.New(d)}
	return NewEngine(m), d
}

// hitlPending creates a pending row (audit 固化超时策略) + mapping for the tests.
func hitlPending(t *testing.T, d *db.DB, taskID, tool string, timeoutSecs int, timeoutAction string) (pendingID int64, cpID string) {
	t.Helper()
	audit := &db.InterceptAudit{
		Correlation: "unavailable", InputDigest: "digest-" + tool, CapturedAt: time.Now().UTC(),
		InitialAction: "ask", InitialReason: "测试规则命中", ExecutionStatus: "not_started",
		AskTimeoutEnabled: timeoutSecs > 0, AskTimeoutSeconds: timeoutSecs, AskTimeoutAction: timeoutAction,
	}
	pid, err := d.CreateInterceptPending(0, 0, taskID, "tester", tool, []byte(`{"q":"1"}`), "测试规则命中", "rule", audit)
	if err != nil {
		t.Fatalf("CreateInterceptPending: %v", err)
	}
	cpID = "cp-eng-" + tool + "-" + taskID
	if err := d.SaveHitlMapping(pid, cpID, "int-"+taskID, taskID); err != nil {
		t.Fatalf("SaveHitlMapping: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid)
		_, _ = d.Exec(`DELETE FROM runner_checkpoints WHERE checkpoint_id=$1`, cpID)
	})
	return pid, cpID
}

func TestHitlPauseParksWaitingRun(t *testing.T) {
	e, d := hitlEngine(t)
	const taskID = "task-hitl-park"
	pid, _ := hitlPending(t, d, taskID, "park_probe", 0, "deny")

	execCtx := e.execContextFor(context.Background(), taskID)
	e.Pause(taskID, agent.AbortPausedByUser)
	if execCtx.Err() != nil {
		t.Fatal("审批挂起的任务 Pause 不得 cancel 执行上下文（park 语义）")
	}
	// 钥匙消费后恢复 cancel 语义。
	if err := d.ConsumeHitlMapping(pid); err != nil {
		t.Fatalf("ConsumeHitlMapping: %v", err)
	}
	e.Pause(taskID, agent.AbortPausedByUser)
	if execCtx.Err() == nil {
		t.Fatal("无挂起钥匙的任务 Pause 应恢复 cancel 语义")
	}
}

func TestHitlDecideDeliversToParkedRun(t *testing.T) {
	e, d := hitlEngine(t)
	const taskID = "task-hitl-deliver"
	pid, cpID := hitlPending(t, d, taskID, "deliver_probe", 0, "deny")

	// 停靠中的 run（与任务 worker 同款钩子；任务不在内存 → TaskStatus("") 非
	// 终态 → 停靠持续等待）。
	type parkedOut struct {
		resume *db.HitlResumeData
		ok     bool
	}
	out := make(chan parkedOut, 1)
	go func() {
		resume, ok := e.hitlParkHook(0, &askernel.HitlInterrupt{
			CheckpointID: cpID, InterruptID: "int-" + taskID, PendingID: pid, Tool: "deliver_probe",
		})
		out <- parkedOut{resume, ok}
	}()
	// 有界等待停靠注册（禁短 sleep：轮询 parks 直到注册生效）。
	waitFor(t, 5*time.Second, func() bool {
		_, ok := e.parksMap().Load(pid)
		return ok
	})

	// 决定落库（ResolveIntercept 走哈希链）→ 投递签名决定。
	if ok, err := d.ResolveIntercept(pid, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept: ok=%v err=%v", ok, err)
	}
	delivered, requiresRerun := e.DeliverHitlDecision(pid, true)
	if !delivered || requiresRerun {
		t.Fatalf("decide 应投递到停靠运行: delivered=%v requiresRerun=%v", delivered, requiresRerun)
	}
	p := <-out
	if !p.ok || p.resume == nil {
		t.Fatalf("停靠钩子应收到恢复数据: %+v", p)
	}
	if !p.resume.Allowed || p.resume.PendingID != pid {
		t.Fatalf("投递的恢复数据不完整: %+v", p.resume)
	}
	// 决定行 id 绑定（guard 验签的库行核对基础）。
	decisionID, ok, _ := d.LastInterceptDecisionID(pid)
	if !ok || p.resume.DecisionID != decisionID {
		t.Fatalf("恢复数据应带真实决定行 id: got=%d want=%d", p.resume.DecisionID, decisionID)
	}
	// 一次性钥匙已消费。
	if cp, _, _, err := d.HitlMapping(pid); err != nil || cp != "" {
		t.Fatalf("投递后映射钥匙应已消费: cp=%q err=%v", cp, err)
	}
	// 无钥匙的重复投递走劣化（requiresRerun）。
	delivered, requiresRerun = e.DeliverHitlDecision(pid, true)
	if delivered || !requiresRerun {
		t.Fatalf("钥匙已消费的重复投递应走劣化: delivered=%v requiresRerun=%v", delivered, requiresRerun)
	}
}

func TestHitlReaperTimeoutStrategies(t *testing.T) {
	e, d := hitlEngine(t)

	// 超时 deny（audit 固化 1s，时钟注入 2h 后扫描）→ timeout/deny + 无停靠清理。
	pidDeny, cpDeny := hitlPending(t, d, "task-hitl-reap-deny", "reap_deny_probe", 1, "deny")
	if err := d.SetCheckpoint(context.Background(), cpDeny, []byte("payload")); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}
	e.reapHitlAt(time.Now().Add(2 * time.Hour))
	assertDecision(t, d, pidDeny, "timeout", "deny")
	if _, ok, _ := d.GetCheckpoint(context.Background(), cpDeny); ok {
		t.Fatal("无停靠运行的超时收尾应清 checkpoint（P2-6 劣化）")
	}

	// 超时 allow（固化策略 allow）→ timeout/allow（放行语义经同一条链）。
	pidAllow, _ := hitlPending(t, d, "task-hitl-reap-allow", "reap_allow_probe", 1, "allow")
	e.reapHitlAt(time.Now().Add(2 * time.Hour))
	assertDecision(t, d, pidAllow, "timeout", "allow")

	// 未到点：不收尾。
	pidFresh, _ := hitlPending(t, d, "task-hitl-reap-fresh", "reap_fresh_probe", 3600, "deny")
	e.reapHitlAt(time.Now())
	if decision, _ := hitlDecision(t, d, pidFresh); decision != "" {
		t.Fatalf("未到点的审批不得被 reaper 收尾，got %q", decision)
	}
}

// 评审第 1 轮 #1 的补口回归：决定**先于**停靠注册到达（同轮多工具乱序决定 /
// PersistAsk→Store 窗口内的 decide / 重启前落库的决定）——decide 对已决行 409
// 不会再投递、reaper 排除已决行，停靠钩子必须自查库中已有决定自投递，否则
// 停靠运行卡死到任务删除。
func TestHitlParkSelfDeliversAlreadyDecidedPending(t *testing.T) {
	e, d := hitlEngine(t)
	const taskID = "task-hitl-selfdeliver"
	pid, cpID := hitlPending(t, d, taskID, "self_probe", 0, "deny")

	// 决定先落库（此时该 pending 还没有停靠）。
	if ok, err := d.ResolveIntercept(pid, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept: ok=%v err=%v", ok, err)
	}
	// decide 通道对这种时序只能走劣化（映射尚不存在）。
	if delivered, _ := e.DeliverHitlDecision(pid, true); delivered {
		t.Fatal("无映射时 decide 通道不应声称已投递")
	}

	// 停靠：钩子必须在注册后自查库中已有决定并返回签名恢复数据（有界预算，
	// 轮询粒度 2s）。
	type parkedOut struct {
		resume *db.HitlResumeData
		ok     bool
	}
	out := make(chan parkedOut, 1)
	go func() {
		resume, ok := e.hitlParkHook(0, &askernel.HitlInterrupt{
			CheckpointID: cpID, InterruptID: "int-" + taskID, PendingID: pid, Tool: "self_probe",
		})
		out <- parkedOut{resume, ok}
	}()
	deadline := time.Now().Add(15 * time.Second)
	var p parkedOut
	for {
		select {
		case p = <-out:
		case <-time.After(time.Until(deadline)):
			t.Fatal("停靠钩子未在预算内自查投递库中已有决定（死锁回归）")
		}
		break
	}
	if !p.ok || p.resume == nil || !p.resume.Allowed {
		t.Fatalf("自投递的恢复数据不完整: %+v", p)
	}
	decisionID, ok, _ := d.LastInterceptDecisionID(pid)
	if !ok || p.resume.DecisionID != decisionID {
		t.Fatalf("自投递应带真实决定行 id: got=%d want=%d", p.resume.DecisionID, decisionID)
	}
	// 钥匙一次性：自投递即消费。
	if cp, _, _, err := d.HitlMapping(pid); err != nil || cp != "" {
		t.Fatalf("自投递后钥匙应已消费: cp=%q err=%v", cp, err)
	}

	// denied 的乱序决定走同一条自投递（guard 验签后以「人工拒绝」拦截）。
	pid2, cpID2 := hitlPending(t, d, taskID, "self_deny_probe", 0, "deny")
	if ok, err := d.ResolveIntercept(pid2, "denied", "deny", "人工拒绝执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept(denied): ok=%v err=%v", ok, err)
	}
	out2 := make(chan parkedOut, 1)
	go func() {
		resume, ok := e.hitlParkHook(0, &askernel.HitlInterrupt{
			CheckpointID: cpID2, InterruptID: "int-" + taskID, PendingID: pid2, Tool: "self_deny_probe",
		})
		out2 <- parkedOut{resume, ok}
	}()
	deadline2 := time.Now().Add(15 * time.Second)
	var p2 parkedOut
	for {
		select {
		case p2 = <-out2:
		case <-time.After(time.Until(deadline2)):
			t.Fatal("denied 的自投递未在预算内返回")
		}
		break
	}
	if !p2.ok || p2.resume == nil || p2.resume.Allowed {
		t.Fatalf("denied 的自投递方向不符: %+v", p2)
	}
}

func TestHitlResumeSeedFingerprintGate(t *testing.T) {
	e, d := hitlEngine(t)
	const taskID = "task-hitl-seed"
	const sessionID = "sess-hitl-seed"
	pid, cpID := hitlPending(t, d, taskID, "seed_probe", 0, "deny")
	if err := d.SetCheckpoint(context.Background(), cpID, []byte("payload")); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}
	if err := d.RecordRunnerCheckpoint(context.Background(), sessionID, "worker", cpID, "fp-good"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	if ok, err := d.ResolveIntercept(pid, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept: ok=%v err=%v", ok, err)
	}

	// 指纹匹配 → 返回指令并消费钥匙（一次性）。
	directives := e.hitlResumeSeed(sessionID, "fp-good")
	if len(directives) != 1 {
		t.Fatalf("指纹匹配应返回 1 条续跑指令，got %d", len(directives))
	}
	dir := directives[0]
	if dir.CheckpointID != cpID || dir.InterruptID != "int-"+taskID || !dir.Resume.Allowed {
		t.Fatalf("续跑指令字段不完整: %+v", dir)
	}
	decisionID, ok, _ := d.LastInterceptDecisionID(pid)
	if !ok || dir.Resume.DecisionID != decisionID {
		t.Fatalf("指令应带真实决定行 id: got=%d want=%d", dir.Resume.DecisionID, decisionID)
	}
	if cp, _, _, err := d.HitlMapping(pid); err != nil || cp != "" {
		t.Fatalf("种子消费应删钥匙: cp=%q err=%v", cp, err)
	}
	// 第二次取（钥匙已消费）为空——同一决定不会被重放二次执行。
	if got := e.hitlResumeSeed(sessionID, "fp-good"); len(got) != 0 {
		t.Fatalf("钥匙消费后不应再产出指令，got %d", len(got))
	}

	// 指纹不匹配 → P2-6 回退：不返回指令、钥匙保留（决定在库，运行侧重跑）。
	pid2, cpID2 := hitlPending(t, d, taskID, "seed_fp_probe", 0, "deny")
	if err := d.SetCheckpoint(context.Background(), cpID2, []byte("payload")); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}
	if err := d.RecordRunnerCheckpoint(context.Background(), sessionID, "worker", cpID2, "fp-recorded"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	if ok, err := d.ResolveIntercept(pid2, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept: ok=%v err=%v", ok, err)
	}
	if got := e.hitlResumeSeed(sessionID, "fp-drifted"); len(got) != 0 {
		t.Fatalf("指纹不匹配必须走 P2-6 回退（不续跑），got %d 条", len(got))
	}
	// 回退即刻消费钥匙（评审第 1 轮 #3）：决定照常在库、运行侧按重跑收尾；
	// 钥匙滞留会把该任务的 Pause 短路成空操作（P2-5 判定点）。
	if cp, _, _, err := d.HitlMapping(pid2); err != nil || cp != "" {
		t.Fatalf("回退路径钥匙应即刻消费（Pause 判定点不再被死钥匙短路）: cp=%q err=%v", cp, err)
	}
}

// --- helpers ---

func waitFor(t *testing.T, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("条件未在预算内达成")
}

func assertDecision(t *testing.T, d *db.DB, pendingID int64, decision, action string) {
	t.Helper()
	gotDecision, gotAction := hitlDecision(t, d, pendingID)
	if gotDecision != decision || gotAction != action {
		t.Fatalf("决定行不符: got (%q,%q) want (%q,%q)", gotDecision, gotAction, decision, action)
	}
}

func hitlDecision(t *testing.T, d *db.DB, pendingID int64) (decision, action string) {
	t.Helper()
	row := d.QueryRow(`SELECT decision, action FROM intercept_decisions WHERE pending_id=$1`, pendingID)
	if err := row.Scan(&decision, &action); err != nil {
		return "", ""
	}
	return decision, action
}
