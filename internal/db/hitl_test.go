package db

// hitl_test.go — P2 HITL 持久层的 DSN 门控测试（ZRECO_PG_DSN 缺省 skip，与
// intent_dedup_test 同款门控）：
//   - CheckPointStore 语义：Get/Set 往返、同 id 复写（re-interrupt）、payload
//     上限拒绝、DeleteCheckpointsBySession；
//   - 映射表：Save/Hitl/Consume（一次性钥匙）、HasHitlPendingCheckpoint；
//   - 决定签名：SignHitlResume/VerifyHitlResume 对 allowed/denied/timeout 各自
//     的核对方向、伪造签名不可放行；
//   - reaper 输入：PendingHitlApprovals 只含未决行并带 audit 固化超时；
//   - 重领重建输入：DecidedHitlResumesForSession 按会话取已决未消费钥匙。

import (
	"context"
	"testing"
	"time"
)

func hitlTestDB(t *testing.T) *DB {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// hitlPendingRow 落一条 pending 行并返回 id（audit 带 ask 固化超时）。
func hitlPendingRow(t *testing.T, d *DB, tool string) int64 {
	t.Helper()
	id, err := d.CreateInterceptPending(0, 0, "", "tester", tool, []byte(`{"q":"1"}`), "测试规则命中", "rule", &InterceptAudit{
		Correlation: "unavailable", InputDigest: "digest-" + tool, CapturedAt: time.Now().UTC(),
		InitialAction: "ask", InitialReason: "测试规则命中", ExecutionStatus: "not_started",
		AskTimeoutEnabled: true, AskTimeoutSeconds: 90, AskTimeoutAction: "deny",
	})
	if err != nil {
		t.Fatalf("CreateInterceptPending: %v", err)
	}
	return id
}

func TestHitlCheckpointStoreRoundTripAndRewrite(t *testing.T) {
	d := hitlTestDB(t)
	ctx := context.Background()
	store := d.AsCheckpointStore()
	pid := hitlPendingRow(t, d, "rt_probe")
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid) })

	// Set → Get 往返（且只命中 payload 非空的行——指纹留痕行不被读到）。
	payload := []byte("checkpoint-bytes-1")
	if err := store.Set(ctx, "cp-rt-1", payload); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := store.Get(ctx, "cp-rt-1")
	if err != nil || !ok || string(got) != string(payload) {
		t.Fatalf("Get 往返失败: ok=%v err=%v got=%q", ok, err, string(got))
	}

	// re-interrupt 复写：同一 checkpoint id 二次 Set 覆盖（ON CONFLICT DO UPDATE）。
	if err := store.Set(ctx, "cp-rt-1", []byte("checkpoint-bytes-2")); err != nil {
		t.Fatalf("Set(rewrite): %v", err)
	}
	got, _, _ = store.Get(ctx, "cp-rt-1")
	if string(got) != "checkpoint-bytes-2" {
		t.Fatalf("同 id 复写失败，got=%q", string(got))
	}

	// 装配留痕行与 checkpoint 行共存：RecordRunnerCheckpoint 把指纹绑到同一行
	//（恢复校验基准）；无指纹行/空 checkpoint id 的留痕行不参与 Get。
	if err := d.RecordRunnerCheckpoint(ctx, "sess-rt", "worker", "cp-rt-1", "fp-abc"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	fp, version, ok, err := d.HitlCheckpointMeta("cp-rt-1")
	if err != nil || !ok || fp != "fp-abc" || version != CheckpointVersion {
		t.Fatalf("HitlCheckpointMeta 应读到装配指纹: fp=%q v=%d ok=%v err=%v", fp, version, ok, err)
	}

	// payload 上限兜底（Go 侧拒绝，schema CHECK 同值兜底）。
	if err := store.Set(ctx, "cp-rt-big", make([]byte, CheckpointPayloadLimit+1)); err == nil {
		t.Fatal("超上限 payload 必须被拒绝")
	}

	// 任务终态清理：按会话删（连带映射钥匙）。
	if err := d.SaveHitlMapping(pid, "cp-rt-1", "int-1", "task-rt"); err != nil {
		t.Fatalf("SaveHitlMapping: %v", err)
	}
	if err := d.DeleteCheckpointsBySession("sess-rt"); err != nil {
		t.Fatalf("DeleteCheckpointsBySession: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "cp-rt-1"); ok {
		t.Fatal("按会话清理后 checkpoint 应不存在")
	}
	if cp, _, _, err := d.HitlMapping(pid); err != nil || cp != "" {
		t.Fatalf("按会话清理应连带删映射钥匙: cp=%q err=%v", cp, err)
	}
}

func TestHitlMappingOneShotKey(t *testing.T) {
	d := hitlTestDB(t)
	pid := hitlPendingRow(t, d, "map_probe")
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid) })

	if err := d.SaveHitlMapping(pid, "cp-map-1", "int-9", "task-1"); err != nil {
		t.Fatalf("SaveHitlMapping: %v", err)
	}
	cp, ii, tid, err := d.HitlMapping(pid)
	if err != nil || cp != "cp-map-1" || ii != "int-9" || tid != "task-1" {
		t.Fatalf("HitlMapping: cp=%q ii=%q tid=%q err=%v", cp, ii, tid, err)
	}
	has, err := d.HasHitlPendingCheckpoint("task-1")
	if err != nil || !has {
		t.Fatalf("HasHitlPendingCheckpoint 应为真: has=%v err=%v", has, err)
	}
	// 重挂（re-interrupt 换 checkpoint）复写同一钥匙。
	if err := d.SaveHitlMapping(pid, "cp-map-2", "int-9", "task-1"); err != nil {
		t.Fatalf("SaveHitlMapping(rewrite): %v", err)
	}
	cp, _, _, _ = d.HitlMapping(pid)
	if cp != "cp-map-2" {
		t.Fatalf("重挂应复写 checkpoint id，got=%q", cp)
	}
	// 消费即删（一次性钥匙）。
	if err := d.ConsumeHitlMapping(pid); err != nil {
		t.Fatalf("ConsumeHitlMapping: %v", err)
	}
	cp, ii, _, err = d.HitlMapping(pid)
	if err != nil || cp != "" || ii != "" {
		t.Fatalf("消费后映射应为空: cp=%q ii=%q err=%v", cp, ii, err)
	}
}

func TestHitlResumeSignatureVerification(t *testing.T) {
	d := hitlTestDB(t)
	pid := hitlPendingRow(t, d, "sig_probe")
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid) })

	// allowed 决定：签名核对方向一致。
	if ok, err := d.ResolveIntercept(pid, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept(allowed): ok=%v err=%v", ok, err)
	}
	decisionID, ok, err := d.LastInterceptDecisionID(pid)
	if err != nil || !ok {
		t.Fatalf("LastInterceptDecisionID: ok=%v err=%v", ok, err)
	}
	if !d.VerifyHitlResume(d.SignHitlResume(pid, decisionID, true)) {
		t.Fatal("allowed 的签名恢复数据应通过校验")
	}
	// 方向不符不可放行（把 deny 冒充 allowed 决定）。
	if d.VerifyHitlResume(d.SignHitlResume(pid, decisionID, false)) {
		t.Fatal("方向不符的恢复数据不可放行")
	}
	// 伪造签名不可放行。
	forged := d.SignHitlResume(pid, decisionID, true)
	forged.Sig = "deadbeef"
	if d.VerifyHitlResume(forged) {
		t.Fatal("伪造签名的恢复数据不可放行")
	}
	// 决定行号张冠李戴不可放行。
	other := d.SignHitlResume(pid, decisionID, true)
	other.DecisionID++
	if d.VerifyHitlResume(other) {
		t.Fatal("决定行号不匹配的恢复数据不可放行")
	}

	// timeout 决定按 action 核对（TimeoutAction=allow 的超时放行经同一条链）。
	pid2 := hitlPendingRow(t, d, "sig_timeout")
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid2) })
	if ok, err := d.ResolveIntercept(pid2, "timeout", "allow", "审批超时，按超时策略处理", "", "timeout"); err != nil || !ok {
		t.Fatalf("ResolveIntercept(timeout/allow): ok=%v err=%v", ok, err)
	}
	tid2, ok2, err2 := d.LastInterceptDecisionID(pid2)
	if err2 != nil || !ok2 {
		t.Fatalf("LastInterceptDecisionID(timeout): ok=%v err=%v", ok2, err2)
	}
	if !d.VerifyHitlResume(d.SignHitlResume(pid2, tid2, true)) {
		t.Fatal("timeout(allow) 的恢复数据应通过校验（Allowed=true）")
	}
	if d.VerifyHitlResume(d.SignHitlResume(pid2, tid2, false)) {
		t.Fatal("timeout(allow) 的恢复数据以 Allowed=false 不可放行")
	}
}

func TestHitlPendingApprovalsAndReclaimSeed(t *testing.T) {
	d := hitlTestDB(t)
	pid := hitlPendingRow(t, d, "reap_probe")
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pid)
		_, _ = d.Exec(`DELETE FROM runner_checkpoints WHERE checkpoint_id LIKE 'cp-reap%'`)
	})

	// reaper 输入：映射存在 + 未决 → 扫描行带 audit 固化超时。
	if err := d.SaveHitlMapping(pid, "cp-reap-1", "int-1", "task-reap"); err != nil {
		t.Fatalf("SaveHitlMapping: %v", err)
	}
	rows, err := d.PendingHitlApprovals()
	if err != nil {
		t.Fatalf("PendingHitlApprovals: %v", err)
	}
	var found *PendingHitlApproval
	for i := range rows {
		if rows[i].PendingID == pid {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatal("未决审批应出现在 reaper 扫描中")
	}
	if found.CheckpointID != "cp-reap-1" || found.TaskID != "task-reap" {
		t.Fatalf("扫描行映射不完整: %+v", found)
	}
	if found.AskTimeoutSeconds != 90 || found.AskTimeoutAction != "deny" {
		t.Fatalf("audit 固化超时应随行带出: %+v", found)
	}

	// 重领重建输入：决定后 + 钥匙未消费 + checkpoint（带指纹）在 → 按会话取回。
	if err := d.SetCheckpoint(context.Background(), "cp-reap-1", []byte("payload")); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}
	if err := d.RecordRunnerCheckpoint(context.Background(), "sess-reap", "worker", "cp-reap-1", "fp-reap"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	if ok, err := d.ResolveIntercept(pid, "allowed", "allow", "人工允许执行", "tester", "human"); err != nil || !ok {
		t.Fatalf("ResolveIntercept: ok=%v err=%v", ok, err)
	}
	seeds, err := d.DecidedHitlResumesForSession("sess-reap")
	if err != nil {
		t.Fatalf("DecidedHitlResumesForSession: %v", err)
	}
	var seed *DecidedHitlResume
	for i := range seeds {
		if seeds[i].PendingID == pid {
			seed = &seeds[i]
		}
	}
	if seed == nil {
		t.Fatal("已决未消费的审批应出现在重领种子中")
	}
	if seed.CheckpointID != "cp-reap-1" || seed.InterruptID != "int-1" || seed.Fingerprint != "fp-reap" || seed.Decision != "allowed" {
		t.Fatalf("重领种子字段不完整: %+v", seed)
	}
	// 决定后不再出现在 reaper 扫描。
	rows, _ = d.PendingHitlApprovals()
	for _, r := range rows {
		if r.PendingID == pid {
			t.Fatal("已决审批不应再出现在 reaper 扫描中")
		}
	}
	// 钥匙消费后不再出现在重领种子。
	if err := d.ConsumeHitlMapping(pid); err != nil {
		t.Fatalf("ConsumeHitlMapping: %v", err)
	}
	seeds, _ = d.DecidedHitlResumesForSession("sess-reap")
	for _, s := range seeds {
		if s.PendingID == pid {
			t.Fatal("钥匙消费后不应再出现在重领种子中")
		}
	}
}
