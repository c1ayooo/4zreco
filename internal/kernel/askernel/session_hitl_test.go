package askernel

// session_hitl_test.go — P2 HITL 全链的内核级验收（docs/Eino深度接入方案
// -2026-11-05.md §4-P2 验收口径；禁短 sleep，全部由决定投递驱动，无时间断言）：
//
//   - ask → StatefulInterrupt → checkpoint 落盘（内存 store 断言 payload 存在）
//     → run 以 awaiting_approval 终态收场，工具未执行；
//   - allowed → ResumeApproval 从 checkpoint 续跑：该工具执行恰好一次、不再
//     重审（重入不重复 ask），run 自然完成；
//   - denied → 工具不执行，管控文本作 tool_result 回给模型，run 继续；
//   - 「进程重启」：新 Session 从 transcript 重建（ResumeForApproval 保留尾部
//     tool_use）+ 同一 checkpoint store → 续跑该工具不重审（跨进程恢复链）；
//   - 同轮两工具同时 ask：聚合中断 → 逐个决定逐个续跑（未命中 re-interrupt），
//     两工具各执行一次；
//   - checkpoint 被清（模拟载荷丢失/损坏）→ 续跑以错误终态收场（P2-6 劣化：
//     运行侧不阻塞，宿主重跑）。
//
// 决定验签的 HMAC/库行核对在 db 层测（internal/db/hitl_test.go，DSN 门控）；
// 本文件的 hooks 桩以同等结构（db.HitlResumeFrom + 方向/绑定核对）模拟 guard 的
// 恢复放行分支，聚焦内核机制本身。

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/harness"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/kernel/termmap"
)

// memStore is an in-memory adk.CheckPointStore（结构化满足；内核测试不连 PG）。
type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Get(_ context.Context, id string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[id]
	return append([]byte(nil), b...), ok, nil
}

func (m *memStore) Set(_ context.Context, id string, cp []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[id] = append([]byte(nil), cp...)
	return nil
}

func (m *memStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
	return nil
}

func (m *memStore) has(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[id]
	return ok
}

func (m *memStore) drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
}

// recModel is a scripted model that also records model-call inputs（拒绝路径的
// tool_result 断言用）。
type recModel struct {
	mu     sync.Mutex
	inputs []string
	steps  []func() (*schema.Message, error)
	call   int
}

func (m *recModel) script(step func() (*schema.Message, error)) { m.steps = append(m.steps, step) }

func (m *recModel) record(in []*schema.Message) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	for _, msg := range in {
		if msg.Role == schema.Tool {
			// 工具结果：Role=Tool 的消息本体（Content 即 tool_result 文本）。
			b.WriteString("toolresult:" + msg.Content + "\n")
			continue
		}
		b.WriteString(string(msg.Role) + ":" + msg.Content + "\n")
		for _, tc := range msg.ToolCalls {
			b.WriteString("toolcall:" + tc.Function.Name + "\n")
		}
	}
	s := b.String()
	m.inputs = append(m.inputs, s)
	return s
}

func (m *recModel) Generate(ctx context.Context, in []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.record(in)
	m.mu.Lock()
	call := m.call
	m.call++
	m.mu.Unlock()
	if call < len(m.steps) {
		return m.steps[call]()
	}
	return schema.AssistantMessage("done", nil), nil
}

func (m *recModel) Stream(ctx context.Context, in []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *recModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) { return m, nil }

func (m *recModel) lastInput() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.inputs) == 0 {
		return ""
	}
	return m.inputs[len(m.inputs)-1]
}

// hitlTestHooks 模拟 guard 的 eino-mode 行为：ask 分支落「内存 pending」并把
// 挂起写进 ctx 信号（gate 升格为 StatefulInterrupt）；恢复重入核对
// db.HitlResumeFrom 的方向与调用绑定后放行/拦截（与 guard.applyHitlResume 同构）。
type hitlTestHooks struct {
	mu       sync.Mutex
	seq      int64
	pendings map[int64]*db.HitlAskInfo
	binds    map[int64]string // pendingID → 本次 ask 的 (tool, input) 绑定
	asks     int              // ask 次数（重入不得重复 ask）
}

func newHitlHooks() *hitlTestHooks {
	return &hitlTestHooks{pendings: map[int64]*db.HitlAskInfo{}, binds: map[int64]string{}}
}

func (h *hitlTestHooks) askCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.asks
}

// decide 产出签名外形的恢复数据（真实 HMAC 签发/核对在 db 层测）。
func (h *hitlTestHooks) decide(pendingID int64, allowed bool) *db.HitlResumeData {
	return &db.HitlResumeData{PendingID: pendingID, DecisionID: pendingID * 10, Allowed: allowed, Sig: "test"}
}

func (h *hitlTestHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	// 恢复重入：核对决定与本次调用的绑定（guard.applyHitlResume 同构——
	// 方向 + pending 对得上才放行；不匹配按拒绝收口）。
	if r := db.HitlResumeFrom(ctx); r != nil {
		h.mu.Lock()
		ask := h.pendings[r.PendingID]
		bound := ask != nil && ask.Tool == name && h.binds[r.PendingID] == name+":"+string(input)
		h.mu.Unlock()
		if !bound || r.Sig == "" || r.DecisionID != r.PendingID*10 {
			return true, "【4ZRECO 平台管控·非目标防御】审批恢复数据校验失败，本次调用不放行。", nil
		}
		if !r.Allowed {
			return true, "【4ZRECO 平台管控·非目标防御】人工审批未通过（用户拒绝执行）。", nil
		}
		return false, "", nil
	}
	// 首轮：ask → 落库段（内存 pending）+ 信号（gate 以 StatefulInterrupt 中断）。
	h.mu.Lock()
	h.asks++
	h.seq++
	pid := h.seq
	info := &db.HitlAskInfo{PendingID: pid, Tool: name, Kind: "rule", Reason: "测试规则命中"}
	h.pendings[pid] = info
	h.binds[pid] = name + ":" + string(input)
	h.mu.Unlock()
	db.RaiseAskInterrupt(ctx, info)
	return false, "", nil
}

func (h *hitlTestHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}

func askProbe(name string, ran *int) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "probe",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			*ran++
			return actool.Text(name + " ran"), nil
		},
	})
}

// hitlSession builds a session with the checkpoint store armed and a scripted
// model: call 0 → one tool call per tool; call 1 → final text.
func hitlSession(t *testing.T, store *memStore, hooks *hitlTestHooks, tools []actool.CoreTool, sid string, tx *transcript.Store) (*Session, *recModel) {
	t.Helper()
	m := &recModel{}
	m.script(func() (*schema.Message, error) {
		calls := make([]schema.ToolCall, 0, len(tools))
		for i, tl := range tools {
			calls = append(calls, schema.ToolCall{
				ID:       "c-" + tl.Name(),
				Function: schema.FunctionCall{Name: tl.Name(), Arguments: `{"q":"` + string(rune('1'+i)) + `"}`},
			})
		}
		return schema.AssistantMessage("", calls), nil
	})
	m.script(func() (*schema.Message, error) { return schema.AssistantMessage("完成", nil), nil })
	return hitlSessionWithModel(t, store, hooks, tools, sid, tx, m), m
}

// hitlSessionWithModel assembles a session over a caller-supplied model（重启
// 重建用：重建进程的第一次模型调用就是「续跑后的收尾」，脚本下标重排）。
func hitlSessionWithModel(t *testing.T, store *memStore, hooks *hitlTestHooks, tools []actool.CoreTool, sid string, tx *transcript.Store, m *recModel) *Session {
	t.Helper()
	opts := Options{
		Model:           m,
		SystemPrompt:    []string{"hitl test"},
		Tools:           tools,
		PermissionMode:  acperm.ModeBypass,
		MaxConcurrency:  2,
		CheckpointStore: store,
		Hooks:           hooks,
		SessionID:       sid,
	}
	if tx != nil {
		opts.Transcript = tx
	}
	return NewSession(opts)
}

// runOnce drains one session run and returns the terminal.
func runOnce(t *testing.T, events iter.Seq2[harness.Event, error]) *harness.Terminal {
	t.Helper()
	var term *harness.Terminal
	for ev, err := range events {
		if err != nil {
			t.Fatalf("run error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			term = ev.Terminal
		}
	}
	return term
}

func TestHitlAskInterruptsAndResumesAllowed(t *testing.T) {
	store := newMemStore()
	hooks := newHitlHooks()
	ran := 0
	probe := askProbe("probe", &ran)
	sess, _ := hitlSession(t, store, hooks, []actool.CoreTool{probe}, "hitl-allowed", nil)
	ctx := context.Background()

	// 1. 首轮：ask → 中断 → awaiting_approval，工具未执行，checkpoint 落盘。
	term := runOnce(t, sess.Prompt(ctx, "做点事"))
	if term == nil || term.Reason != termmap.AwaitingApproval {
		t.Fatalf("首轮应以待审批终态收场，got %+v", term)
	}
	if ran != 0 {
		t.Fatalf("中断的工具不应已执行，ran=%d", ran)
	}
	hitl := sess.Interrupt()
	if hitl == nil || hitl.PendingID == 0 || hitl.InterruptID == "" || hitl.CheckpointID == "" {
		t.Fatalf("中断描述不完整: %+v", hitl)
	}
	if !store.has(hitl.CheckpointID) {
		t.Fatalf("checkpoint 未落盘: %s", hitl.CheckpointID)
	}

	// 2. allowed → ResumeApproval → 工具恰好执行一次、不再重审 → run 完成。
	term = runOnce(t, sess.ResumeApproval(ctx, hitl.CheckpointID, hitl.InterruptID, hooks.decide(hitl.PendingID, true)))
	if term == nil || term.Reason != harness.ReasonCompleted {
		t.Fatalf("allowed 续跑应完成，got %+v", term)
	}
	if ran != 1 {
		t.Fatalf("工具应恰好执行一次，ran=%d", ran)
	}
	if hooks.askCount() != 1 {
		t.Fatalf("续跑不得重审（应只 ask 一次），asks=%d", hooks.askCount())
	}
}

func TestHitlDeniedContinuesWithControlText(t *testing.T) {
	store := newMemStore()
	hooks := newHitlHooks()
	ran := 0
	probe := askProbe("probe", &ran)
	sess, m := hitlSession(t, store, hooks, []actool.CoreTool{probe}, "hitl-denied", nil)
	ctx := context.Background()

	term := runOnce(t, sess.Prompt(ctx, "做点事"))
	if term == nil || term.Reason != termmap.AwaitingApproval {
		t.Fatalf("首轮应以待审批终态收场，got %+v", term)
	}
	hitl := sess.Interrupt()
	if hitl == nil {
		t.Fatal("中断描述缺失")
	}

	// denied → 工具不执行，管控文本作 tool_result 回给模型，run 继续。
	term = runOnce(t, sess.ResumeApproval(ctx, hitl.CheckpointID, hitl.InterruptID, hooks.decide(hitl.PendingID, false)))
	if term == nil || term.Reason != harness.ReasonCompleted {
		t.Fatalf("denied 后 run 应继续到完成，got %+v", term)
	}
	if ran != 0 {
		t.Fatalf("denied 的工具不应执行，ran=%d", ran)
	}
	if !strings.Contains(m.lastInput(), "人工审批未通过") {
		t.Fatalf("denied 的管控文本应回给模型，got: %s", m.lastInput())
	}
}

func TestHitlRestartResumeFromCheckpoint(t *testing.T) {
	store := newMemStore()
	hooks := newHitlHooks()
	ran := 0
	probe := askProbe("probe", &ran)
	sid := "hitl-restart"
	tx := transcript.NewStore(t.TempDir())
	sess, _ := hitlSession(t, store, hooks, []actool.CoreTool{probe}, sid, tx)
	ctx := context.Background()

	runOnce(t, sess.Prompt(ctx, "做点事"))
	hitl := sess.Interrupt()
	if hitl == nil {
		t.Fatal("首轮应中断")
	}

	// 模拟进程重启：新 Session 从 transcript + checkpoint store 重建，
	// ResumeForApproval 保留尾部 tool_use（待续跑的调用本体）。重建进程的模型
	// 脚本只有「收尾」一步——续跑先重放工具调用（无模型调用），然后模型收尾。
	m2 := &recModel{}
	m2.script(func() (*schema.Message, error) { return schema.AssistantMessage("完成", nil), nil })
	sess2 := hitlSessionWithModel(t, store, hooks, []actool.CoreTool{probe}, sid, tx, m2)
	if err := sess2.ResumeForApproval(sid); err != nil {
		t.Fatalf("ResumeForApproval: %v", err)
	}
	msgs := sess2.Messages()
	if len(msgs) == 0 || msgs[len(msgs)-1].Role != "assistant" || len(msgs[len(msgs)-1].ToolUses()) == 0 {
		t.Fatalf("重启装配的 DTO 尾部应是 assistant tool_use: %+v", msgs)
	}
	term := runOnce(t, sess2.ResumeApproval(ctx, hitl.CheckpointID, hitl.InterruptID, hooks.decide(hitl.PendingID, true)))
	if term == nil || term.Reason != harness.ReasonCompleted {
		t.Fatalf("重启后 allowed 续跑应完成，got %+v", term)
	}
	if ran != 1 {
		t.Fatalf("重启续跑应恰好执行该工具一次，ran=%d", ran)
	}
	if hooks.askCount() != 1 {
		t.Fatalf("重启续跑不得重审，asks=%d", hooks.askCount())
	}
}

func TestHitlSameTurnTwoAsksAggregateDispatch(t *testing.T) {
	store := newMemStore()
	hooks := newHitlHooks()
	ran1, ran2 := 0, 0
	probe1 := askProbe("probe1", &ran1)
	probe2 := askProbe("probe2", &ran2)
	sess, _ := hitlSession(t, store, hooks, []actool.CoreTool{probe1, probe2}, "hitl-agg", nil)
	ctx := context.Background()

	// 同轮两个工具同时 ask → 聚合中断，首个上下文浮出，run 以待审批收场。
	term := runOnce(t, sess.Prompt(ctx, "做点事"))
	if term == nil || term.Reason != termmap.AwaitingApproval {
		t.Fatalf("同轮双 ask 应以待审批终态收场，got %+v", term)
	}
	cur := sess.Interrupt()
	if cur == nil {
		t.Fatal("首个中断缺失")
	}

	// 逐个决定逐个续跑（官方 Targets 分发义务：未命中者 re-interrupt 再次浮出）。
	decided := map[int64]bool{cur.PendingID: true}
	for i := 0; i < 6; i++ {
		term = runOnce(t, sess.ResumeApproval(ctx, cur.CheckpointID, cur.InterruptID, hooks.decide(cur.PendingID, true)))
		if term == nil {
			t.Fatal("续跑无终态")
		}
		if term.Reason == harness.ReasonCompleted {
			break
		}
		if term.Reason != termmap.AwaitingApproval {
			t.Fatalf("意外终态: %+v", term)
		}
		next := sess.Interrupt()
		if next == nil || decided[next.PendingID] {
			t.Fatalf("re-interrupt 未浮出未决定的挂起: %+v", next)
		}
		decided[next.PendingID] = true
		cur = next
	}
	if ran1+ran2 != 2 || ran1 != 1 || ran2 != 1 {
		t.Fatalf("两个工具应各执行一次，ran1=%d ran2=%d", ran1, ran2)
	}
	if hooks.askCount() != 2 {
		t.Fatalf("每个工具应恰好 ask 一次，asks=%d", hooks.askCount())
	}
}

func TestHitlResumeWithoutCheckpointDegrades(t *testing.T) {
	store := newMemStore()
	hooks := newHitlHooks()
	ran := 0
	probe := askProbe("probe", &ran)
	sess, _ := hitlSession(t, store, hooks, []actool.CoreTool{probe}, "hitl-gone", nil)
	ctx := context.Background()

	runOnce(t, sess.Prompt(ctx, "做点事"))
	hitl := sess.Interrupt()
	if hitl == nil {
		t.Fatal("首轮应中断")
	}
	store.drop(hitl.CheckpointID) // 模拟载荷丢失/损坏（P2-6 回退口径）

	term := runOnce(t, sess.ResumeApproval(ctx, hitl.CheckpointID, hitl.InterruptID, hooks.decide(hitl.PendingID, true)))
	if term == nil {
		t.Fatal("续跑无终态")
	}
	if term.Reason == termmap.AwaitingApproval || term.Reason == harness.ReasonCompleted {
		t.Fatalf("checkpoint 缺失的续跑不得静默成功，got %+v", term)
	}
	if term.Err == nil {
		t.Fatalf("载荷丢失必须以错误冒出（宿主重跑），got %+v", term)
	}
	if ran != 0 {
		t.Fatalf("载荷丢失不得执行工具，ran=%d", ran)
	}
}
