package agent

// kernelrun_test.go — 路线 A（刀④）driver 的行为单测：
//
//   - TestIsThinkingOnlyTurn：空转回合判据（自 engine_emptyturn_test.go 随代码上移）；
//   - TestRunKernelEmptyTurnNudge：spec 要求的三路径（续跑一次 / 到上限 / 正常结束），
//     scripted eino model 驱动真 kernel（adk ChatModelAgent + Runner）；
//   - TestRunKernelSettlementKeepsBudgetReason：max_turns 终态 → settlement 分支
//     注入收尾词、终态保留原预算 reason、文本取自收尾 run。
//
// 无 sleep 断言（AGENTS.md）：全部同步 scripted 调用。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
)

func assistantThinking(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: text, Signature: "sig"},
	}}
}

func TestIsThinkingOnlyTurn(t *testing.T) {
	toolUse := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "先扫端口"},
		{Type: llm.BlockToolUse, ID: "t1", Name: "run_nuclei"},
	}}
	cases := []struct {
		name string
		msgs []llm.Message
		want bool
	}{
		{"仅思考", []llm.Message{llm.UserText("开始"), assistantThinking("想想")}, true},
		{"思考+工具", []llm.Message{llm.UserText("开始"), toolUse}, false},
		{"思考+正文", []llm.Message{assistantThinking("想想"), {
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("结论")},
		}}, false},
		{"正文只有空白字符", []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("  \n ")},
		}}, true},
		{"完全空的 assistant 回合", []llm.Message{{Role: llm.RoleAssistant}}, true},
		// 工具结果是 user 角色，判定必须回溯到它前面那条 assistant，而不是就近误判。
		{"最后一条是工具结果", []llm.Message{toolUse, {
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "t1"}},
		}}, false},
		{"没有 assistant 消息", []llm.Message{llm.UserText("开始")}, false},
		{"空历史", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isThinkingOnlyTurn(c.msgs); got != c.want {
				t.Fatalf("isThinkingOnlyTurn = %v, want %v", got, c.want)
			}
		})
	}
}

// testEmptyTurnNudges 与 engine.defaultEmptyTurnNudges(=2) 同源：预算「每条意图
// 总量」的内置默认。agent 包不 import server，这里镜像常量值。
const testEmptyTurnNudges = 2

// memNudger is the in-memory Nudger the DB-backed IntentNudger mirrors.
type memNudger struct {
	n     int
	limit int
}

func (m *memNudger) Increment(ctx context.Context) (int, error) { m.n++; return m.n, nil }
func (m *memNudger) Limit() int                                 { return m.limit }
func (m *memNudger) Label() string                              { return "test" }

// scriptModel is a minimal scripted model.ToolCallingChatModel (non-streaming
// path only — the kernel runs EnableStreaming=false under NonStreaming).
type scriptModel struct {
	mu    sync.Mutex
	steps []func(call int) (*schema.Message, error)
	calls int
}

func (m *scriptModel) script(step func(call int) (*schema.Message, error)) {
	m.mu.Lock()
	m.steps = append(m.steps, step)
	m.mu.Unlock()
}

func (m *scriptModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	call := m.calls
	m.calls++
	var run func(call int) (*schema.Message, error)
	if call < len(m.steps) {
		run = m.steps[call]
	} else if len(m.steps) > 0 {
		run = m.steps[len(m.steps)-1] // 步数耗尽 → 保持最后一步（空转脚本一直空转）
	}
	m.mu.Unlock()
	if run != nil {
		return run(call)
	}
	return schema.AssistantMessage("done", nil), nil
}

func (m *scriptModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *scriptModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

// thinkingTurn renders a thinking-only assistant turn (route-A nudge condition).
func thinkingTurn() *schema.Message {
	m := schema.AssistantMessage("", nil)
	m.ReasoningContent = "再想想下一步"
	return m
}

// runNudgeCase drives one kernel conversation with the given script and returns
// (finalText, reason, nudger, session) for assertions.
func runNudgeCase(t *testing.T, sm *scriptModel, nudger *memNudger) (string, harness.TerminalReason, *askernel.Session) {
	t.Helper()
	sess := askernel.NewSession(askernel.Options{
		Model:        sm,
		SystemPrompt: []string{"route-a test"},
		MaxTurns:     6,
		NonStreaming: true,
	})
	defer func() { _ = sess.Close() }()
	d := kernelDriver{nudge: nudger}
	text, reason, err := captureRunSession(context.Background(), sess, "开始", nil, d)
	if err != nil {
		t.Fatalf("captureRunSession: %v", err)
	}
	return text, reason, sess
}

// 三路径之一：续跑一次——第一轮 thinking-only，nudge 注入后模型给出正文收场。
func TestRunKernelEmptyTurnNudgedOnce(t *testing.T) {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return thinkingTurn(), nil }) // 空转回合
	sm.script(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("扫描完成，无开放端口", nil), nil
	})

	nudger := &memNudger{limit: testEmptyTurnNudges}
	text, reason, sess := runNudgeCase(t, sm, nudger)

	if reason != harness.ReasonCompleted {
		t.Fatalf("reason = %q, want completed", string(reason))
	}
	if !strings.Contains(text, "扫描完成") {
		t.Fatalf("final text = %q", text)
	}
	if nudger.n != 1 {
		t.Fatalf("nudge count = %d, want 1（续跑一次）", nudger.n)
	}
	// 注入的续跑指令确实进了会话（同一条 DTO master / transcript 链重开 Run）。
	found := false
	for _, m := range sess.Messages() {
		if m.Role == llm.RoleUser && strings.Contains(m.Text(), "空转提醒") {
			found = true
		}
	}
	if !found {
		t.Fatalf("empty-turn nudge not appended to the conversation master")
	}
	if sm.calls != 2 {
		t.Fatalf("model calls = %d, want 2（空转轮 + 续跑轮）", sm.calls)
	}
}

// 三路径之二：到上限——空转与工具回合交替（norma 语义：连续空转只推一次，预算挡
// 「工具→空转→推→工具→空转」的病态循环），推满 2 次后第三次空转放行收场。
func TestRunKernelEmptyTurnBudgetExhausted(t *testing.T) {
	sm := &scriptModel{}
	toolTurn := func(int) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c", Function: schema.FunctionCall{Name: "probe", Arguments: `{}`}},
		}), nil
	}
	emptyTurn := func(int) (*schema.Message, error) { return thinkingTurn(), nil }
	sm.script(toolTurn)  // 工具回合（钩子重新武装）
	sm.script(emptyTurn) // 空转 → nudge 1
	sm.script(toolTurn)  // 工具回合
	sm.script(emptyTurn) // 空转 → nudge 2
	sm.script(toolTurn)  // 工具回合
	sm.script(emptyTurn) // 空转 → 预算耗尽，放行收场

	sess := askernel.NewSession(askernel.Options{
		Model:        sm,
		Tools:        []coreToolAlias{mustProbeTool(t)},
		MaxTurns:     20,
		NonStreaming: true,
	})
	defer func() { _ = sess.Close() }()

	nudger := &memNudger{limit: 2}
	text, reason, _ := captureRunSession(context.Background(), sess, "开始", nil, kernelDriver{nudge: nudger})

	if reason != harness.ReasonCompleted {
		t.Fatalf("reason = %q, want completed（放行收场）", string(reason))
	}
	if strings.TrimSpace(text) != "" {
		t.Fatalf("空转收场应无文字总结, got %q", text)
	}
	// 计数语义 = 注入尝试数（norma steerHooks.Add(1) 先计数后比较）：2 次注入 +
	// 1 次被预算拒绝的尝试 = 3。
	if nudger.n != 3 {
		t.Fatalf("nudge count = %d, want 3（2 次注入 + 1 次拒绝尝试）", nudger.n)
	}
	if sm.calls != 6 {
		t.Fatalf("model calls = %d, want 6", sm.calls)
	}
}

// 三路径之三：正常结束——首轮就有正文，nudge 完全不介入、计数不动。
func TestRunKernelNormalFinishNoNudge(t *testing.T) {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return schema.AssistantMessage("一次到位", nil), nil })

	nudger := &memNudger{limit: 2}
	text, reason, _ := runNudgeCase(t, sm, nudger)

	if reason != harness.ReasonCompleted || text != "一次到位" {
		t.Fatalf("reason=%q text=%q", string(reason), text)
	}
	if nudger.n != 0 {
		t.Fatalf("正常收场不应计数, got %d", nudger.n)
	}
	if sm.calls != 1 {
		t.Fatalf("model calls = %d, want 1", sm.calls)
	}
}

// 预算关闭（limit<=0，用户把「空响应重试次数」配 -1）时不介入。
func TestRunKernelNudgeDisabled(t *testing.T) {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return thinkingTurn(), nil })

	nudger := &memNudger{limit: 0}
	_, reason, _ := runNudgeCase(t, sm, nudger)
	if reason != harness.ReasonCompleted {
		t.Fatalf("reason = %q", string(reason))
	}
	if nudger.n != 0 || sm.calls != 1 {
		t.Fatalf("关闭时应不计数不续跑: nudges=%d calls=%d", nudger.n, sm.calls)
	}
}

// Stop 链 prevent → stop_hook_prevented 收场（内核不再产出该终态——上移 engine 的
// 宿主出口）。
func TestRunKernelStopChainPrevent(t *testing.T) {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return schema.AssistantMessage("先收一下", nil), nil })

	sess := askernel.NewSession(askernel.Options{Model: sm, NonStreaming: true, MaxTurns: 4})
	defer func() { _ = sess.Close() }()
	d := kernelDriver{stop: fakeStopHooks{prevent: true, msg: "写回后收手"}}
	text, reason, err := captureRunSession(context.Background(), sess, "开始", nil, d)
	if err != nil {
		t.Fatalf("captureRunSession: %v", err)
	}
	if reason != harness.ReasonStopHookPrevented {
		t.Fatalf("reason = %q, want stop_hook_prevented", string(reason))
	}
	if text != "写回后收手" {
		t.Fatalf("text = %q, want the hook message", text)
	}
}

// Stop 链 blocking → 注入消息再跑一轮；stopHookActive 挡住连环注入（第二轮自然
// 结束不再调 Stop 链）。
func TestRunKernelStopChainBlockingInjectsOnce(t *testing.T) {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return schema.AssistantMessage("还没完", nil), nil })
	sm.script(func(int) (*schema.Message, error) { return schema.AssistantMessage("好，写回收手", nil), nil })

	sess := askernel.NewSession(askernel.Options{Model: sm, NonStreaming: true, MaxTurns: 4})
	defer func() { _ = sess.Close() }()
	stop := &countingStopHooks{msg: "把已确认的结果写回"}
	d := kernelDriver{stop: stop}
	text, reason, err := captureRunSession(context.Background(), sess, "开始", nil, d)
	if err != nil {
		t.Fatalf("captureRunSession: %v", err)
	}
	if reason != harness.ReasonCompleted || text != "好，写回收手" {
		t.Fatalf("reason=%q text=%q", string(reason), text)
	}
	if stop.calls != 1 {
		t.Fatalf("Stop 链被调 %d 次, want 1（stopHookActive 挡住第二轮）", stop.calls)
	}
	if sm.calls != 2 {
		t.Fatalf("model calls = %d, want 2", sm.calls)
	}
}

type fakeStopHooks struct {
	prevent  bool
	blocking []string
	msg      string
}

func (f fakeStopHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (f fakeStopHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (f fakeStopHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return f.prevent, f.blocking, f.msg
}

type countingStopHooks struct {
	fakeStopHooks
	calls int
	msg   string
}

func (c *countingStopHooks) Stop(ctx context.Context, msgs []llm.Message) (bool, []string, string) {
	c.calls++
	return false, []string{c.msg}, ""
}

// max_turns → settlement 分支：注入收尾词、隐藏 Bash 由 RunSettlement 的工具过滤
// 保证、终态保留原预算 reason、文本取自收尾 run。
func TestRunKernelSettlementKeepsBudgetReason(t *testing.T) {
	sm := &scriptModel{}
	// 第一轮就发工具调用 → MaxTurns=1 的预算在回合边界耗尽 → ErrExceedMaxIterations。
	sm.script(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c1", Function: schema.FunctionCall{Name: "probe", Arguments: `{}`}},
		}), nil
	})
	// 收尾 run：输出总结文本。
	sm.script(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("预算到点，已写回事实", nil), nil
	})
	probe := mustProbeTool(t)

	sess := askernel.NewSession(askernel.Options{
		Model:        sm,
		Tools:        []coreToolAlias{probe},
		MaxTurns:     1,
		NonStreaming: true,
	})
	defer func() { _ = sess.Close() }()

	settle := &askernel.Settlement{Prompt: "把已识别的写回再总结", DisabledTools: []string{"Bash"}, MaxTurns: 2}
	d := kernelDriver{settle: settle}
	text, reason, err := captureRunSession(context.Background(), sess, "开始", nil, d)
	if err != nil {
		t.Fatalf("captureRunSession: %v", err)
	}
	if reason != harness.ReasonMaxTurns {
		t.Fatalf("reason = %q, want max_turns（结算保留原预算终态）", string(reason))
	}
	if !strings.Contains(text, "预算到点") {
		t.Fatalf("text = %q, want the settlement run's text", text)
	}
	// 收尾词确实注入了 master。
	found := false
	for _, m := range sess.Messages() {
		if m.Role == llm.RoleUser && strings.Contains(m.Text(), "把已识别的写回") {
			found = true
		}
	}
	if !found {
		t.Fatalf("settlement prompt not appended to the master")
	}
	if sm.calls != 2 {
		t.Fatalf("model calls = %d, want 2（预算轮 + 收尾轮）", sm.calls)
	}
}

// 核对 err 透传：模型错误 → runKernel 返回该错误（engine 的 model_error 重试据此触发）。
func TestRunKernelModelErrorPassthrough(t *testing.T) {
	sm := &scriptModel{}
	boom := errors.New("provider 500: upstream exploded")
	sm.script(func(int) (*schema.Message, error) { return nil, boom })

	sess := askernel.NewSession(askernel.Options{Model: sm, NonStreaming: true, MaxTurns: 2})
	defer func() { _ = sess.Close() }()

	p := newCapturePump(context.Background(), "开始", nil, nil)
	defer p.finish()
	_, reason, rerr := runKernel(context.Background(), sess, "开始", kernelDriver{}, p)
	if reason != harness.ReasonModelError {
		t.Fatalf("reason = %q, want model_error", string(reason))
	}
	if rerr == nil || !strings.Contains(rerr.Error(), "upstream exploded") {
		t.Fatalf("err = %v, want the provider error", rerr)
	}
}

// timeout_settle：墙钟到点打断在跑的模型调用 → termmap.Timeout → driver 的
// settlement 分支注入收尾词重开一次 → 终态保留 timeout（norma「在活 ctx 上就地
// 进收尾」的路线 A 形态）。模型调用挂到 ctx 到点，无 sleep 断言。
func TestRunKernelTimeoutSettles(t *testing.T) {
	sm := &scriptModel{}
	// 主 run：模型挂死等 ctx（Runner ctx 带 MaxDuration deadline）。
	sm.script(func(int) (*schema.Message, error) {
		time.Sleep(50 * time.Millisecond) // bounded: MaxDuration=40ms 打断它
		return schema.AssistantMessage("不该到这里", nil), nil
	})
	// 收尾 run：输出总结。
	sm.script(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("超时收尾：已写回事实", nil), nil
	})

	sess := askernel.NewSession(askernel.Options{Model: sm, MaxDuration: 40 * time.Millisecond, NonStreaming: true, MaxTurns: 4})
	defer func() { _ = sess.Close() }()

	settle := &askernel.Settlement{Prompt: "到点了，写回再总结", MaxTurns: 2}
	d := kernelDriver{settle: settle}
	text, reason, err := captureRunSession(context.Background(), sess, "开始", nil, d)
	if err != nil {
		t.Fatalf("captureRunSession: %v", err)
	}
	if reason != harness.ReasonTimeout {
		t.Fatalf("reason = %q, want timeout", string(reason))
	}
	if !strings.Contains(text, "超时收尾") {
		t.Fatalf("text = %q, want the settlement run's text", text)
	}
	found := false
	for _, m := range sess.Messages() {
		if m.Role == llm.RoleUser && strings.Contains(m.Text(), "到点了") {
			found = true
		}
	}
	if !found {
		t.Fatalf("settlement prompt not appended")
	}
}

// capturePump.drain 的两条防御路径（评审第 1 轮 #2）：当前内核契约（runStream 对
// 错误也映射后 yield KindResult，drainEvents 全部 yield nil error）下不可达，但
// iter.Seq2 的类型契约允许错误与无终态收场（P2 ResumeWithParams/checkpoint 错误
// 可能经同一 seam 冒错）——这两条测试直接喂迭代器把分支钉进已验证行为，防止被当
// 死代码误删或误依赖。
func TestCapturePumpDrainErrorBranch(t *testing.T) {
	boom := errors.New("iterator seam error")
	events := func(yield func(harness.Event, error) bool) {
		yield(harness.Event{Kind: harness.KindText, Text: "部分输出"}, nil)
		yield(harness.Event{}, boom)
	}
	p := newCapturePump(context.Background(), "开始", nil, nil)
	defer p.finish()
	term, drained, err := p.drain(events)
	if term != nil {
		t.Fatalf("error run must not carry a terminal: %+v", term)
	}
	if !drained {
		t.Fatal("drained=false on an error run — the branch must report drained=true")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the seam error", err)
	}
	// 错误路径已发 result 活动（执行出错渲染），供 engine 的 err!=nil→blocked 消费。
	found := false
	for _, e := range p.recordedActivities() {
		if e.Kind == "result" && e.IsError && strings.Contains(e.Summary, "执行出错") {
			found = true
		}
	}
	if !found {
		t.Fatalf("error branch did not emit the result activity")
	}
}

func TestCapturePumpDrainStreamEndsWithoutResult(t *testing.T) {
	events := func(yield func(harness.Event, error) bool) {
		yield(harness.Event{Kind: harness.KindText, Text: "半截"}, nil)
	}
	p := newCapturePump(context.Background(), "开始", nil, nil)
	defer p.finish()
	var activities []db.Activity
	p.rec = func(a db.Activity) { activities = append(activities, a) }
	term, drained, err := p.drain(events)
	if term != nil || err != nil {
		t.Fatalf("term=%v err=%v, want clean no-terminal close", term, err)
	}
	if drained {
		t.Fatal("stream closed without KindResult must report drained=false（norma consumerStopped 形态）")
	}
	// 无终态收场不发 result 活动（runKernel 对 !drained 同样不发）。
	for _, a := range activities {
		if a.Kind == "result" {
			t.Fatalf("no-terminal close must not emit a result activity: %+v", a)
		}
	}
}
