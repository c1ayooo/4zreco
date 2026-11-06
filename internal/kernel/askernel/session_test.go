package askernel

// session_test.go — 内核单次 run 的行为单测（对照 norma harness 行为清单的内核侧）：
//   - 事件保真：thinking/text/tool_use/tool_result/usage/result 六类事件与顺序；
//   - 流式与非流式两条模型路径；
//   - ctx deadline → termmap.Timeout（timeout_settle 的内核半边，driver 结算半边在
//     internal/agent/kernelrun_test.go）；
//   - todo 提醒节流（norma maybeInjectTodoReminder 移植）；
//   - per-request 日期 <system-reminder> 前置（不入 master）；
//   - 旧会话（norma 时代落盘的 transcript JSONL）Resume 续跑（⑥ 回放）。
//
// 无 sleep 断言（AGENTS.md）：超时用 ctx deadline 机制本身驱动，不做时间断言。

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/c1ayooo/4zreco/internal/norma/transcript"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/acllm"
)

// scriptModel is a minimal scripted model.ToolCallingChatModel.
type scriptModel struct {
	mu           sync.Mutex
	steps        []func(call int) (*schema.Message, error)
	calls        int
	scriptStream func(call int) (*schema.StreamReader[*schema.Message], error)
}

func intPtr(i int) *int { return &i }

// acllmNewMessageStore aliases the acllm master constructor for readability.
func acllmNewMessageStore() *acllm.MessageStore { return acllm.NewMessageStore() }

// schemaChatAgentState is the middleware state shell the kernel middlewares take.
type schemaChatAgentState = adk.ChatModelAgentState

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
		run = m.steps[len(m.steps)-1]
	}
	m.mu.Unlock()
	if run != nil {
		return run(call)
	}
	return schema.AssistantMessage("done", nil), nil
}

func (m *scriptModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	m.mu.Lock()
	call := m.calls
	m.calls++
	fn := m.scriptStream
	m.mu.Unlock()
	if fn != nil {
		return fn(call)
	}
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *scriptModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func toolTurnModel() *scriptModel {
	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c1", Function: schema.FunctionCall{Name: "probe", Arguments: `{"q":"1"}`}},
		}), nil
	})
	sm.script(func(int) (*schema.Message, error) {
		msg := schema.AssistantMessage("完成", nil)
		msg.ResponseMeta = &schema.ResponseMeta{
			FinishReason: "end_turn",
			Usage:        &schema.TokenUsage{PromptTokens: 20, CompletionTokens: 5, TotalTokens: 25},
		}
		return msg, nil
	})
	return sm
}

func probeTool(t *testing.T) actool.CoreTool {
	t.Helper()
	return actool.Build(actool.Spec{
		Name:        "probe",
		Description: "probe",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("probe ran"), nil
		},
	})
}

// drainAll consumes one run's event stream into a slice.
func drainAll(t *testing.T, sess *Session, ctx context.Context, input string) ([]harness.Event, *harness.Terminal) {
	t.Helper()
	var evs []harness.Event
	var term *harness.Terminal
	for ev, err := range sess.Prompt(ctx, input) {
		if err != nil {
			t.Fatalf("prompt error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			term = ev.Terminal
		}
		evs = append(evs, ev)
	}
	return evs, term
}

// TestSessionEventFidelityStreaming: 流式路径的完整事件序列保真——thinking/text
// 增量、tool_use/tool_result 配对、usage、result，与 norma harness.Event 同形。
func TestSessionEventFidelityStreaming(t *testing.T) {
	sm := &scriptModel{}
	sm.scriptStream = func(call int) (*schema.StreamReader[*schema.Message], error) {
		if call == 0 {
			// 流式第一轮：thinking 增量 + text 增量 + 一个工具调用（参数分两段到）
			chunks := []*schema.Message{}
			th1 := schema.AssistantMessage("", nil)
			th1.ReasoningContent = "想一步"
			th2 := schema.AssistantMessage("", nil)
			th2.ReasoningContent = "做一步"
			chunks = append(chunks, th1, th2,
				schema.AssistantMessage("调用 ", nil),
				schema.AssistantMessage("探针", nil))
			tc1 := schema.AssistantMessage("", []schema.ToolCall{
				{ID: "s1", Function: schema.FunctionCall{Name: "probe"}, Index: intPtr(0)},
			})
			tc2 := schema.AssistantMessage("", []schema.ToolCall{
				{Function: schema.FunctionCall{Arguments: `{"q":"`}, Index: intPtr(0)},
			})
			tc3 := schema.AssistantMessage("", []schema.ToolCall{
				{Function: schema.FunctionCall{Arguments: `1"}`}, Index: intPtr(0)},
			})
			chunks = append(chunks, tc1, tc2, tc3)
			return schema.StreamReaderFromArray(chunks), nil
		}
		m := schema.AssistantMessage("完成", nil)
		m.ResponseMeta = &schema.ResponseMeta{
			FinishReason: "end_turn",
			Usage:        &schema.TokenUsage{PromptTokens: 20, CompletionTokens: 5, TotalTokens: 25},
		}
		return schema.StreamReaderFromArray([]*schema.Message{m}), nil
	}

	sess := NewSession(Options{Model: sm, Tools: []actool.CoreTool{probeTool(t)}, MaxTurns: 4})
	defer func() { _ = sess.Close() }()
	evs, term := drainAll(t, sess, context.Background(), "开始")

	// 事件序列：thinking×2, text×2, tool_use, tool_result, (usage), thinking?…
	// 保守断言：六类事件各出现至少一次，顺序关键对成立。
	kinds := map[harness.EventKind]int{}
	lastToolUse, lastResult := -1, -1
	for i, ev := range evs {
		kinds[ev.Kind]++
		switch ev.Kind {
		case harness.KindToolUse:
			lastToolUse = i
		case harness.KindToolResult:
			lastResult = i
		}
	}
	for _, k := range []harness.EventKind{harness.KindThinking, harness.KindText, harness.KindToolUse, harness.KindToolResult, harness.KindUsage, harness.KindResult} {
		if kinds[k] == 0 {
			t.Fatalf("event %s missing from the stream: %v", k, evs)
		}
	}
	if lastToolUse < 0 || lastResult < lastToolUse {
		t.Fatalf("tool_result must follow its tool_use; use@%d result@%d", lastToolUse, lastResult)
	}
	// 流式增量的参数片段被折叠回完整 tool_use 输入。
	var useBlock *llm.ContentBlock
	for _, ev := range evs {
		if ev.Kind == harness.KindToolUse {
			useBlock = ev.ToolUse
		}
	}
	if useBlock == nil || useBlock.Name != "probe" || string(useBlock.Input) != `{"q":"1"}` {
		t.Fatalf("tool_use input drifted: %+v", useBlock)
	}
	if term == nil || term.Reason != harness.ReasonCompleted || term.Text != "完成" {
		t.Fatalf("terminal = %+v", term)
	}
	if term.Usage.OutputTokens != 5 {
		t.Fatalf("terminal usage = %+v, want output 5", term.Usage)
	}
	if term.Turns != 1 {
		t.Fatalf("turns = %d, want 1（一次工具回合）", term.Turns)
	}
	// DTO master：assistant 捕获 + 工具结果落库（门 OnResult 半边）。
	msgs := sess.Messages()
	if len(msgs) < 4 {
		t.Fatalf("master too short: %d", len(msgs))
	}
}

// TestSessionEventFidelityNonStreaming: 非流式路径同保真（norma NonStreaming 行为）。
func TestSessionEventFidelityNonStreaming(t *testing.T) {
	sm := toolTurnModel()
	sess := NewSession(Options{Model: sm, Tools: []actool.CoreTool{probeTool(t)}, MaxTurns: 4, NonStreaming: true})
	defer func() { _ = sess.Close() }()
	evs, term := drainAll(t, sess, context.Background(), "开始")

	for _, k := range []harness.EventKind{harness.KindToolUse, harness.KindToolResult, harness.KindUsage, harness.KindResult} {
		found := false
		for _, ev := range evs {
			if ev.Kind == k {
				found = true
			}
		}
		if !found {
			t.Fatalf("non-streaming run missing event %s", k)
		}
	}
	if term == nil || term.Reason != harness.ReasonCompleted {
		t.Fatalf("terminal = %+v", term)
	}
}

// TestSessionToolResultInMaster: 工具结果以 norma 形状（user 消息 + tool_result 块）
// 落进 DTO master——下一次模型调用投影能看到它（第二轮输入核对）。
func TestSessionToolResultInMaster(t *testing.T) {
	sm := toolTurnModel()
	sess := NewSession(Options{Model: sm, Tools: []actool.CoreTool{probeTool(t)}, MaxTurns: 4, NonStreaming: true})
	defer func() { _ = sess.Close() }()
	_, term := drainAll(t, sess, context.Background(), "开始")
	if term == nil {
		t.Fatal("no terminal")
	}
	var found bool
	for _, m := range sess.Messages() {
		if m.Role != llm.RoleUser {
			continue
		}
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && b.ToolUseID == "c1" && strings.Contains(b.Content[0].Text, "probe ran") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("tool result not persisted into the master: %+v", sess.Messages())
	}
}

// TestSessionTimeoutMapsToTimeoutTerm: ctx deadline → termmap.Timeout（内核半边；
// 超时后的结算由 driver 的 settlement 分支承担，见 internal/agent）。
func TestSessionTimeoutMapsToTimeoutTerm(t *testing.T) {
	sm := &ctxBlockModel{}
	sess := NewSession(Options{Model: sm, MaxDuration: time.Second, NonStreaming: true})
	defer func() { _ = sess.Close() }()

	// 模型调用一直挂到 ctx 到点（Runner ctx 带 MaxDuration deadline——4zrec 取舍：
	// 模型与工具同受墙钟），超时由 ctx 机制本身驱动，无 sleep 断言。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var term *harness.Terminal
	for ev, err := range sess.Prompt(ctx, "开始") {
		if err != nil {
			t.Fatalf("prompt error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			term = ev.Terminal
		}
	}
	if term == nil || term.Reason != harness.ReasonTimeout {
		t.Fatalf("terminal = %+v, want timeout", term)
	}
}

// ctxBlockModel blocks Generate on ctx.Done — the deadline-abort shape.
type ctxBlockModel struct{}

func (m *ctxBlockModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *ctxBlockModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *ctxBlockModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

// TestTodoReminderThrottle: todo 提醒节流——写完 TodoWrite 后 10 个 assistant 回合
// 内不提醒、到阈值注入一次、注入后重新节流（norma maybeInjectTodoReminder 移植）。
func TestTodoReminderThrottle(t *testing.T) {
	store := actool.NewTodoStore()
	setTodos(t, store, `{"todos":[{"content":"扫一遍资产","status":"pending"}]}`)
	dto := acllmNewMessageStore()
	// 10 个不含 TodoWrite 的 assistant 回合 → 到 sinceWrite 阈值。
	for i := 0; i < 10; i++ {
		dto.Append(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("turn")}})
	}
	mw := &todoReminderMiddleware{store: store, dto: dto}

	state := &schemaChatAgentState{}
	_, st, err := mw.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState: %v", err)
	}
	// 提醒注入 master + 投影。
	if n := countTodoReminders(dto.Get()); n != 1 {
		t.Fatalf("master reminders = %d, want 1", n)
	}
	if len(st.Messages) == 0 || !strings.Contains(st.Messages[len(st.Messages)-1].Content, "<system-reminder>") {
		t.Fatalf("reminder not appended to the projected view: %+v", st.Messages)
	}
	// 立即再来一次：节流生效（sinceReminder=0 < 10）。
	_, _, _ = mw.BeforeModelRewriteState(context.Background(), state, nil)
	if n := countTodoReminders(dto.Get()); n != 1 {
		t.Fatalf("throttled reminder leaked: %d", n)
	}
	// 空 todo 列表不提醒。
	setTodos(t, store, `{"todos":[]}`)
	dto2 := acllmNewMessageStore()
	for i := 0; i < 12; i++ {
		dto2.Append(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("turn")}})
	}
	mw2 := &todoReminderMiddleware{store: store, dto: dto2}
	_, _, _ = mw2.BeforeModelRewriteState(context.Background(), state, nil)
	if n := countTodoReminders(dto2.Get()); n != 0 {
		t.Fatalf("empty todo list must not remind: %d", n)
	}
}

// setTodos drives the store through its own TodoWrite tool (Set is unexported).
func setTodos(t *testing.T, store *actool.TodoStore, input string) {
	t.Helper()
	tl := store.Tool()
	tc := &actool.ToolContext{}
	res, err := tl.(interface {
		Call(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)
	}).Call(context.Background(), json.RawMessage(input), tc)
	if err != nil {
		t.Fatalf("TodoWrite: %v", err)
	}
	if res.IsError {
		t.Fatalf("TodoWrite errored: %v", res.Flatten())
	}
}

func countTodoReminders(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		if llm.IsTodoReminder(m) {
			n++
		}
	}
	return n
}

// TestDateReminderPrependedPerRequest: 日期 <system-reminder> 前置在投影消息最前
// （system 之后），且不写入 master（per-request 形状，norma query.go:784 parity）。
func TestDateReminderPrependedPerRequest(t *testing.T) {
	dto := acllmNewMessageStore()
	dto.Append(llm.UserText("用户输入"))
	mw := &dateReminderMiddleware{extra: func() string { return "# extraSection\n内容" }}
	state := &schemaChatAgentState{Messages: []*schema.Message{schema.SystemMessage("sys"), schema.UserMessage("用户输入")}}
	_, st, err := mw.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState: %v", err)
	}
	if len(st.Messages) != 3 {
		t.Fatalf("messages = %d, want 3", len(st.Messages))
	}
	rm := st.Messages[0]
	if rm.Role != schema.User || !strings.Contains(rm.Content, "<system-reminder>") ||
		!strings.Contains(rm.Content, "Today's date is") || !strings.Contains(rm.Content, "# extraSection") {
		t.Fatalf("reminder shape drifted: %+v", rm)
	}
	if st.Messages[1].Role != schema.System {
		t.Fatalf("system message must stay ahead of the reminder: %+v", st.Messages[1])
	}
	if n := len(dto.Get()); n != 1 {
		t.Fatalf("master grew by the reminder: %d", n)
	}
}

// TestOldTranscriptResumeAndContinue（⑥ 回放）: norma 时代落盘的 transcript
// JSONL → kernel Session.Resume → 续跑一轮，master 接旧历史、后续写入接同一文件。
func TestOldTranscriptResumeAndContinue(t *testing.T) {
	dir := t.TempDir()
	store := transcript.NewStore(dir)
	sid := "exp7-worker-i2"
	// 用 norma Writer 落一段旧会话（冻结形状的生产方）。
	w := store.NewWriter(sid, "")
	w.RecordMessage(llm.UserText("上一轮的任务指令"), llm.Usage{})
	w.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		llm.TextBlock("上一轮的结论"),
	}}, llm.Usage{InputTokens: 40, OutputTokens: 9})
	if err := w.Err(); err != nil {
		t.Fatalf("norma writer: %v", err)
	}

	sm := &scriptModel{}
	sm.script(func(int) (*schema.Message, error) { return schema.AssistantMessage("续跑的新结论", nil), nil })

	sess := NewSession(Options{Model: sm, Transcript: store, SessionID: sid, NonStreaming: true, MaxTurns: 2})
	defer func() { _ = sess.Close() }()
	if err := sess.Resume(sid); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if len(sess.Messages()) != 2 {
		t.Fatalf("resumed master = %d messages, want 2", len(sess.Messages()))
	}
	if u := sess.Usage(); u.InputTokens != 40 || u.OutputTokens != 9 {
		t.Fatalf("resumed usage = %+v", u)
	}
	// 续跑一轮：模型投影应包含旧历史（第一轮输入 = system + 旧 user + 旧 assistant + 新 user）。
	_, term := drainAll(t, sess, context.Background(), "接着干")
	if term == nil || term.Reason != harness.ReasonCompleted || term.Text != "续跑的新结论" {
		t.Fatalf("terminal = %+v", term)
	}
	msgs := sess.Messages()
	if len(msgs) != 4 {
		t.Fatalf("master after continue = %d, want 4（旧 2 + 旧 user? + 新 user + 新 assistant）", len(msgs))
	}
	if msgs[0].Role != llm.RoleUser || !strings.Contains(msgs[0].Text(), "上一轮") {
		t.Fatalf("old history lost: %+v", msgs[0])
	}
	// 续跑写入接同一文件：重新 Load 应看到 4 条。
	recs, err := store.Load(store.MainPath(sid))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(recs) < 4 {
		t.Fatalf("transcript after continue has %d records, want ≥4", len(recs))
	}
}

// ---- 取消终态 phase 判定（评审第 2 轮 #1：norma 双检查点移植的用例钉）----

// blockModel 按脚本走前 N 步，之后阻塞等 ctx（取消/到点），把阻塞入口广播在
// entered 上供测试确定性驱动。ctx 已死时直接透传 ctx.Err()（镜像真实 provider
// 的取消行为——adk CancelCheck 之外模型调用本身也会失败）。
type blockModel struct {
	mu      sync.Mutex
	steps   []func(call int) (*schema.Message, error)
	calls   int
	entered chan struct{}
	once    sync.Once
}

func newBlockModel() *blockModel {
	return &blockModel{steps: nil, entered: make(chan struct{}, 4)}
}

func (m *blockModel) signalEntered() { m.once.Do(func() { close(m.entered) }) }

func (m *blockModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	call := m.calls
	m.calls++
	var run func(call int) (*schema.Message, error)
	if call < len(m.steps) {
		run = m.steps[call]
	}
	m.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if run != nil {
		return run(call)
	}
	// 阻塞步：广播入口后等 ctx。
	m.signalEntered()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *blockModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{m2ptr(msg)}), nil
}

func (m *blockModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) { return m, nil }

func m2ptr(m *schema.Message) *schema.Message { return m }

// cancelingTool cancels the run's parent mid-execution, then blocks on ctx —
// deterministically reproducing "cancellation interrupted an in-flight tool"
// （无 goroutine、无 sleep：取消点就在工具执行体内）。
func cancelingTool(t *testing.T, cancel context.CancelFunc) actool.CoreTool {
	t.Helper()
	return actool.Build(actool.Spec{
		Name:        "slowprobe",
		Description: "slow probe",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			cancel() // 工具执行中途取消（run 的父 ctx）
			<-ctx.Done()
			return actool.Errorf("context canceled"), nil
		},
	})
}

// TestSessionCancelDuringToolsMapsToAbortedTools: 取消打断在跑的工具（OnResult
// 观测时 ctx 已死）→ aborted_tools（norma query.go:526-528 检查点移植）。
func TestSessionCancelDuringToolsMapsToAbortedTools(t *testing.T) {
	sm := newBlockModel()
	sm.steps = append(sm.steps, func(int) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c1", Function: schema.FunctionCall{Name: "slowprobe", Arguments: `{}`}},
		}), nil
	})
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(Options{Model: sm, Tools: []actool.CoreTool{cancelingTool(t, cancel)}, MaxTurns: 4, NonStreaming: true})
	defer func() { _ = sess.Close() }()

	var term *harness.Terminal
	for ev, err := range sess.Prompt(parent, "开始") {
		if err != nil {
			t.Fatalf("prompt error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			term = ev.Terminal
		}
	}
	if term == nil || term.Reason != harness.ReasonAbortedTools {
		t.Fatalf("terminal = %+v, want aborted_tools", term)
	}
}

// TestSessionCancelDuringModelStreamAfterTools: 工具回合干净完成（OnResult 观测
// 时 ctx 还活着）、其后的模型流式阶段才被取消 → aborted_streaming（第一轮
// turns>0 近似会把这条误记成 aborted_tools）。
func TestSessionCancelDuringModelStreamAfterTools(t *testing.T) {
	sm := newBlockModel()
	sm.steps = append(sm.steps, func(int) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c1", Function: schema.FunctionCall{Name: "probe", Arguments: `{}`}},
		}), nil
	})
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(Options{Model: sm, Tools: []actool.CoreTool{probeTool(t)}, MaxTurns: 4, NonStreaming: true})
	defer func() { _ = sess.Close() }()

	done := make(chan *harness.Terminal, 1)
	go func() {
		var term *harness.Terminal
		for ev, err := range sess.Prompt(parent, "开始") {
			if err != nil {
				continue
			}
			if ev.Kind == harness.KindResult {
				term = ev.Terminal
			}
		}
		done <- term
	}()
	<-sm.entered // 模型第二调用已在等 ctx（工具边界早已干净通过，flag 未置）
	cancel()
	if term := <-done; term == nil || term.Reason != harness.ReasonAbortedStreaming {
		t.Fatalf("terminal = %+v, want aborted_streaming", term)
	}
}

// TestSessionCancelDuringFirstStream: 首个模型流式阶段被取消 → aborted_streaming
// （无工具回合，flag 天然未置）。
func TestSessionCancelDuringFirstStream(t *testing.T) {
	sm := newBlockModel() // 无脚本步：首个调用即阻塞等 ctx
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := NewSession(Options{Model: sm, NonStreaming: true, MaxTurns: 4})
	defer func() { _ = sess.Close() }()

	done := make(chan *harness.Terminal, 1)
	go func() {
		var term *harness.Terminal
		for ev, err := range sess.Prompt(parent, "开始") {
			if err != nil {
				continue
			}
			if ev.Kind == harness.KindResult {
				term = ev.Terminal
			}
		}
		done <- term
	}()
	<-sm.entered
	cancel()
	if term := <-done; term == nil || term.Reason != harness.ReasonAbortedStreaming {
		t.Fatalf("terminal = %+v, want aborted_streaming", term)
	}
}
