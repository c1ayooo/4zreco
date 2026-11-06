package askernel

// run.go — one bounded runner run: the ChatModelAgent + Runner assembly
// (刀④ runner 装配约定，交接自刀③) and the event pump that surfaces the run as
// a harness.Event stream.
//
// Handlers = [view, dateReminder, injection, todo, deferred, gate]:
// BeforeModel hooks run in registration order — view projects the master,
// dateReminder prepends the per-request <system-reminder>, injection drains the
// host's sources, todo injects the throttled reminder, deferred filters tool
// schemas; WrapModel's first registration is outermost (the reactive retry must
// wrap the MaxTokens cap) — the view middleware is registered FIRST so its
// WrapModel lands outermost (4zrec askernel/session.go:553-570 同款).
//
// compose.ToolsNodeConfig.Tools = ToEinoTools(gate.Managed()) — 保序
// （= toolset_snapshot_hash 稳定）；UnknownToolsHandler 兜底幻觉工具名。
//
// The middlewares are constructed per run and never reused across runs
// (view.reactiveTried state). The DTO master and the gate's OnResult host
// wiring are the seams that outlive a run.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/acllm"
)

// runState is per-run bookkeeping shared by the pump: tool-exec records (the
// pump labels tool_result error-ness from what the gate observed), the
// completed-tool-turn counter and the run's cumulative usage.
type runState struct {
	mu      sync.Mutex
	records map[string]*toolExecRecord // callID → record
	turns   int                        // completed tool turns (norma turnCount)
	usage   llm.Usage                  // cumulative usage this run
	// cancelAfterTools 是「工具回合结束时 ctx 已经死了」的观测（norma
	// query.go:526-528 的检查点移植：结果记录后查 l.ctx.Err()）——gate 的
	// OnResult 与工具完成同步、先于下一个模型调用，无泵滞后，故该检查
	// 确定性地区分取消发生在工具阶段还是其后的模型流式阶段。
	cancelAfterTools bool
}

func (rs *runState) markCancelAfterTools() {
	rs.mu.Lock()
	rs.cancelAfterTools = true
	rs.mu.Unlock()
}

func (rs *runState) toolsPhaseCancel() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.cancelAfterTools
}

type toolExecRecord struct {
	isErr bool
}

func newRunState() *runState {
	return &runState{records: map[string]*toolExecRecord{}}
}

func (rs *runState) record(callID string, isErr bool) {
	rs.mu.Lock()
	rs.records[callID] = &toolExecRecord{isErr: isErr}
	rs.mu.Unlock()
}

func (rs *runState) lookup(callID string) *toolExecRecord {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.records[callID]
}

func (rs *runState) addUsage(u llm.Usage) {
	rs.mu.Lock()
	rs.usage.Add(u)
	rs.mu.Unlock()
}

// mergeEchoUsage folds a usage report that may re-echo fields already counted
// (Anthropic repeats the input side across stream chunks) — norma
// llm.Accumulator.MergeEcho semantics, applied per arriving chunk so a
// mid-stream death still leaves the partial usage in the session total.
func (rs *runState) mergeEchoUsage(u llm.Usage) {
	rs.mu.Lock()
	rs.usage.MergeEcho(u)
	rs.mu.Unlock()
}

func (rs *runState) usageSnapshot() llm.Usage {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.usage
}

func (rs *runState) turnsSnapshot() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.turns
}

// driveAgent constructs the ChatModelAgent + Runner for one run and drains its
// event iterator. Returns the completed tool turns, whether a cancellation was
// already observed at a tool boundary (norma aborted_tools 的判定点), the run
// error (nil = natural stop), and whether the consumer drained to the end.
func (s *Session) driveAgent(ctx context.Context, disabledTools []string, maxTurns int, yield func(harnessEvent, error) bool) (int, bool, error, bool) {
	toolSet := s.registry.List()
	if len(disabledTools) > 0 {
		toolSet = filterTools(toolSet, disabledTools)
	}

	rs := newRunState()

	gate := acllm.NewToolGate(toolSet, s.tcTpl, s.opts.MaxConcurrency).
		SetPermissionMode(s.opts.PermissionMode).
		SetHooks(s.opts.Hooks).
		// P2：checkpoint store armed ⇔ gate 的 ask 走审批中断（两半同源，
		// host 只装配一个开关）。
		SetHitl(s.opts.CheckpointStore != nil)
	if len(s.opts.DeferredTools) > 0 {
		gate.SetDeferred(s.opts.DeferredTools, s.unlock)
	}
	// OnResult host wiring (刀④ 约定): tool results + Result.Extra skill
	// guidance land in the master as norma-shaped DTO — the pump then emits the
	// tool_result event from the eino tool message; the extra messages surface
	// on the next projection exactly like norma's execOne extras.
	gate.OnCallStart = s.OnCallStart
	gate.OnResult = func(callID, name, text string, isErr bool, extras []llm.Message) {
		msgs := make([]llm.Message, 0, 1+len(extras))
		msgs = append(msgs, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
			llm.ToolResultText(callID, text, isErr),
		}})
		msgs = append(msgs, extras...)
		s.dto.Append(msgs...)
		rs.record(callID, isErr)
		// norma query.go:526-528 的取消检查点：工具结果记录时 ctx 已死 → 本次
		// 取消发生在工具阶段（aborted_tools）；ctx 在此处仍活着、其后模型流式
		// 阶段才死的 → aborted_streaming。OnResult 与工具完成同步（先于下一个
		// 模型调用），无事件泵滞后（评审第 2 轮：取代 turns>0 近似）。
		if ctx.Err() != nil {
			rs.markCancelAfterTools()
		}
		if s.OnResult != nil {
			s.OnResult(callID, name, text, isErr, extras)
		}
	}

	einoTools, err := acllm.ToEinoTools(toolSet)
	if err != nil {
		return 0, false, err, true
	}
	infos := make([]*schema.ToolInfo, 0, len(toolSet))
	for _, t := range toolSet {
		ti, err := acllm.ToolInfoOf(t)
		if err != nil {
			return 0, false, fmt.Errorf("askernel: tool %s: %w", t.Name(), err), true
		}
		infos = append(infos, ti)
	}

	ps := &acllm.PromptState{}
	var compactor *acllm.Compactor
	if s.opts.Compaction != nil {
		summarizer := acllm.NewModelSummarizer(s.opts.Model, s.opts.MaxTokens, s.opts.NonStreaming)
		compactor = acllm.NewCompactor(*s.opts.Compaction, summarizer)
	}
	// recorder 只在 writer 非nil 时传入：typed-nil 接口值会绕过中间件的
	// nil 判空，打进 transcript.Writer 的空指针。
	var recorder acllm.TranscriptRecorder
	if s.writer != nil {
		recorder = s.writer
	}
	vm := acllm.NewViewMiddleware(s.dto, ps, compactor, s.opts.SystemPrompt, s.opts.MaxTokens, recorder)

	handlers := []adk.ChatModelAgentMiddleware{
		vm,
		&dateReminderMiddleware{extra: s.opts.SystemReminderFunc},
		acllm.NewInjectionMiddleware(s.dto),
		&todoReminderMiddleware{store: s.todos, dto: s.dto, writer: recorder},
		acllm.NewDeferredMiddleware(infos, s.opts.DeferredTools, s.unlock),
		gate,
	}

	cfg := &adk.ChatModelAgentConfig{
		Name:          "4zreco-kernel",
		Model:         s.opts.Model,
		MaxIterations: maxIterationsFor(maxTurns),
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools:               einoTools,
				UnknownToolsHandler: unknownToolResult(),
			},
		},
		Handlers: handlers,
	}
	if compactor != nil {
		cfg.ModelRetryConfig = acllm.NewReactiveRetryConfig(vm)
	}

	ag, err := adk.NewChatModelAgent(ctx, cfg)
	if err != nil {
		return 0, false, err, true
	}
	// P2（方案 §4-P2 第 1 条）：checkpoint store 非 nil = HITL 半边 armed。
	// 普通 run 也带 checkpoint id（Runner 只在中断时落库，正常完成零开销）——
	// re-interrupt 与同轮聚合都落在同一 id 上（Set 的 ON CONFLICT 复写）。
	runner := adk.NewRunner(ctx, adk.RunnerConfig{Agent: ag, EnableStreaming: !s.opts.NonStreaming,
		CheckPointStore: s.opts.CheckpointStore})
	if res := s.takeResume(); res != nil {
		// HITL 恢复：决定数据按 interrupt id 定点投递（官方 Targets 语义；
		// 未命中的兄弟中断由 gate 以原状态 re-interrupt）。恢复 run 不带
		// WithCheckPointID——Resume 路径由 Runner 自行从 store 读 checkpoint。
		iter, rerr := runner.ResumeWithParams(ctx, res.checkpointID, &adk.ResumeParams{
			Targets: map[string]any{res.interruptID: res.resume},
		})
		if rerr != nil {
			return 0, false, rerr, true
		}
		turns, runErr, drained := s.drainEvents(iter, rs, yield, res.checkpointID)
		return turns, rs.toolsPhaseCancel(), runErr, drained
	}
	cpID := ""
	if s.opts.CheckpointStore != nil {
		cpID = newCheckpointID(s.sessionID)
		if s.opts.OnCheckpointID != nil {
			s.opts.OnCheckpointID(cpID)
		}
		turns, runErr, drained := s.drainEvents(runner.Run(ctx, nil, adk.WithCheckPointID(cpID)), rs, yield, cpID)
		return turns, rs.toolsPhaseCancel(), runErr, drained
	}
	turns, runErr, drained := s.drainEvents(runner.Run(ctx, nil), rs, yield, cpID)
	return turns, rs.toolsPhaseCancel(), runErr, drained
}

func filterTools(tools []actool.CoreTool, disabled []string) []actool.CoreTool {
	block := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		block[d] = true
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if !block[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}

// unknownToolResult is the ToolsNode handler for hallucinated tool names: an
// error tool_result instead of a run-fatal failure (norma execOne semantics;
// 4zrec askernel 同款照抄). The ToolsNode attaches the real call id to the
// resulting tool message; the pump persists it into the DTO (the gate never
// saw that call).
func unknownToolResult() func(ctx context.Context, name, input string) (string, error) {
	return func(_ context.Context, name string, _ string) (string, error) {
		return fmt.Sprintf("Error: unknown tool %q", name), nil
	}
}

// drainEvents is the event pump: it surfaces text/thinking deltas, tool_use,
// tool_result and usage events to the consumer as harness.Events. DTO writes
// do NOT happen here (the view middleware captures assistants and the gate's
// OnResult persists tool results synchronously with the graph) — except for
// unknown-tool results, which the gate never saw. cpID 是本次 run 的 checkpoint
// id（中断事件捕获用；空 = 未 armed）。
func (s *Session) drainEvents(eventIter *adk.AsyncIterator[*adk.AgentEvent], rs *runState, yield func(harnessEvent, error) bool, cpID string) (int, error, bool) {
	var runErr error
	for {
		ev, ok := eventIter.Next()
		if !ok {
			s.absorbUsage(rs)
			return rs.turnsSnapshot(), runErr, true
		}
		if ev.Err != nil {
			runErr = ev.Err // last error wins (4zrec spike drain parity)
			continue
		}
		if ev.Action != nil && ev.Action.Interrupted != nil {
			// P2：工具审批中断——事件流随后闭合。记录首个可归属的中断上下文
			//（聚合中断在恢复侧按 interrupt id 逐个投递决定；未命中的 re-interrupt
			// 会再次浮出，captureInterrupt 只留首个）。
			s.captureInterrupt(hitlFromEvent(ev, cpID))
			continue
		}
		if ev.Output == nil || ev.Output.MessageOutput == nil {
			continue
		}
		mv := ev.Output.MessageOutput

		switch {
		case mv.IsStreaming && mv.Role == schema.Assistant && mv.MessageStream != nil:
			// Assistant stream: emit text/thinking deltas, then assemble the
			// final message for tool calls + usage.
			var (
				chunks []*schema.Message
				serr   error
			)
			for {
				chunk, err := mv.MessageStream.Recv()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						serr = err
					}
					break
				}
				if chunk == nil {
					continue
				}
				if chunk.Content != "" {
					if !yield(harnessEvent{Kind: harness.KindText, Text: chunk.Content}, nil) {
						return rs.turnsSnapshot(), nil, false
					}
				}
				if chunk.ReasoningContent != "" {
					if !yield(harnessEvent{Kind: harness.KindThinking, Text: chunk.ReasoningContent}, nil) {
						return rs.turnsSnapshot(), nil, false
					}
				}
				// 流式 usage 逐块 MergeEcho 折叠（norma Accumulator 同款）——中途
				// 死流的已报告 usage 也留在会话累计里；成功路径的整轮 usage 已由
				// 块折叠覆盖，emitAssistant 不再叠加。
				if chunk.ResponseMeta != nil && chunk.ResponseMeta.Usage != nil {
					if u := acllm.UsageFromToken(chunk.ResponseMeta.Usage); u != (llm.Usage{}) {
						rs.mergeEchoUsage(u)
					}
				}
				chunks = append(chunks, chunk)
			}
			if serr != nil {
				s.absorbUsage(rs)
				return rs.turnsSnapshot(), serr, true
			}
			final, cerr := schema.ConcatMessages(chunks)
			if cerr != nil {
				s.absorbUsage(rs)
				return rs.turnsSnapshot(), cerr, true
			}
			if !emitAssistantStreamed(final, rs, yield) {
				return rs.turnsSnapshot(), nil, false
			}
			if u := rs.usageSnapshot(); u != (llm.Usage{}) {
				if !yield(harnessEvent{Kind: harness.KindUsage, Usage: &u}, nil) {
					return rs.turnsSnapshot(), nil, false
				}
			}

		case mv.Role == schema.Assistant:
			if mv.Message == nil {
				continue
			}
			m := mv.Message
			if m.ReasoningContent != "" {
				if !yield(harnessEvent{Kind: harness.KindThinking, Text: m.ReasoningContent}, nil) {
					return rs.turnsSnapshot(), nil, false
				}
			}
			if m.Content != "" {
				if !yield(harnessEvent{Kind: harness.KindText, Text: m.Content}, nil) {
					return rs.turnsSnapshot(), nil, false
				}
			}
			if !emitAssistant(m, rs, yield) {
				return rs.turnsSnapshot(), nil, false
			}
			if u := rs.usageSnapshot(); u != (llm.Usage{}) {
				if !yield(harnessEvent{Kind: harness.KindUsage, Usage: &u}, nil) {
					return rs.turnsSnapshot(), nil, false
				}
			}

		case mv.Role == schema.Tool:
			if mv.Message == nil {
				continue
			}
			m := mv.Message
			isErr := true
			if rec := rs.lookup(m.ToolCallID); rec != nil {
				isErr = rec.isErr
			} else {
				// Unknown-tool result: the gate never saw this call, so the
				// pump persists it (always an error — the model hallucinated
				// the tool name).
				s.dto.Append(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
					llm.ToolResultText(m.ToolCallID, m.Content, true),
				}})
			}
			block := llm.ToolResultText(m.ToolCallID, m.Content, isErr)
			if !yield(harnessEvent{Kind: harness.KindToolResult, ToolResult: &block}, nil) {
				return rs.turnsSnapshot(), nil, false
			}
		}
	}
}

// absorbUsage folds a run's accumulated usage into the session total.
func (s *Session) absorbUsage(rs *runState) {
	s.mu.Lock()
	s.usage.Add(rs.usageSnapshot())
	s.mu.Unlock()
}

// emitAssistant surfaces tool_use blocks and usage from a NON-streaming
// assistant message (the DTO write itself happened in AfterModelRewriteState).
// A tool-use turn advances the turn counter once (norma: only tool-turns advance
// turnCount; parallel calls in one round stay one turn).
func emitAssistant(m *schema.Message, rs *runState, yield func(harnessEvent, error) bool) bool {
	if !emitAssistantBlocks(m, rs, yield) {
		return false
	}
	if m.ResponseMeta != nil && m.ResponseMeta.Usage != nil {
		if u := acllm.UsageFromToken(m.ResponseMeta.Usage); u != (llm.Usage{}) {
			rs.addUsage(u)
		}
	}
	return true
}

// emitAssistantStreamed is the streaming variant: the per-turn usage was already
// folded chunk-by-chunk (MergeEcho), so only the blocks/turn counter run here —
// adding the assembled message's usage again would double-count the echoed side.
func emitAssistantStreamed(m *schema.Message, rs *runState, yield func(harnessEvent, error) bool) bool {
	return emitAssistantBlocks(m, rs, yield)
}

func emitAssistantBlocks(m *schema.Message, rs *runState, yield func(harnessEvent, error) bool) bool {
	for _, tc := range m.ToolCalls {
		block := &llm.ContentBlock{
			Type:  llm.BlockToolUse,
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(tc.Function.Arguments),
		}
		if !yield(harnessEvent{Kind: harness.KindToolUse, ToolUse: block}, nil) {
			return false
		}
	}
	if len(m.ToolCalls) > 0 {
		rs.mu.Lock()
		rs.turns++
		rs.mu.Unlock()
	}
	return true
}

// dateReminderMiddleware prepends the per-request <system-reminder> (today's
// date always included; SystemReminderFunc contributes extra) to the projected
// request — norma harness/query.go:784-786 parity: a request-shape prepend,
// NOT a master message.
type dateReminderMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]
	extra func() string
}

func (d *dateReminderMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	var extra string
	if d.extra != nil {
		extra = d.extra()
	}
	state.Messages = append([]*schema.Message{schema.UserMessage(buildSystemReminder(extra))}, state.Messages...)
	return ctx, state, nil
}

// buildSystemReminder assembles the reminder content (norma agentcore parity).
func buildSystemReminder(extra string) string {
	b := &strings.Builder{}
	b.WriteString("<system-reminder>\n# currentDate\nToday's date is ")
	b.WriteString(today())
	b.WriteString(".")
	if extra != "" {
		b.WriteString("\n")
		b.WriteString(extra)
	}
	b.WriteString("\n</system-reminder>")
	return b.String()
}

// todoReminderMiddleware ports norma harness.maybeInjectTodoReminder: appends a
// throttled todo <system-reminder> user message to the master (+ transcript)
// when the model has gone long enough without touching TodoWrite and without a
// recent reminder. Throttle turns derive from the API-visible window so a
// reminder re-appears after compaction drops the prior one. No-op when todos
// are disabled or empty.
type todoReminderMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]
	store  *actool.TodoStore
	dto    *acllm.MessageStore
	writer acllm.TranscriptRecorder
}

const (
	todoTurnsSinceWrite      = 10 // norma defaultTodoTurnsSinceWrite
	todoTurnsBetweenReminder = 10 // norma defaultTodoTurnsBetween
)

func (t *todoReminderMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if t.store == nil {
		return ctx, state, nil
	}
	todos := t.store.List()
	if len(todos) == 0 {
		return ctx, state, nil
	}
	apiView := llm.MessagesForAPI(t.dto.Get())
	sinceWrite, sinceReminder := todoReminderTurnCounts(apiView)
	if sinceWrite < todoTurnsSinceWrite || sinceReminder < todoTurnsBetweenReminder {
		return ctx, state, nil
	}
	body := actool.RenderTodoReminder(todos)
	if body == "" {
		return ctx, state, nil
	}
	msg := llm.TodoReminderMessage(body)
	t.dto.Append(msg)
	if t.writer != nil {
		t.writer.RecordMessage(msg, llm.Usage{})
	}
	state.Messages = append(state.Messages, acllm.ToSchema([]llm.Message{msg})...)
	return ctx, state, nil
}

// todoReminderTurnCounts scans messages (most-recent first) and returns the
// number of assistant turns since the last TodoWrite tool_use and since the
// last todo reminder — norma harness parity, verbatim.
func todoReminderTurnCounts(msgs []llm.Message) (sinceWrite, sinceReminder int) {
	foundWrite, foundReminder := false, false
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if !foundReminder && llm.IsTodoReminder(m) {
			foundReminder = true
			continue
		}
		if m.Role != llm.RoleAssistant {
			continue
		}
		if !foundWrite {
			if messageHasToolUse(m, "TodoWrite") {
				foundWrite = true
			} else {
				sinceWrite++
			}
		}
		if !foundReminder {
			sinceReminder++
		}
	}
	return
}

func messageHasToolUse(m llm.Message, name string) bool {
	for _, b := range m.Content {
		if b.Type == llm.BlockToolUse && b.Name == name {
			return true
		}
	}
	return false
}
