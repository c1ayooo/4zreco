package askernel

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"math"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/kernel/termmap"
)

// harnessEvent / harnessTerminal alias the norma harness event vocabulary: the
// kernel's output stream IS the harness.Event shape, so the host capture driver
// (capture.go) iterates it unchanged and terminalreason.go/wrapup.go keep
// consuming harness.Terminal — the frozen contract the engine depends on.
type (
	harnessEvent    = harness.Event
	harnessTerminal = harness.Terminal
)

// Session is a long-lived conversation over one model + one toolset. Call
// Prompt/Continue/RunSettlement repeatedly; the DTO master and the transcript
// persist across calls. Not safe for concurrent Prompt calls on the same
// Session (mirrors norma agentcore).
//
// 每个 Prompt/Continue/RunSettlement = 一次有界 runner run；空轮次续跑、Stop 链、
// 结算的循环判定在宿主 driver（包注释路线 A）。
type Session struct {
	opts Options

	registry *actool.Registry // assembled toolset, registration order
	unlock   *actool.UnlockSet
	tasks    *actool.Manager
	todos    *actool.TodoStore

	tcTpl acllm.ToolTemplate // per-call ToolContext template (CallID filled in)

	dto *acllm.MessageStore // DTO master: the single source of truth

	mu    sync.Mutex
	usage llm.Usage // cumulative usage (rebuilt on Resume, accumulated per run)

	sessionID string
	store     *transcript.Store
	writer    *transcript.Writer // satisfies acllm.TranscriptRecorder structurally

	// OnCallStart observes kernel-managed tool call initiation, synchronously
	// before the permission pipeline / hooks (acllm.ToolGate.OnCallStart). The
	// host wires it to its intercept audit trace (Trace.Start) so the guard's
	// WithCall claim binds deterministically — in norma the tool_use event was
	// yielded before execOne; in eino the tools node races the event pump.
	// Optional; set before the first Prompt/Continue.
	OnCallStart func(callID, name string, input json.RawMessage)

	// OnResult observes gate-executed calls AFTER the kernel's own DTO write
	// (kernel first: master + transcript; host second: intercept audit context
	// entries + execution status — synchronous at execution end, so the NEXT
	// call's judge sees the prior result without racing the event pump).
	// Optional.
	OnResult func(callID, name, text string, isErr bool, extras []llm.Message)
}

// NewSession builds a Session, mirroring norma agentcore.NewSession's assembly
// order: tools → webfetch → websearch → todos → background tasks → deferred
// access tools → transcript writer. Configuration warnings go to opts.OnWarn;
// nothing is written to stdout/stderr.
func NewSession(opts Options) *Session {
	s := &Session{opts: opts}

	toolSet := opts.Tools
	if toolSet == nil {
		toolSet = actool.DefaultTools()
	}
	if s.opts.PermissionMode == "" {
		s.opts.PermissionMode = acperm.ModeBypass
	}
	if s.opts.MaxConcurrency <= 0 {
		s.opts.MaxConcurrency = 10 // norma harness Query default
	}

	tools := append([]actool.CoreTool(nil), toolSet...)
	if opts.EnableWebFetch {
		tools = append(tools, actool.NewWebFetch(actool.WebFetchConfig{Proxy: opts.WebFetchProxy, CACert: opts.WebFetchCACert}))
	}
	if opts.EnableWebSearch {
		// A misconfigured backend drops the tool rather than failing the whole
		// session — agentcore parity.
		if ws, err := actool.NewWebSearch(actool.WebSearchConfig{Backend: opts.WebSearchBackend, BraveAPIKey: opts.BraveSearchAPIKey, TavilyAPIKey: opts.TavilySearchAPIKey, DeepSeekBaseURL: opts.DeepSeekSearchBaseURL, DeepSeekAPIKey: opts.DeepSeekSearchAPIKey, DeepSeekModel: opts.DeepSeekSearchModel, Proxy: opts.WebSearchProxy}); err == nil {
			tools = append(tools, ws)
		} else {
			s.warn("web_search dropped: " + err.Error())
		}
	}
	if opts.Todos != nil {
		s.todos = opts.Todos
		tools = append(tools, opts.Todos.Tool())
	}

	// A session id is always needed (background-task temp dir + transcript file).
	s.sessionID = opts.SessionID
	if s.sessionID == "" {
		s.sessionID = transcript.NewSessionID()
	}
	// Background-task execution: per-session manager + its tools (agentcore
	// parity; the AGENT_CORE_DISABLE_BACKGROUND_TASKS env still applies).
	if !opts.DisableBackgroundTasks {
		if mgr, err := actool.NewManager(s.sessionID); err == nil {
			s.tasks = mgr
			tools = append(tools, actool.NewTaskOutput(), actool.NewTaskStop(), actool.NewTaskList(), actool.NewMonitor())
		}
	}

	// Deferred tools: withhold their schemas (deferredMiddleware) but keep them
	// callable through the two always-loaded access tools, which close over the
	// registry (it already holds the deferred tools) — agentcore parity.
	s.registry = actool.NewRegistry(tools...)
	if len(opts.DeferredTools) > 0 {
		s.unlock = opts.UnlockSet
		if s.unlock == nil {
			s.unlock = actool.NewUnlockSet(opts.DeferredTools...)
		}
		s.registry.Add(actool.NewSearchExtraTools(s.registry, opts.DeferredTools))
		s.registry.Add(actool.NewExecuteExtraTool(s.registry, s.unlock))
	}

	s.dto = acllm.NewMessageStore()
	s.tcTpl = acllm.ToolTemplate{
		WorkingDir:     opts.WorkingDir,
		AgentID:        opts.AgentID,
		MaxOutputChars: opts.MaxToolOutputChars,
		OutputDir:      opts.ToolOutputDir,
		Tasks:          s.tasks,
		Env:            opts.BashEnv,
	}

	if opts.Transcript != nil {
		s.store = opts.Transcript
		s.writer = s.store.NewWriter(s.sessionID, "")
	}
	return s
}

// warn reports a configuration warning to the host, if it asked for them.
func (s *Session) warn(msg string) {
	if s.opts.OnWarn != nil {
		s.opts.OnWarn("askernel: " + msg)
	}
}

// SessionID returns the transcript session id (always non-empty).
func (s *Session) SessionID() string { return s.sessionID }

// UnlockSet returns the deferred-tool call gate (nil when no deferred tools).
func (s *Session) UnlockSet() *actool.UnlockSet { return s.unlock }

// Usage returns the cumulative token usage (rebuilt on Resume, accumulated per
// run — norma parity).
func (s *Session) Usage() llm.Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

// Messages returns the DTO master (full, non-destructive — includes compact
// boundaries).
func (s *Session) Messages() []llm.Message { return s.dto.Get() }

// DrainNotifications surfaces pending background-task completions as the
// <task-notification> text block. The driver calls this at a natural stop: any
// output → AppendUser + Continue (norma ContinueTaskNotification semantics,
// route A: the loop lives in the host).
func (s *Session) DrainNotifications() string {
	if s.tasks == nil {
		return ""
	}
	notes := s.tasks.DrainNotifications()
	if len(notes) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range notes {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(n.String())
	}
	return b.String()
}

// Close releases session resources (background tasks and their temporary
// output directory). Safe to call multiple times.
func (s *Session) Close() error {
	if s.tasks != nil {
		s.tasks.Cleanup()
		s.tasks = nil
	}
	return nil
}

// Resume reloads a prior conversation from the transcript store: load →
// cleanResumed (drop trailing dangling tool_use) → cumulative usage rebuild →
// ResumeWriter, so the next Prompt continues the same file. Requires
// Options.Transcript. 旧会话（norma 时代落盘的 JSONL）按同一冻结形状回放。
func (s *Session) Resume(sessionID string) error {
	if s.store == nil {
		return errors.New("askernel: Resume requires Options.Transcript")
	}
	recs, err := s.store.Load(s.store.MainPath(sessionID))
	if err != nil {
		return err
	}
	msgs, usage := transcript.Messages(recs)
	s.dto.Set(cleanResumed(msgs))
	s.mu.Lock()
	s.usage = usage
	s.mu.Unlock()
	s.sessionID = sessionID
	if s.writer != nil {
		s.writer = s.store.ResumeWriter(sessionID, transcript.LastUUID(recs))
	}
	return nil
}

// cleanResumed drops trailing assistant tool calls whose results were never
// persisted — a crash mid-tool would otherwise leave a dangling tool_use that
// the API rejects (norma agentcore parity).
func cleanResumed(msgs []llm.Message) []llm.Message {
	for len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if last.Role == llm.RoleAssistant && len(last.ToolUses()) > 0 {
			msgs = msgs[:len(msgs)-1]
			continue
		}
		break
	}
	return msgs
}

// AppendUser appends a user message to the master + transcript (route A seam:
// the driver's nudges, Stop-chain blocking messages and settlement prompts land
// here, then Continue reruns the agent over the extended master).
func (s *Session) AppendUser(text string) {
	if text == "" {
		return
	}
	msg := llm.UserText(text)
	s.dto.Append(msg)
	if s.writer != nil {
		s.writer.RecordMessage(msg, llm.Usage{})
	}
}

// Prompt appends input as a user message and streams ONE bounded agent run to
// completion. The final event is KindResult carrying a Terminal (unless the
// consumer stops draining early).
func (s *Session) Prompt(ctx context.Context, input string) iter.Seq2[harnessEvent, error] {
	return func(yield func(harnessEvent, error) bool) {
		// Background-task completions that landed since the previous turn
		// surfaced before the new user message (agentcore parity).
		if notes := s.DrainNotifications(); notes != "" {
			s.AppendUser(notes)
		}
		s.AppendUser(input)
		s.runStream(ctx, nil, s.opts.MaxTurns, yield)
	}
}

// Continue streams ONE bounded agent run with no new user input — the driver
// appended its nudge / blocking message / notification via AppendUser first.
func (s *Session) Continue(ctx context.Context) iter.Seq2[harnessEvent, error] {
	return func(yield func(harnessEvent, error) bool) {
		s.runStream(ctx, nil, s.opts.MaxTurns, yield)
	}
}

// RunSettlement appends the wrap-up prompt and streams ONE bounded run with
// disabledTools hidden from the model (route-A settlement primitive). The
// DRIVER decides when to call it (budget terminal) and keeps the ORIGINAL
// budget reason on the final Terminal regardless of how this run ends —
// norma: the settlement is just a checkpoint; finish(settleReason) either way.
func (s *Session) RunSettlement(ctx context.Context, prompt string, disabledTools []string, maxTurns int) iter.Seq2[harnessEvent, error] {
	return func(yield func(harnessEvent, error) bool) {
		s.AppendUser(prompt)
		s.runStream(ctx, disabledTools, maxTurns, yield)
	}
}

// runStream drives one runner run and maps its outcome onto the frozen
// TerminalReason vocabulary via termmap (方案 §4-P1 第 6 条). turns counts
// completed tool turns (norma turnCount parity: only tool-turns advance);
// the driver uses it to re-arm its Stop chain (stopHookActive).
func (s *Session) runStream(ctx context.Context, disabledTools []string, maxTurns int, yield func(harnessEvent, error) bool) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.opts.MaxDuration > 0 {
		var stopClock context.CancelFunc
		runCtx, stopClock = context.WithTimeout(runCtx, s.opts.MaxDuration)
		defer stopClock()
	}
	if s.writer != nil {
		// transcript.WithSessionID → llmrec 归属（guard Log 的会话 id 由宿主在
		// 更外层经 ctx 挂 intercept.ConvIDFromContext 所需值）。
		runCtx = transcript.WithSessionID(runCtx, s.sessionID)
	}

	turns, toolsPhase, runErr, drained := s.driveAgent(runCtx, disabledTools, maxTurns, yield)
	if !drained {
		return // consumer stopped draining — end without KindResult (norma consumerStopped)
	}

	term := &harnessTerminal{Turns: turns}
	if runErr != nil {
		// Phase（norma 双检查点的忠实移植）：取消在某个工具结果记录时已可见
		//（gate OnResult 同步观测）→ 工具阶段（aborted_tools）；ctx 在工具边界
		// 仍活着、其后的模型流式阶段才死 → 流式阶段（aborted_streaming）。此前
		// 的 turns>0 近似会把「工具轮之后的模型流式取消」误记成 aborted_tools
		//（评审第 2 轮 #1）。
		phase := termmap.PhaseModel
		if toolsPhase {
			phase = termmap.PhaseTools
		}
		term.Reason, term.Err = termmap.MapError(runCtx, runErr, phase)
	} else {
		term.Reason = termmap.Completed
	}
	term.Messages = s.dto.Get()
	term.Text = lastAssistantText(s.dto.Get())
	term.Usage = s.Usage()

	yield(harnessEvent{Kind: "result", Terminal: term}, nil)
}

// lastAssistantEmpty reports whether the last assistant message in the master
// has neither text nor tool calls (the route-A empty-turn nudge condition).
func lastAssistantEmpty(dto []llm.Message) bool {
	m := lastAssistant(dto)
	if m == nil {
		return false
	}
	return m.Text() == "" && len(m.ToolUses()) == 0
}

func lastAssistant(dto []llm.Message) *llm.Message {
	for i := len(dto) - 1; i >= 0; i-- {
		if dto[i].Role == llm.RoleAssistant {
			return &dto[i]
		}
	}
	return nil
}

// lastAssistantText returns the last assistant message's text (Terminal.Text).
func lastAssistantText(dto []llm.Message) string {
	if m := lastAssistant(dto); m != nil {
		return m.Text()
	}
	return ""
}

// maxIterationsFor translates norma's "0 = unlimited" MaxTurns into the ADK's
// iteration budget (adk treats 0 as its own default of 20 — NOT unlimited).
func maxIterationsFor(maxTurns int) int {
	if maxTurns > 0 {
		return maxTurns
	}
	return math.MaxInt32
}
