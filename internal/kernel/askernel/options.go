// Package askernel is the eino ADK implementation of the norma
// agentcore+harness runtime (docs/Eino深度接入方案-2026-11-05.md §4-P1 第 4/8 条,
// 刀④ 切换默认): a stateful Session whose Prompt/Continue methods stream ONE
// bounded agent run as a range-over-func iterator of harness Events, on top of
// a ChatModelAgent + Runner assembled per run.
//
// Core invariant (4zrec askernel 同款): the kernel holds a DTO master history
// (acllm.MessageStore) as the single source of truth. Transcripts record DTO
// births verbatim (frozen JSONL format via the acllm.TranscriptRecorder seam —
// norma transcript.Writer satisfies it structurally), and every model call
// projects the post-boundary working set through acllm.ToSchema — compaction
// semantics do not drift from the norma era. There are no ADK checkpoints in
// this cut: run pause/resume remains ctx cancellation plus transcript replay
// (P2 引入 checkpoint 时才需要 CheckpointStore；runner_checkpoints.fingerprint
// 已由本刀先行落库，见 fingerprint.go)。
//
// 与 4zrec askernel 的关键分叉（方案 §3.1 路线 A，本刀定案）：
//
//   - 空轮次续跑（empty-turn nudge）、Stop 钩子链（idle-stop 写回收手）、
//     任务通知续跑、结算（settlement）的【循环判定】全部上移宿主 driver
//     （internal/agent 的 capture 驱动）。内核只提供单次有界 run 与
//     AppendUser/Continue/RunSettlement 三个原语。理由：nudge 预算按
//     「每条意图总量」落 DB（engine 持有 DB，内核没有），§3.1 明确路线 A。
//   - eino 的 ReAct 循环在「模型无 tool_call」即终态且无 Continue 语义，
//     所以这里的一个 run ≈ norma loop 的一轮「自然结束」；宿主把
//     注入消息 append 进 master 后以 Continue 重开一次 run（同一条 DTO
//     master、同一 session/transcript 链 = 同一 checkpoint 链）。
//
// TerminalReason 的错误映射不在本包：internal/kernel/termmap 单独成包，
// 表驱动单测锁定 12 种终态的来源（方案 §4-P1 第 6 条）。
package askernel

import (
	"time"

	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/cloudwego/eino/components/model"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/kernel/termmap"
)

// Options configures a Session — the norma agentcore.Options surface the four
// agent assemblies (worker/planner/mainagent/chat) already speak, narrowed to
// what the eino kernel implements. Fields the norma SDK had but 4zreco never
// set (Plan/Memory/Skills/AskUser/TokenBudget/EscalateMaxTokens) are dropped;
// noa 尚未随 eino 迁移（宿主侧回退内置 compaction 并告警）。
type Options struct {
	// Model is the chat model the loop calls. The host hands
	// acllm.BridgeModel(norma provider) — the provider stack beneath (failover,
	// recording, quota capture, retries) stays byte-identical — or an eino-side
	// pool model.
	Model model.ToolCallingChatModel

	// SystemPrompt is the host-controlled system prompt, in segments (joined
	// with "\n\n" into one system message per request, norma provider parity).
	SystemPrompt []string

	// Tools the agent may call. Nil → actool.DefaultTools() (agentcore parity).
	Tools []actool.CoreTool

	// DeferredTools names tools whose schemas are withheld from the model.
	// Non-empty → the kernel auto-adds the two access tools
	// (SearchExtraTools/ExecuteExtraTool) and arms the V5 hard gate.
	DeferredTools []string
	UnlockSet     *actool.UnlockSet

	// Hooks is the PreToolUse/PostToolUse seam (guard 链 + steer + toollog +
	// 空转拦截, composed by the host). The norma Stop half is deliberately
	// absent — 空转续跑/收手上移宿主 driver（§3.1 路线 A）.
	Hooks acllm.ToolHooks

	// Permission policy. Zero mode → bypass (4zreco 全 agent 显式 bypass).
	PermissionMode acperm.Mode

	// Compaction enables the acllm Compactor (Pre/Reactive/ContextView 三挂点,
	// 刀③ 移植). Nil = off.
	Compaction *acllm.CompactionConfig

	MaxTurns     int           // 0 = unlimited (adk 需要 >0，内核给 MaxInt32)
	MaxDuration  time.Duration // run 墙钟（ctx deadline；4zrec 已接受取舍：模型与工具同受墙钟）
	MaxTokens    int           // 0 = 不发上限
	NonStreaming bool          // true → EnableStreaming=false，整轮非流式
	MaxConcurrency int         // ≤0 = 10（norma harness 默认）

	WorkingDir        string
	AgentID           string
	ToolOutputDir     string
	MaxToolOutputChars int
	BashEnv           []string

	// Todos, when non-nil, adds the TodoWrite tool backed by this store and
	// arms the throttled todo reminder middleware (norma harness 同款).
	Todos *actool.TodoStore

	EnableWebFetch bool
	WebFetchProxy  string
	WebFetchCACert string

	EnableWebSearch       bool
	WebSearchBackend      string
	BraveSearchAPIKey     string
	TavilySearchAPIKey    string
	DeepSeekSearchBaseURL string
	DeepSeekSearchAPIKey  string
	DeepSeekSearchModel   string
	WebSearchProxy        string

	// Transcript, when non-nil, persists the conversation (frozen JSONL shape).
	Transcript *transcript.Store
	// SessionID names the transcript file. Empty generates a fresh id.
	SessionID string

	// DisableBackgroundTasks prevents the background-task tools
	// (TaskOutput/TaskStop/TaskList/Monitor) from being added.
	DisableBackgroundTasks bool

	// SystemReminderFunc, when set, contributes extra content to the
	// <system-reminder> prepended to every request (today's date is always
	// included). Per-request prepend, NOT a master message — norma parity.
	SystemReminderFunc func() string

	// OnWarn receives configuration warnings (misconfigurations worked around).
	OnWarn func(string)
}

// Settlement describes the wrap-up phase the HOST driver triggers after a
// budget termination (路线 A 收尾同机制): the driver appends the prompt and
// calls Session.RunSettlement with these fields. The shape mirrors norma
// harness.Settlement so wrapup.go ports with an import swap only.
type Settlement struct {
	Prompt string
	// PromptByReason keys by terminal reason (e.g. termmap.Timeout / MaxTurns);
	// termmap.Reason aliases harness.TerminalReason, so wrapup.go's literal map
	// ports with an import swap only.
	PromptByReason map[termmap.Reason]string
	DisabledTools  []string
	MaxTurns       int // ≤0 → 内核给 2（norma settleMaxTurns 默认）
}

// PromptFor resolves the settlement prompt for a reason: PromptByReason override
// when present and non-empty, else Prompt (norma Settlement.promptFor parity).
func (s *Settlement) PromptFor(reason termmap.Reason) string {
	if s == nil {
		return ""
	}
	if s.PromptByReason != nil {
		if p := s.PromptByReason[reason]; p != "" {
			return p
		}
	}
	return s.Prompt
}

// llm import guard: session.go uses norma DTO vocabulary directly; keeping the
// import here documents the shared vocabulary decision in one place.
var _ = llm.Usage{}
