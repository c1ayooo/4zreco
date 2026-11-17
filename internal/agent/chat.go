package agent

import (
	"context"
	"os"
	"time"

	"github.com/c1ayooo/4zreco/internal/config"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/guard"
	"github.com/c1ayooo/4zreco/internal/intercept"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/c1ayooo/4zreco/internal/norma/transcript"
	"github.com/cloudwego/eino/adk"
)

// ChatAgent is the generic, task-independent conversational runner behind the chat
// page. It generalizes MainAgent.Chat: any agent (built-in OR a custom one, by
// key) can be chatted with, multi-turn history resumed from the transcript. It is
// a PURE ASSISTANT — base tools are the SDK DefaultTools (Bash/Read/Write/Edit/
// LS/Glob/Grep) plus whatever skills/MCP the key is made visible; NO pentest
// graph/task context is injected (that stays exclusive to MainAgent).
type ChatAgent struct {
	prov           llm.Provider
	model          string
	workDir        string
	tx             *transcript.Store
	window         int
	proxyAddr      string
	proxyCACert    string
	webSearch      WebSearchOpts
	guard          *guard.Guard // optional; nil disables intercept hooks for chat
	nonStreamingFn func() bool  // resolver: use non-streaming (Complete) path? (nil = streaming)
	maxTokensFn    func() int   // resolver: per-reply output cap (nil/0 = send no cap)
	// hitlFn 是 hitl_mode=eino 的 chat 半边（P2，engine 接线）：返回本 run 的
	// checkpoint store 与停靠钩子（store nil = channel 语义照旧）。每次 Chat 读
	// 一遍——开关对下一次会话生效，与 checkpoint 装配同一时点。
	hitlFn ChatHitlSource
}

func NewChatAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window int) *ChatAgent {
	return &ChatAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window}
}

// SetNonStreaming wires a resolver deciding whether chat runs use the
// non-streaming model path (true = non-streaming). nil/unset = streaming.
func (c *ChatAgent) SetNonStreaming(fn func() bool) { c.nonStreamingFn = fn }

func (c *ChatAgent) nonStreaming() bool { return c.nonStreamingFn != nil && c.nonStreamingFn() }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (c *ChatAgent) SetMaxTokens(fn func() int) { c.maxTokensFn = fn }

func (c *ChatAgent) maxTokens() int {
	if c.maxTokensFn == nil {
		return 0
	}
	return c.maxTokensFn()
}

// SetProxy points the chat agent's WebFetch/Bash at the recording proxy plus the
// CA cert it trusts (empty addr = direct). Kept for parity with the other agents.
func (c *ChatAgent) SetProxy(addr, caCert string) { c.proxyAddr, c.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the chat agent (off by default).
func (c *ChatAgent) SetWebSearch(o WebSearchOpts) { c.webSearch = o }

// SetGuard attaches a guard (with user-configured intercept rules) to this chat
// agent. Must be called before Chat; safe to call multiple times.
func (c *ChatAgent) SetGuard(g *guard.Guard) { c.guard = g }

// ChatHitlSource 是 hitl_mode 的 chat 半边接线类型（engine 提供实现；adk 类型
// 在 agent 侧命名——engine*.go 源文件不得出现 eino 引用，R1 机检口径）。ctx 是
// 本次 run 的上下文：停靠钩子随它感知取消（客户端断开 → 审批按取消收尾，与
// channel 模式的 HandleAsk 同观感）。
type ChatHitlSource = func(ctx context.Context) (adk.CheckPointStore, func(*askernel.HitlInterrupt) (*db.HitlResumeData, bool))

// SetHitl wires the hitl_mode=eino chat half（P2）：fn 返回本次 run 的 checkpoint
// store 与停靠钩子（store nil = channel 语义照旧）。每次 Chat 读取——开关对下一
// 次会话生效。nil fn = 永远 channel。
func (c *ChatAgent) SetHitl(fn ChatHitlSource) { c.hitlFn = fn }

// chatWorkDirSpec returns a working-directory notice appended to every chat
// agent's system prompt. Mirrors artifactSpec but without pentest-specific
// wording ("payload", "抓响应体") that would be odd in a general assistant.
func chatWorkDirSpec(workDir string) string {
	return "\n\n**文件输出规约**：需要写文件时，一律写到工作目录 " + workDir + "（这是默认 CWD，相对路径即落在这里，也可用该绝对路径）——不要写 /tmp 或其他绝对路径。"
}

// chatSystem renders the DB-managed prompt body for agentKey. Custom agents have
// no per-key in-code default, so DefaultAssistantPrompt is the render fallback.
func chatSystem(agentKey, dataDir, workDir string) string {
	out := renderSystem(agentKey, DefaultAssistantPrompt, chatVars{DataDir: dataDir, Now: nowStr()}) + chatWorkDirSpec(workDir)
	// 执行/报告/复测类对话 agent 也注入授权口径（engagementFraming）——它们不走
	// planner/worker 的 system 装配，只在 chat 路径运行；该口径同时是 llmguard
	// 拒答守卫的触发锚。pentest 另注入全量危害验证协议与编排纪律；reporter 另注入
	// SRC 全量证据附录（0.4.71 全量危害验证协议移植）。
	switch agentKey {
	case "pentest":
		out += engagementFraming + impactVerificationGuidance + impactOrchestrationGuidance + srcReportAnnex
	case "reporter":
		out += engagementFraming + srcReportAnnex
	case "retester":
		out += engagementFraming
	}
	return out
}

// chatVars carries the runtime variables a custom agent's prompt may reference.
// DataDir (server data root) + Now (server wall-clock, refreshed each turn) are the
// universal ones; any other {{.X}} fails to render and falls back to
// DefaultAssistantPrompt.
type chatVars struct{ DataDir, Now string }

// Chat runs ONE turn of a conversation with the agent identified by agentKey,
// resuming prior history keyed by sessionID. maxTurns is the per-turn agent step
// budget (0 = unlimited). maxDuration is the wall-clock run budget per turn
// (0 = unlimited); the timer resets each time Chat is called, so a new user
// message always starts a fresh countdown. webSearch gates network search for
// THIS agent (the global backend/key still come from the chat agent's config,
// but each agent decides on/off). emit receives each execution step (thinking /
// tool_use / tool_result / text / result), tagged with the agent key as the
// worker lane.
func (c *ChatAgent) Chat(ctx context.Context, agentKey, sessionID, message string, maxTurns int, maxDuration time.Duration, webSearch bool, emit func(db.Activity)) (string, error) {
	// gate the global web-search opts by this agent's own flag.
	ws := c.webSearch
	if !webSearch {
		ws.Enabled = false
	}

	// Per-session working directory: <workDir>/sessions/<sessionID>/
	// Isolates file writes across conversations, mirroring how workers use i<intentID>/.
	// 布局解析走 config.Paths（SessionDir；F4 2026-11-13 收敛）。
	sessionWorkDir := config.DerivePaths(c.workDir).SessionDir(sessionID)
	_ = os.MkdirAll(sessionWorkDir, 0o755)
	ctx = intercept.WithReviewWorkingDirectory(ctx, sessionWorkDir)

	// Pure assistant: DefaultTools as the base; AugmentTools layers in the key's
	// visible skills/MCP and lets the DB tools table filter/override. DefaultTools
	// have no tools-table rows, so they always pass through.
	base := actool.DefaultTools()
	ctx = WithRunInfo(ctx, RunInfo{SessionID: sessionID, Kind: KindChat})
	tools, def, cleanup := AugmentTools(ctx, agentKey, base)
	defer cleanup()

	system, _ := deferredSystem(chatSystem(agentKey, c.workDir, sessionWorkDir), def)
	// DynamicBoundary（缓存断点）语义按 4zrec V5 定案放弃——system 分段在内核侧
	// 拼成一条 system message，缓存交 provider 侧。
	// O3：公共装配段收敛进 kernelOptions（kernel_options.go）；chat 的差异化参数
	// （按 agent key 门控的搜索开关 ws、按轮重置的墙钟预算、SDK 默认回显上限）留在
	// 本调用点。
	opts := kernelOptions(kernelOptionsSeed{
		prov:             c.prov,
		system:           system,
		tools:            tools,
		def:              def,
		proxyAddr:        c.proxyAddr,
		proxyCACert:      c.proxyCACert,
		webSearch:        ws,
		workingDir:       sessionWorkDir,
		maxTurns:         maxTurns,
		maxDuration:      maxDuration,
		compactionWindow: c.window,
		todos:            actool.NewTodoStore(),
		// 截断上限留 SDK 默认(tool.Capture 的 30000 字符)，不设 maxToolOutputChars。
		nonStreaming: c.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		maxTokens:    c.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	})
	// 命中预算(步数)→ 收尾机制(runKernel 的 settlement 分支):输出一句总结。
	// Prompt 与收尾轮数按本 agent key 后台可编辑
	// (自定义 agent 各自一份;留空/0 用通用默认:10 轮)。
	settle := wrapupSettlement(agentKey, nil)
	hooks := harness.HookRunner(toolLogSink(KindChat))
	if c.guard != nil {
		// 日志层套在拦截链外侧（先记后转发），纯旁路。
		hooks = wrapToolLog(c.guard.Hooks(), KindChat, "")
	}
	opts.Hooks = hooks // gate 的 PreToolUse/PostToolUse 半边（结构兼容 acllm.ToolHooks）
	// P2 HITL（hitl_mode=eino）：armed 时 ask 走审批中断 + checkpoint（停靠在
	// engine 注册表，与任务共用 pendingID 键）；store nil = channel 语义照旧。
	var hitlPark func(*askernel.HitlInterrupt) (*db.HitlResumeData, bool)
	if c.hitlFn != nil {
		if store, park := c.hitlFn(ctx); store != nil {
			opts.CheckpointStore = store
			hitlPark = park
		}
	}
	if c.tx != nil { // persist raw human↔AI conversation; one accumulating file per thread
		opts.Transcript = c.tx
		opts.SessionID = sessionID
	}
	ctx = attachSideCapture(ctx)
	s := askernel.NewSession(opts)
	defer s.Close()
	// reload prior conversation so the agent has context across turns (each Chat is
	// a fresh session). First turn: no file yet → Resume loads nothing and proceeds.
	if c.tx != nil {
		_ = s.Resume(sessionID)
	}
	// re-unlock skill-gated MCPs from prior Skill() calls in the reloaded history so
	// revealed tools stay callable across the fresh session.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = agentKey
			emit(r)
		}
	}, kernelDriver{stop: hooks, settle: settle, park: hitlPark})
	return text, err
}
