// The tool gate: the eino-side execution surface for bridged tools
// (docs/Eino深度接入方案-2026-11-05.md §3.2 模板注入 + §3.3 并发分流 + §4-P1 第 4 条;
// 刀③ 落地 guard 链 / deferred 硬门控 / PostToolUse 审计尾钩).
//
// ToolGate is a ChatModelAgentMiddleware whose WrapInvokableToolCall wraps every
// kernel-managed tool call with norma execOne's ordering, verbatim:
//
//  0. deferred 硬门控（V5 双保险的执行期那一半；schema 过滤另一半在
//     deferredMiddleware）——锁定的 deferred 工具直呼即报错
//  1. schema validation (unless the tool opts out via RawInput)
//  2. permission pipeline — full norma parity (mode / rule lists / ask
//     callback); 4zreco agents run bypass today
//  3. PreToolUse hooks（guard 链 egress→tarpit→规则→judge + steer drain +
//     空转拦截 + toollog——宿主把整条包装链经 SetHooks 交进来）。本刀 ask 仍走
//     现有 channel HandleAsk（判定函数在 internal/guard、internal/intercept，
//     R4 红线不动）；P2 HITL 才把 ask 换成 tool.StatefulInterrupt
//  4. ToolContext 注入（ToolUseID = adk.ToolContext.CallID）+ 并发分流
//     (IsConcurrencySafe → toolsched) + panic-safe call
//     [刀④挂点] 墙钟：norma 的「仅工具受 MaxDuration」语义在工具 ctx 上落地
//     （见步骤 4 注释）；本刀沿用 Runner ctx 携带的 deadline（4zrec 取舍）
//  5. capOutput（幂等，唯一收口）
//  6. PostToolUse hooks（guard.postToolUse 归因分类器 + toollog——同一
//     ToolHooks seam 的 PostToolUse 半边，在结果文本定形之后）
//  7. "(no output)" 归一 + OnResult 观测
//
// Like 4zrec's gateMiddleware, the returned endpoint NEVER returns a non-nil Go
// error: tool failures must reach the model as error tool_result text, and the
// eino ToolsNode would turn a Go error into a run-fatal failure. Unknown tools
// pass through untouched (the agent-level UnknownToolsHandler owns hallucinated
// names — kernel-assembly business).
//
// 4zrec reference: internal/kernel/askernel/middleware.go gateMiddleware.execOne.
package acllm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/db"
)

// ToolHooks is the PreToolUse/PostToolUse seam the host hands to the gate —
// structurally the norma harness.HookRunner minus Stop (the kernel has no Stop
// hook; 方案 §3.1 — 空转续跑上移 engine，刀④). Any *hook.Registry
// (guard.Guard.Hooks()) and the agent package's wrappers (steerHooks,
// toolLogHooks, idleStopHooks) satisfy it, so the guard chain runs here with
// its judgment code untouched in internal/guard (R4 红线).
type ToolHooks interface {
	PreToolUse(ctx context.Context, name string, input []byte) (block bool, message string, updated []byte)
	PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool)
}

// ToolGate adapts a set of CoreTools onto an eino agent: the same list goes to
// ToEinoTools for model binding and into the gate for execution. Not safe to
// mutate after NewToolGate; one gate per runner run's toolset.
type ToolGate struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	tools map[string]actool.CoreTool // kernel-managed tools, by name
	list  []actool.CoreTool          // same tools, registration order (Managed)
	tpl   ToolTemplate               // run-level ToolContext template (§3.2)
	mode  acperm.Mode                // permission mode (zero → bypass, 4zreco 现状)
	sched *toolScheduler

	// hooks 是 PreToolUse/PostToolUse 尾钩 seam（guard 链 + steer + toollog +
	// 归因分类器——宿主装配的整条包装链）。nil = 无钩子。
	hooks ToolHooks

	// deferred/unlock 是 V5 延迟工具的执行期硬门控输入（SetDeferred）：
	// deferred 集合里的名字，凡 unlock 未解锁者，直呼即在步骤 0 报错。
	deferred map[string]bool
	unlock   *actool.UnlockSet

	// Permission policy inputs (norma harness QueryInput parity): allow/deny
	// rules consulted by the pipeline's rule stages, and the interactive
	// approval callback consulted at the ask stage. 4zreco agents run bypass
	// and leave all three unset today; the fields exist so a future non-bypass
	// mode keeps norma semantics instead of silently dropping them. The ask
	// callback here is policy-level only — the guard/intercept chain's real
	// ask 走 SetHooks 注入的链内 HandleAsk（channel 语义照旧，P2 才换 Interrupt）.
	allowed    []string
	disallowed []string
	ask        acperm.CanUseTool

	// OnResult observes each gate-executed call, synchronously on the
	// executing goroutine. The kernel cut wires it to DTO/transcript writes
	// (result text + Result.Extra skill-guidance messages); nil = observe
	// nothing. isErr reports actool.Result.IsError — the eino tool message
	// cannot carry it (convert.go's ExtraIsError rides on the schema message).
	OnResult func(callID, name, text string, isErr bool, extras []llm.Message)

	// OnCallStart observes call INITIATION, synchronously at the top of the
	// gate endpoint — before the permission pipeline, hooks and execution. The
	// kernel cut wires it to the host's intercept audit trace (Trace.Start):
	// in norma the tool_use event was yielded before execOne, so the guard's
	// WithCall claim found the traced call; in eino the tools node races the
	// event pump, so the bind must happen here to stay deterministic. input is
	// the ArgsFromEino-decoded payload (the same bytes the hooks receive, so
	// WithCall's key digest matches). nil = observe nothing.
	OnCallStart func(callID, name string, input json.RawMessage)

	// hitl 是 hitl_mode=eino 的 gate 半边（SetHitl）：开启后 execOne 的步骤 3
	// 会向 hooks 链注入 db.AskSignal，PreToolUse 返回后读到审批挂起即以
	// StatefulInterrupt 中断本次调用（checkpoint 由内核 Runner 落盘）；同时
	// 恢复重入路径（GetInterruptState/GetResumeContext）生效。false = channel
	// 语义照旧。装配点与 askernel.Options.CheckpointStore 同源（内核 armed ⇔
	// gate armed），由 Session 装配处统一传导。
	hitl bool
}

// NewToolGate builds a gate over tools. maxConcurrency ≤ 0 defaults to 10
// (norma harness Query default). Permission mode defaults to bypass — 4zreco
// builds every agent with permission.ModeBypass (agent/worker.go, planner.go,
// chat.go); override via SetPermissionMode.
func NewToolGate(tools []actool.CoreTool, tpl ToolTemplate, maxConcurrency int) *ToolGate {
	byName := make(map[string]actool.CoreTool, len(tools))
	for _, t := range tools {
		byName[t.Name()] = t
	}
	return &ToolGate{
		tools: byName,
		list:  append([]actool.CoreTool(nil), tools...),
		tpl:   tpl,
		mode:  acperm.ModeBypass,
		sched: newToolScheduler(maxConcurrency),
	}
}

// SetPermissionMode overrides the pipeline mode (norma Options.PermissionMode).
func (g *ToolGate) SetPermissionMode(m acperm.Mode) *ToolGate { g.mode = m; return g }

// SetAllowRules sets the allow list (norma QueryInput.Allowed): bare names,
// "*", or "Name(...)"-style rules auto-allowed at the pipeline's rule stage.
func (g *ToolGate) SetAllowRules(rules []string) *ToolGate { g.allowed = rules; return g }

// SetDenyRules sets the deny list (norma QueryInput.Disallowed): stage-1
// absolute denials.
func (g *ToolGate) SetDenyRules(rules []string) *ToolGate { g.disallowed = rules; return g }

// SetAsk sets the interactive approval callback (norma QueryInput.CanUseTool),
// consulted only when the pipeline reaches the ask stage. Leave nil in the
// kernel cut — the guard/intercept chain turns asks into tool interrupts.
func (g *ToolGate) SetAsk(ask acperm.CanUseTool) *ToolGate { g.ask = ask; return g }

// SetHooks installs the PreToolUse/PostToolUse seam: the guard chain
// (egress→tarpit→规则→judge, ask 走 HandleAsk channel), the engine's steer
// wrapper, toollog and the attribution classifier all ride it — pass the same
// composed runner the norma path built (agent 包的 wrapToolLog/steerHooks 链)。
// nil = no hooks.
func (g *ToolGate) SetHooks(hooks ToolHooks) *ToolGate { g.hooks = hooks; return g }

// SetDeferred arms the V5 execution-time hard gate: names in deferred whose
// unlock set does not contain them error out at execOne step 0 ("load the
// skill that provides it first", 4zrec wording). The schema-withholding half
// lives in deferredMiddleware (middleware.go). unlock may be nil (everything
// in deferred stays locked).
func (g *ToolGate) SetDeferred(deferred []string, unlock *actool.UnlockSet) *ToolGate {
	set := make(map[string]bool, len(deferred))
	for _, n := range deferred {
		set[n] = true
	}
	g.deferred = set
	g.unlock = unlock
	return g
}

// SetHitl arms the eino-mode ask path（P2-2）：guard 的 ask 经 ctx 信号升级为
// tool.StatefulInterrupt（checkpoint 落盘、决定后精确续跑），恢复重入在本端点
// 顶部接住。与 askernel.Options.CheckpointStore 同源装配。
func (g *ToolGate) SetHitl(on bool) *ToolGate { g.hitl = on; return g }

// Managed returns the managed tools in registration order — the exact list
// that fed NewToolGate (and ToEinoTools for binding). The gate keeps the slice
// so the order cannot drift (toolset_snapshot_hash stability, 方案 §4-P1 第 8 条).
func (g *ToolGate) Managed() []actool.CoreTool {
	return append([]actool.CoreTool(nil), g.list...)
}

// Tool looks up one managed tool.
func (g *ToolGate) Tool(name string) (actool.CoreTool, bool) {
	t, ok := g.tools[name]
	return t, ok
}

// WrapInvokableToolCall implements adk.ChatModelAgentMiddleware. Managed tools
// are replaced by the gate endpoint; anything else passes through untouched.
//
// Like 4zrec's gateMiddleware, the returned endpoint NEVER returns a non-nil Go
// error on tool failures — EXCEPT the HITL interrupt (StatefulInterrupt 原样上
// 抛，ADK 提升为 CompositeInterrupt 事件并由 Runner 落 checkpoint；4zrec
// askernel/middleware.go 同款例外)。
func (g *ToolGate) WrapInvokableToolCall(ctx context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	t, ok := g.tools[tCtx.Name]
	if !ok {
		return endpoint, nil // not kernel-managed; pass through untouched
	}
	return func(ctx context.Context, args string, _ ...tool.Option) (string, error) {
		input := ArgsFromEino(args)
		if g.OnCallStart != nil {
			g.OnCallStart(tCtx.CallID, t.Name(), input)
		}
		// P2-3 恢复重入：本调用此前被审批中断，框架带着 checkpoint 重放本端点。
		// 命中的调用把决定交 guard 核对（db.WithHitlResume → guard 顶部）；未命中
		// （同轮兄弟中断按官方语义——Targets 只投递命中的 interrupt id）以原状态
		// 重新 interrupt 保状态。
		if g.hitl {
			if was, _, stored := tool.GetInterruptState[*hitlState](ctx); was {
				isTarget, hasData, data := tool.GetResumeContext[*db.HitlResumeData](ctx)
				if !isTarget || !hasData || data == nil {
					return "", tool.StatefulInterrupt(ctx, stored.Info, stored)
				}
				ctx = db.WithHitlResume(ctx, data)
			}
		}
		text, isErr, extras, intErr := g.execOne(ctx, t, tCtx.CallID, input)
		if intErr != nil {
			// 审批中断：工具未执行、无结果可记——结果在恢复后落 DTO。
			return "", intErr
		}
		if g.OnResult != nil {
			g.OnResult(tCtx.CallID, t.Name(), text, isErr, extras)
		}
		return text, nil
	}, nil
}

// execOne resolves and runs a single tool call — norma harness execOne
// ordering, verbatim. It never panics; failures become error results.
// input is pre-decoded (ArgsFromEino, done by the endpoint so OnCallStart and
// the hooks see the same bytes). intErr 非 nil 表示 HITL 审批中断
// （StatefulInterrupt 错误，端点原样上抛，其余失败仍是 error tool_result）。
func (g *ToolGate) execOne(ctx context.Context, t actool.CoreTool, callID string, input json.RawMessage) (text string, isErr bool, extras []llm.Message, intErr error) {
	fail := func(msg string) (string, bool, []llm.Message, error) { return msg, true, nil, nil }

	// 0. Deferred hard gate (V5 双保险): a locked deferred tool is not callable
	//    directly — the model must go through ExecuteExtraTool after its skill
	//    loaded (the access tool runs the same check internally). The schema
	//    filter in deferredMiddleware keeps the name out of the tool list; this
	//    gate closes the hallucinated-direct-call hole.
	if g.deferred[t.Name()] && g.unlock != nil && !g.unlock.Has(t.Name()) {
		return fail("Error: tool " + t.Name() + " is not unlocked in this session — load the skill that provides it first.")
	}

	// 1. Schema validation (FR-04.5). The eino ToolsNode parses JSON but does
	//    not schema-validate; a tool may opt out (Spec.RawInput).
	if r, ok := t.(rawInputTool); !ok || !r.AcceptsRawInput() {
		if err := actool.ValidateInput(t.InputSchema(), input); err != nil {
			return fail("Error: invalid tool input: " + err.Error())
		}
	}

	// 2. Permission pipeline (bypass passes through; an "ask" verdict with no
	//    interactive callback denies — norma semantics; 4zreco runs bypass).
	//    Full norma parity: rule lists ride the Context, the ask callback the
	//    Request (norma harness/tools.go:52-70).
	pc := acperm.Context{
		Mode:       g.mode,
		WorkingDir: g.tpl.WorkingDir,
		Allowed:    g.allowed,
		Disallowed: g.disallowed,
	}
	dec := acperm.Evaluate(ctx, acperm.Request{
		ToolName:     t.Name(),
		Input:        input,
		IsReadOnly:   t.IsReadOnly(input),
		ToolDecision: t.CheckPermissions(ctx, input, pc),
		Ctx:          pc,
		Ask:          g.ask,
	})
	if dec.Behavior != acperm.Allow {
		msg := dec.Message
		if msg == "" {
			msg = "denied"
		}
		return fail("Tool call was not permitted: " + msg)
	}
	if len(dec.UpdatedInput) > 0 {
		input = dec.UpdatedInput
	}

	// 3. PreToolUse hooks — the guard chain blocking point (norma
	//    harness/tools.go:78): egress→tarpit→规则→judge via the guard's hook
	//    registry, steer drain and 空转拦截 via the engine's wrapper — whatever
	//    composed chain the host passed to SetHooks. First block halts; the
	//    message becomes the tool error result.
	//    P2-2：hitl 模式先注入 AskSignal 持有者再调链——guard 的 ask 分支只落库
	//    （PersistAsk）并把挂起写进信号，返回后读到即以 StatefulInterrupt 中断
	//    本次调用（checkpoint 落盘，决定后精确续跑）。channel 模式不注入，guard
	//    走 HandleAsk 原语义（分钟级阻塞照旧）。信号走 ctx 是唯一不破坏旁路包装
	//    链（toollog/idlestop/steer 都原样转发 ctx）的通道。
	if g.hooks != nil {
		if g.hitl {
			ctx = db.WithAskSignal(ctx)
		}
		if block, msg, updated := g.hooks.PreToolUse(ctx, t.Name(), input); block {
			return fail("Blocked by hook: " + msg)
		} else if len(updated) > 0 {
			input = updated
		}
		if g.hitl {
			if ask := db.AskInterruptFrom(ctx); ask != nil {
				return "", false, nil, interruptFromSignal(ctx, ask)
			}
		}
	}

	// 4. Execute under the concurrency discipline: safe tools run alongside
	//    each other, a non-safe tool requires exclusive access (norma FIFO +
	//    exclusivity), bounded by MaxConcurrency.
	//
	//    墙钟语义（刀④勿漏）：norma 的 loop.toolCtx（harness/query.go）把 run 的
	//    MaxDuration 只压在工具执行上——超预算的工具被 mid-flight 打断进收尾，
	//    模型流不被切。本刀在裸 ctx 上执行：deadline 由刀④ 的 runCtx 装配
	//    经 Runner 传入（4zrec Session.Prompt 同款：WithTimeout(MaxDuration) 后
	//    交给 runner，模型与工具同受墙钟——4zrec 已接受的取舍）。若刀④要还原
	//    norma 的「仅工具受墙钟」，在这里从 ctx 派生工具专用 ctx 换给 Call。
	tc := g.tpl.toolContext(callID)
	ctx = WithToolContext(ctx, tc)
	safe := t.IsConcurrencySafe(input)
	g.sched.acquire(safe)
	res, callErr := safeToolCall(ctx, t, input, tc)
	g.sched.release(safe)
	if callErr != nil {
		res = actool.Errorf("Error: " + callErr.Error())
	}

	// 5. Global output cap at the single post-tool choke point (idempotent —
	//    tools that captured themselves are left alone; CaptureOnce marker,
	//    norma harness/tools.go:106), then flatten to the model-facing
	//    plain-string tool_result. The model view joins blocks with "\n" and
	//    normalizes empty results to "(no output)" — the bridging shape the
	//    刀② conversion layer froze (eino carries one string where norma ships
	//    separate content blocks); the HOOK payload below does NOT use it.
	text = FlattenToolResult(tc, res)

	// 6. PostToolUse audit / 归因尾钩 (norma harness/tools.go:110-115, verbatim
	//    payload rules — 评审第 1 轮 #1)：在 "(no output)" 归一之前、cap 之后
	//    触发，payload = json.Marshal(res.Flatten())，即 cap 后结果按 norma
	//    Result.Flatten 本体扁平化（多文本块无分隔符直拼、空结果为 ""）。
	//    guard.postToolUse 归因分类器、toollog、注入台账等经同一 ToolHooks
	//    seam 的 PostToolUse 半边。
	if g.hooks != nil {
		raw, _ := json.Marshal(res.Flatten())
		g.hooks.PostToolUse(ctx, t.Name(), input, raw, res.IsError)
	}

	return text, res.IsError, res.Extra, nil
}

// safeToolCall invokes the tool with guardPanic semantics: a panicking tool
// becomes an error, never a crashed run (4zrec askernel parity).
func safeToolCall(ctx context.Context, t actool.CoreTool, input json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = actool.Result{}
			err = fmt.Errorf("tool %s panicked: %v", t.Name(), r)
		}
	}()
	return t.Call(ctx, input, tc)
}
