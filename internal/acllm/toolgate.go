// The tool gate: the eino-side execution surface for bridged tools
// (docs/Eino深度接入方案-2026-11-05.md §3.2 模板注入 + §3.3 并发分流 + §4-P1 第 4 条).
//
// ToolGate is a ChatModelAgentMiddleware whose WrapInvokableToolCall wraps every
// kernel-managed tool call with norma execOne's ordering, up to the hooks that
// belong to the middleware-assembly cut (guard chain / HITL / steer → tool
// interrupt, PostToolUse audit — those land in the next cut and slot in at the
// marked points without re-ordering anything here):
//
//  1. schema validation (unless the tool opts out via RawInput)
//  2. permission pipeline — full norma parity (mode / rule lists / ask
//     callback); 4zreco agents run bypass today
//  3. [下一刀挂点] PreToolUse hooks / guard 链 / steer — ask → tool.StatefulInterrupt
//  4. ToolContext 注入（ToolUseID = adk.ToolContext.CallID）+ 并发分流
//     (IsConcurrencySafe → toolsched) + panic-safe call
//     [下一刀挂点] 墙钟：norma 的「仅工具受 MaxDuration」语义在工具 ctx 上落地
//     （见步骤 4 注释）；本刀沿用 Runner ctx 携带的 deadline（4zrec 取舍）
//  5. capOutput（幂等，唯一收口）
//  6. [下一刀挂点] PostToolUse 审计 / toollog
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

	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

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

	// Permission policy inputs (norma harness QueryInput parity): allow/deny
	// rules consulted by the pipeline's rule stages, and the interactive
	// approval callback consulted at the ask stage. 4zreco agents run bypass
	// and leave all three unset today; the fields exist so a future non-bypass
	// mode keeps norma semantics instead of silently dropping them. The ask
	// callback here is policy-level only — the guard/intercept chain (下一刀)
	// owns the real ask → tool.StatefulInterrupt path.
	allowed    []string
	disallowed []string
	ask        acperm.CanUseTool

	// OnResult observes each gate-executed call, synchronously on the
	// executing goroutine. The kernel cut wires it to DTO/transcript writes
	// (result text + Result.Extra skill-guidance messages); nil = observe
	// nothing. isErr reports actool.Result.IsError — the eino tool message
	// cannot carry it (convert.go's ExtraIsError rides on the schema message).
	OnResult func(callID, name, text string, isErr bool, extras []llm.Message)
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
func (g *ToolGate) WrapInvokableToolCall(ctx context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	t, ok := g.tools[tCtx.Name]
	if !ok {
		return endpoint, nil // not kernel-managed; pass through untouched
	}
	return func(ctx context.Context, args string, _ ...tool.Option) (string, error) {
		text, isErr, extras := g.execOne(ctx, t, tCtx.CallID, args)
		if g.OnResult != nil {
			g.OnResult(tCtx.CallID, t.Name(), text, isErr, extras)
		}
		return text, nil
	}, nil
}

// execOne resolves and runs a single tool call — norma harness execOne
// ordering, up to the hooks marked for the middleware-assembly cut. It never
// panics; failures become error results.
func (g *ToolGate) execOne(ctx context.Context, t actool.CoreTool, callID, args string) (text string, isErr bool, extras []llm.Message) {
	fail := func(msg string) (string, bool, []llm.Message) { return msg, true, nil }

	input := ArgsFromEino(args)

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

	// 3. [下一刀挂点] PreToolUse hooks / guard 链 / steer。挂点在此、并发之前
	//    （norma execOne 顺序）：ask → tool.StatefulInterrupt（P2 HITL）。

	// 4. Execute under the concurrency discipline: safe tools run alongside
	//    each other, a non-safe tool requires exclusive access (norma FIFO +
	//    exclusivity), bounded by MaxConcurrency.
	//
	//    墙钟语义（刀③勿漏）：norma 的 loop.toolCtx（harness/query.go）把 run 的
	//    MaxDuration 只压在工具执行上——超预算的工具被 mid-flight 打断进收尾，
	//    模型流不被切。本刀在裸 ctx 上执行：deadline 由刀③/④ 的 runCtx 装配
	//    经 Runner 传入（4zrec Session.Prompt 同款：WithTimeout(MaxDuration) 后
	//    交给 runner，模型与工具同受墙钟——4zrec 已接受的取舍）。若刀③要还原
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

	// 5. Global output cap at the single post-tool choke point + flatten to
	//    the plain-string tool_result (idempotent — tools that captured
	//    themselves are left alone; empty results become "(no output)", norma
	//    execOne's normalization).
	text = FlattenToolResult(tc, res)

	// 6. [下一刀挂点] PostToolUse 审计 / toollog（在结果文本定形之后）。

	return text, res.IsError, res.Extra
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
