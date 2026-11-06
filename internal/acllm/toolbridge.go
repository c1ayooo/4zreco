// Tool bridge (docs/Eino深度接入方案-2026-11-05.md §3.2 工具桥接层, §4-P1 第 4 条).
//
// actool.CoreTool cannot enter an eino ToolsNode as-is: the tool needs its
// eight-field actool.ToolContext, and eino only offers a JSON-string argument
// plus an adk.ToolContext{Name, CallID}. This file is the adapter between the
// two vocabularies — the tool-side sibling of convert.go's message conversion.
// 4zrec ships the same recipe already verified in production
// (internal/toolface/tools/eino.go ToEino + askernel Session.tcTpl); this file
// mirrors it onto 4zreco's vocabulary.
//
// §3.2 eight-field mapping, field by field (eino side → landing):
//
//	WorkingDir      → ToolTemplate.WorkingDir   (run 级装配参数, injected per call on ctx)
//	AgentID         → ToolTemplate.AgentID      (run 级装配参数)
//	ToolUseID       → adk.ToolContext.CallID    (gate fills per call; adapter reads ctx)
//	MaxOutputChars  → ToolTemplate.MaxOutputChars (自建 capOutput, actool.CaptureOnce)
//	OutputDir       → ToolTemplate.OutputDir    (超限落盘 + 首尾截断, same helpers)
//	Emit            → ToolTemplate.Emit         (事件流桥接: host supplies the sink)
//	Tasks           → ToolTemplate.Tasks        (*actool.Manager 照旧, 进程内)
//	Env             → ToolTemplate.Env          (Bash 工具自建, 不进内核)
//
// The execution contract is norma's, kept verbatim:
//
//   - InvokableRun NEVER returns a non-nil error and never panics outward. The
//     eino ToolsNode turns a Go error into a run-fatal failure, whereas tool
//     failures must reach the model as error tool_result text (norma execOne).
//     isError rides out-of-band — the gate (toolgate.go) knows actool.Result.IsError
//     and reports it; convert.go's ExtraIsError carries it on the schema message.
//   - capOutput runs at the single post-tool choke point and is idempotent
//     (actool.CaptureOnce): oversized output spills to OutputDir with a head +
//     absolute-path pointer, else head+tail truncation — byte-identical to the
//     norma harness because it IS norma's implementation.
//
// 4zrec reference: internal/toolface/tools/eino.go (adapter, guardPanic,
// FlattenResultEino) and internal/kernel/askernel/session.go:134 (tcTpl fields).
package acllm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// ToolTemplate is the run-level actool.ToolContext template (4zrec askernel's
// tcTpl). The host fills everything known at assembly time; per-call state
// (ToolUseID) is filled by the gate (toolgate.go) from adk.ToolContext.CallID.
// Zero value is valid: every field degrades the way the norma harness degrades
// it when the corresponding Options field is empty (cap default 30000, no
// spill dir, no progress sink).
type ToolTemplate struct {
	// WorkingDir anchors relative paths the tool resolves (norma
	// ToolContext.WorkingDir / harness Options.WorkingDir).
	WorkingDir string
	// AgentID names the running agent (norma harness Options.AgentID).
	AgentID string
	// MaxOutputChars bounds each tool's model-facing output head
	// (norma Options.MaxToolOutputChars; 0 = actool default 30000).
	MaxOutputChars int
	// OutputDir makes oversized tool output spill to a file there instead of
	// being truncated away (norma Options.ToolOutputDir; empty disables).
	OutputDir string
	// Tasks is the background-task manager shared with the tools; nil keeps
	// background execution disabled (norma Options.Tasks).
	Tasks *actool.Manager
	// Env holds extra KEY=VALUE entries injected into Bash subprocesses
	// (norma Options.BashEnv).
	Env []string
	// Emit receives progress emitted by long-running tools. It bridges into
	// the run's event stream: the host supplies a goroutine-safe sink (norma
	// harness hands each tool its own per-call emit that pings the executor —
	// here the sink is run-level, so implementors serialize as needed). May be
	// nil; norma tools treat a nil Emit the same way (tool.progress nil-checks).
	//
	// [下一刀挂点] 进度 flush 结构归刀③：norma streaming exec（streaming.go）
	// 是「每 call 独立 prog 缓冲 + ping 驱动 drain」——进度按调用归属、以事件
	// 按序 flush；桥接侧只有一个 run 级 sink，调用归属/顺序化/flush 节奏要在
	// 刀③ 的事件泵里补齐（sink 收到的进度需自带 call 归属或由宿主关联回调 goroutine）。
	Emit func(actool.ProgressInfo)
}

// toolContext materializes the per-call ToolContext: template fields plus the
// call id this execution answers.
func (tpl ToolTemplate) toolContext(toolUseID string) *actool.ToolContext {
	return &actool.ToolContext{
		WorkingDir:     tpl.WorkingDir,
		AgentID:        tpl.AgentID,
		ToolUseID:      toolUseID,
		MaxOutputChars: tpl.MaxOutputChars,
		OutputDir:      tpl.OutputDir,
		Emit:           tpl.Emit,
		Tasks:          tpl.Tasks,
		Env:            tpl.Env,
	}
}

// toolContextKey carries the ToolContext on the execution context, so a tool
// reached through eino without the gate still sees its context (4zrec
// tools.WithToolContext parity).
type toolContextKey struct{}

// WithToolContext returns a context carrying tc for tool execution.
func WithToolContext(ctx context.Context, tc *actool.ToolContext) context.Context {
	return context.WithValue(ctx, toolContextKey{}, tc)
}

// ToolContextFrom returns the ToolContext carried on ctx, or nil.
func ToolContextFrom(ctx context.Context) *actool.ToolContext {
	tc, _ := ctx.Value(toolContextKey{}).(*actool.ToolContext)
	return tc
}

// ArgsFromEino converts eino tool-call arguments (a JSON string) into the
// json.RawMessage input actool.CoreTool.Call expects. Empty arguments become
// "{}" (the norma harness normalizes the same way before validation).
func ArgsFromEino(argsJSON string) json.RawMessage {
	if strings.TrimSpace(argsJSON) == "" {
		return json.RawMessage("{}")
	}
	return json.RawMessage(argsJSON)
}

// ToEinoTool adapts one actool.CoreTool into an eino InvokableTool. This is the
// §3.2 "泛型适配器构造函数": every CoreTool goes through this single constructor,
// no per-tool code. Info merges the extended Prompt into the description exactly
// like actool.Registry.Schemas does, so the model sees identical tool definitions
// on both paths. InvokableRun validates, injects the ToolContext from ctx
// (ToolUseID is already on it when the gate sent the call), recovers panics,
// applies the idempotent output cap and flattens to the plain-string
// tool_result eino carries — always (string, nil).
//
// Scope of the bare path (4zrec toolface/tools/eino.go 头注释同款约定): this
// adapter is deliberately minimal — NO permission pipeline. A host binding
// tools through ToEinoTool without a ToolGate runs them unsandboxed at its own
// discretion; when a ToolGate is installed (kernel assembly, 刀③) it owns the
// managed tools and REPLACES this endpoint at WrapInvokableToolCall, so
// InvokableRun below never executes for gate-managed calls. isError has no
// out-of-band channel on this path (the (string, error) endpoint signature
// cannot carry it) — that is exactly why the gate path exists: the gate knows
// actool.Result.IsError and reports it via OnResult (toolgate.go), the way
// acllm.ExtraIsError later rides on the schema tool message.
func ToEinoTool(t actool.CoreTool) tool.InvokableTool {
	return &einoTool{t: t}
}

type einoTool struct {
	t actool.CoreTool
}

// Info renders the tool definition for model binding.
func (e *einoTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return ToolInfoOf(e.t)
}

// ToolInfoOf builds the eino ToolInfo for a CoreTool: name verbatim,
// description with the extended Prompt merged in (actool.Registry.Schemas
// parity), input schema via ToolSchemaToInfo.
func ToolInfoOf(t actool.CoreTool) (*schema.ToolInfo, error) {
	desc := t.Description()
	if p := t.Prompt(); p != "" {
		desc += "\n\n" + p
	}
	return ToolSchemaToInfo(llm.ToolSchema{
		Name:        t.Name(),
		Description: desc,
		InputSchema: t.InputSchema(),
	})
}

// rawInputTool is the optional opt-out from schema validation, discovered by
// assertion exactly like the norma harness (see actool.Spec.RawInput).
type rawInputTool interface{ AcceptsRawInput() bool }

// InvokableRun executes the tool. It never returns a non-nil error and never
// panics: failures and panics both become "Error: …" result text the model can
// react to.
func (e *einoTool) InvokableRun(ctx context.Context, args string, opts ...tool.Option) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("Error: tool %s panicked: %v", e.t.Name(), r)
			err = nil
		}
	}()

	input := ArgsFromEino(args)

	// Schema validation (FR-04.5), skipped for raw-input tools that parse and
	// repair their own arguments.
	if r, ok := e.t.(rawInputTool); !ok || !r.AcceptsRawInput() {
		if verr := actool.ValidateInput(e.t.InputSchema(), input); verr != nil {
			return "Error: invalid tool input: " + verr.Error(), nil
		}
	}

	tc := ToolContextFrom(ctx)
	res, callErr := e.t.Call(ctx, input, tc)
	if callErr != nil {
		res = actool.Errorf("Error: " + callErr.Error())
	}
	return FlattenToolResult(tc, res), nil
}

// capOutput runs every text block of a tool result through the idempotent
// output cap (actool.CaptureOnce — spill to OutputDir with a head + pointer,
// else head+tail truncation). Non-text blocks pass through untouched. This is
// the norma harness's capOutput verbatim in behavior because it calls norma's
// own implementation; behavior equivalence is by construction, not re-derivation.
func capOutput(tc *actool.ToolContext, res actool.Result) actool.Result {
	for i, b := range res.Content {
		if b.Type == llm.BlockText {
			res.Content[i].Text = actool.CaptureOnce(tc, b.Text)
		}
	}
	return res
}

// FlattenToolResult flattens a tool Result into the plain string an eino
// tool_result carries: every text block capped (idempotent), blocks joined with
// newlines, empty results becoming "(no output)" — norma execOne's empty-result
// normalization. Errors keep actool.Result.IsError out-of-band (the gate
// reports it; see the package doc's error convention).
func FlattenToolResult(tc *actool.ToolContext, res actool.Result) string {
	res = capOutput(tc, res)
	var b strings.Builder
	for _, block := range res.Content {
		if block.Type != llm.BlockText {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block.Text)
	}
	if b.Len() == 0 {
		return "(no output)"
	}
	return b.String()
}

// ToEinoTools adapts a whole CoreTool list (§4-P1 第 4 条 "再批量迁移": one call
// bridges a batch; per-batch tests assert name/schema fidelity). Order is
// preserved — ToolsNode binds schemas in this order.
func ToEinoTools(tools []actool.CoreTool) ([]tool.BaseTool, error) {
	out := make([]tool.BaseTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToEinoTool(t))
	}
	return out, nil
}
