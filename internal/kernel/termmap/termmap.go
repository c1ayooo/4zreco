// Package termmap implements the P1 terminal-reason mapping (方案 §4-P1 第 6 条,
// docs/Eino深度接入方案-2026-11-05.md): the eino ADK Runner terminates runs with
// errors and natural stops, while the engine state machine branches on the frozen
// twelve-value harness.TerminalReason enum. This package is the single place
// where one maps onto the other — 映射函数单独成包, table-driven tested, and the
// engine state machine itself stays untouched (the Reason type is an ALIAS of
// harness.TerminalReason, so kernel-produced reasons flow into agent → engine
// with zero conversion and the enum strings stay byte-identical).
//
// Each reason has exactly one source on the eino side:
//
//	ReasonCompleted          模型无 tool_call 的正常终态（无 error；内核自然结束路径直接给出）
//	ReasonMaxTurns           adk.ErrExceedMaxIterations
//	ReasonModelError         WrapModel 捕获的模型调用错误（MapError 的兜底分支）
//	ReasonAbortedStreaming   事件流中断 / ctx 取消（模型流式阶段）
//	ReasonAbortedTools       工具阶段 ctx 取消（phase 提示区分流式与工具）
//	ReasonTimeout            ctx deadline / engine 墙钟（context.DeadlineExceeded）
//	ReasonHookStopped        中间件主动终止并返回错误（ErrHookStopped 哨兵）
//	ReasonStopHookPrevented  内核不再产出——上移 engine（§3.1 路线 A），宿主直接给定
//	ReasonBlockingLimit      自建阻塞计数（ErrBlockingLimit 哨兵，中间件注入）
//	ReasonPromptTooLong      模型 413 / 超长错误分类（与 acllm.IsOverflow 同一判定，防两处分叉）
//	ReasonImageError         模型侧图片错误分类（自建保守字符串分类，norma 从未产出过该值）
//	ReasonSettlement         engine 收尾路径，不来自 ADK（宿主直接给定）
//
// The two sentinels exist so the kernel's middlewares can terminate a run with a
// classified reason WITHOUT this package importing the kernel (the kernel wraps
// its internal error with fmt.Errorf("%w", termmap.ErrHookStopped) and MapError
// unwraps it back).
//
// The engine consumes reasons via retryableWorkerModelError (ReasonModelError →
// retry) and the db.Activity payload — both keep working because the strings and
// the retryable set are unchanged.
package termmap

import (
	"context"
	"errors"
	"strings"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/cloudwego/eino/adk"

	"github.com/c1ayooo/4zreco/internal/acllm"
)

// Reason aliases the frozen enum: kernel → agent → engine pass it through with
// zero conversion, and the strings stay identical for db.Activity payloads.
type Reason = harness.TerminalReason

// Re-exports of the twelve frozen values, so callers never import norma/harness
// just to name a reason. ReasonStopHookPrevented and ReasonSettlement are
// host-produced (方案 §4-P1 第 6 条表)：内核不再产出 stop_hook_prevented（§3.1 路线 A
// 把 Stop 钩子上移 engine），settlement 一直是 engine 收尾路径。
const (
	Completed         = harness.ReasonCompleted
	MaxTurns          = harness.ReasonMaxTurns
	ModelError        = harness.ReasonModelError
	AbortedStreaming  = harness.ReasonAbortedStreaming
	AbortedTools      = harness.ReasonAbortedTools
	Timeout           = harness.ReasonTimeout
	HookStopped       = harness.ReasonHookStopped
	StopHookPrevented = harness.ReasonStopHookPrevented
	BlockingLimit     = harness.ReasonBlockingLimit
	PromptTooLong     = harness.ReasonPromptTooLong
	ImageError        = harness.ReasonImageError
	// Settlement：4zreco 引擎自有的收尾终态——norma v0.4.4 枚举只有 11 个值，
	// 第 12 个是宿主侧扩展（engine 收尾路径专用，方案表注明「不来自 ADK」）。
	Settlement = harness.TerminalReason("settlement")
	// AwaitingApproval：P2 第 13 个值（§4-P2 第 2/3 条）——工具审批中断终态。
	// Run 的 checkpoint 已由 Runner 落 Options.CheckpointStore，事件流以
	// Interrupted 收尾；宿主停靠等人工决定后显式 ResumeApproval 续跑。不来自
	// ADK 错误映射（内核在中断事件上直接给定），engine 状态机不消费它（park
	// 循环在 runKernel 内闭合）。
	AwaitingApproval = harness.TerminalReason("awaiting_approval")
)

// ErrHookStopped marks "a middleware actively terminated the run" — wrap it from
// anywhere in the kernel and MapError classifies the run error as HookStopped.
var ErrHookStopped = errors.New("termmap: middleware stopped the run")

// ErrBlockingLimit marks "the self-built blocking counter tripped" (自建阻塞计数,
// e.g. a middleware that refuses to grow the request further). Same wrapping
// convention as ErrHookStopped.
var ErrBlockingLimit = errors.New("termmap: blocking limit reached")

// Phase hints where a cancellation happened, splitting the norma
// aborted_streaming / aborted_tools pair. The eino runner runs model streaming
// and tool execution on one ctx, so the kernel's event pump tags which stage it
// was draining when the error surfaced.
type Phase int

const (
	// PhaseModel: the error surfaced while draining the model stream / waiting on
	// a model call (norma ReasonAbortedStreaming).
	PhaseModel Phase = iota
	// PhaseTools: the error surfaced while a tool call was in flight
	// (norma ReasonAbortedTools).
	PhaseTools
)

// MapError maps one runner-run error to its terminal reason. runErr must be
// non-nil (a nil run error is a natural stop — ReasonCompleted belongs to the
// kernel's natural-stop path, not to error mapping). The returned error is the
// payload for harness.Terminal.Err (already what the caller passed; kept for a
// harness-shaped signature).
func MapError(ctx context.Context, runErr error, phase Phase) (Reason, error) {
	if runErr == nil {
		// Defensive: a nil error is not an error mapping; the kernel asserts
		// natural-stop before calling. Completed keeps the enum honest here.
		return Completed, nil
	}
	if errors.Is(runErr, ErrHookStopped) {
		return HookStopped, runErr
	}
	if errors.Is(runErr, ErrBlockingLimit) {
		return BlockingLimit, runErr
	}
	if errors.Is(runErr, adk.ErrExceedMaxIterations) {
		return MaxTurns, nil
	}
	if acllm.IsOverflow(runErr) {
		return PromptTooLong, runErr
	}
	if isImageError(runErr) {
		return ImageError, runErr
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		return Timeout, nil
	}
	if errors.Is(runErr, context.Canceled) || ctx.Err() != nil {
		if phase == PhaseTools {
			return AbortedTools, runErr
		}
		return AbortedStreaming, runErr
	}
	return ModelError, runErr
}

// isImageError conservatively classifies provider errors as image-side: the
// message must mention images/multimodal AND an unsupported/invalid shape.
// norma never produced ReasonImageError (grep of v0.4.4: the constant has no
// production site), so the classification is self-built per the 方案 table and
// deliberately narrow — a false ModelError is retried harmlessly, a false
// ImageError would skip retry.
func isImageError(err error) bool {
	s := strings.ToLower(err.Error())
	media := strings.Contains(s, "image") || strings.Contains(s, "vision") ||
		strings.Contains(s, "multimodal") || strings.Contains(s, "多模态") || strings.Contains(s, "图片")
	if !media {
		return false
	}
	shape := strings.Contains(s, "not support") || strings.Contains(s, "unsupported") ||
		strings.Contains(s, "does not support") || strings.Contains(s, "invalid") ||
		strings.Contains(s, "cannot process") || strings.Contains(s, "unable to process")
	return shape
}
