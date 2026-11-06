package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/internal/sidequestion"
)

// attachSideCapture 是旁路提问快照的内核路径（刀④）：per-conversation 组装一个
// Capture，经 WithAttempt 盖到调用 ctx 上。快照的落点在 provider 侧——server 装配
// 的 provider 已被 sidequestion.Bind 包过（boundProvider 在 ctx 有 Capture 时逐调用
// 落快照，见 internal/sidequestion/capture.go 的 boundProvider），BridgeModel 桥接
// 的正是这个 bound provider，所以内核路径不需要 acllm.BindCaptureModel（那是纯
// eino 模型栈用的；本仓模型面仍是 norma provider）。无 publisher / 无归属的调用
// 纯透传（boundProvider 规则）。norma 版本（经 QueryDeps 注入，agentcore 路径）
// 已随 P4 删 norma 一并移除，仅存这份。
func attachSideCapture(ctx context.Context) context.Context {
	ri := RunInfoFrom(ctx)
	p := sidequestion.Parent{TaskID: ri.TaskID, ExplorationID: ri.ExplorationID, IntentID: ri.IntentID}
	if strings.HasPrefix(ri.SessionID, "conv-") {
		p.ConversationID, _ = strconv.ParseInt(strings.TrimPrefix(ri.SessionID, "conv-"), 10, 64)
	}
	if p.ConversationID == 0 && (p.TaskID == 0 || p.ExplorationID == 0) {
		return ctx
	}
	publish := sidequestion.PublisherFrom(ctx)
	if publish == nil {
		return ctx
	}
	c := sidequestion.NewCapture(p, 0, publish)
	return sidequestion.WithAttempt(ctx, c)
}
