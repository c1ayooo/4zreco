package acllm

// hitl.go — P2 HITL 的 gate 侧接入（docs/Eino深度接入方案-2026-11-05.md §4-P2
// 第 2/3 条）。ask 的等待段从 channel 阻塞改为 tool.StatefulInterrupt：Runner 把
// 图状态落 checkpoint（Options.CheckpointStore），事件流以 Interrupted 收尾，
// run 以 awaiting_approval 终态交还宿主；人工决定后宿主用 ResumeWithParams 从
// checkpoint 精确续跑——决定数据带 HMAC 签名，guard 在中断点核对（库行 + 签名
// + 调用绑定一致才放行，伪造 resume 不可放行）。
//
// 本文件持有唯一的 eino 序列化类型（hitlState）；guard/intercept 侧的载荷与
// 信号类型全部落在 internal/db（R4：判定逻辑不感知 eino）。

import (
	"context"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/db"
)

// hitlState 是 StatefulInterrupt 的可序列化状态：中断信息（pending_id/工具/
// 分类/输入摘要/裁决依据）。恢复重入（或同轮兄弟中断未命中重新 interrupt）时
// 从 GetInterruptState 取回，跨进程重启也成立（状态在 checkpoint 里）。
// 按方案口径不带工具入参明文——入参由 checkpoint 里的消息本体携带。
type hitlState struct {
	Info *db.HitlAskInfo
}

func (h *hitlState) String() string {
	if h == nil || h.Info == nil {
		return "waiting for approval"
	}
	return "waiting for approval: " + h.Info.Reason
}

// gob 注册（checkpoint 序列化 RunCtx 时要求接口携带类型可命名）。
// SetRunLocalValue 携带类型同走此要求——本仓库中间件现状不用 RunLocalValue，
// 这里注册的是中断链上真正进 checkpoint 的三个类型（adk handler.go 的
// gob-serializable 校验口径）。
func init() {
	schema.Register[*hitlState]()
	schema.Register[*db.HitlAskInfo]()
	schema.Register[*db.HitlResumeData]()
}

// interruptFromSignal 把 guard 经 ctx 信号交上来的审批挂起升格为
// StatefulInterrupt：state 与 info 同源（HitlAskInfo），checkpoint 里留足
// 恢复重入所需的全部信息。
func interruptFromSignal(ctx context.Context, info *db.HitlAskInfo) error {
	return tool.StatefulInterrupt(ctx, info, &hitlState{Info: info})
}
