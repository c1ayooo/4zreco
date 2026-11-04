package server

import (
	"testing"
	"time"
)

// 任务级超时的收尾窗口必须够**每个** worker 跑完它的 settlement。
//
// 回归背景（2026-10-21 线上实测）：任务 3 的 12 个 worker 在 13:42:23 任务
// 超时到点时同时在跑，13:43:53（90 秒后）drain 超时被硬 cancel——每个 worker
// 只来得及写回 1~3 条事实，正在写的成果直接丢了。
//
// worker 是**并行**收尾的，所以窗口不需要乘 worker 数；但每个 worker 的
// settlement 至少要 1 轮 LLM（写回成果 + 收尾总结），而思考型模型
// （minimax-m3.1）一轮就要 30~60 秒——90 秒只够「1 轮 LLM + 一点余量」，
// 稍微慢一点就被砍。
//
// 300 秒按「2 轮 LLM（写回 + 总结）+ 余量」给，够 12 个 worker 并行写回。
func TestSettleDrainGraceCoversOneSettlementRound(t *testing.T) {
	// 一轮 settlement 的最坏耗时：写回成果 1 轮 + 收尾总结 1 轮，每轮 60 秒。
	const perSettlement = 120 * time.Second
	if settleDrainGrace < perSettlement {
		t.Errorf("settleDrainGrace = %v，至少要能跑完一轮完整 settlement（%v）",
			settleDrainGrace, perSettlement)
	}
	// 反过来也不能太长：drain 窗口是任务收尾的总时长上限，太长会让用户
	// 干等（任务已到点、状态却迟迟不变）。10 分钟是上限。
	const maxGrace = 10 * time.Minute
	if settleDrainGrace > maxGrace {
		t.Errorf("settleDrainGrace = %v 过长，任务收尾不该等这么久（上限 %v）",
			settleDrainGrace, maxGrace)
	}
}
