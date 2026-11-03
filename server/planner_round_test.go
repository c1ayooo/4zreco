package server

import (
	"context"
	"testing"
	"time"
)

// 规划轮卡住时，planner 循环必须继续响应。
//
// 回归背景（2026-10-21 线上事故）：planner 哑火 1 小时 5 分钟——服务照常
// 运行、任务状态仍是 running、没有任何 planner 日志。goroutine dump 显示它
// 卡在 agent/compaction.go 的自死锁上（tryStart 持有 c.mu 又调了会加锁的
// cooldownFor）。
//
// 关键：**死锁的 goroutine 永远不返回，ctx 取消对它无效**。所以「给规划轮
// 加墙钟上限」这种靠 ctx 的兜底对死锁毫无作用——Plan 直接调用会永远卡住
// runRound，后续所有唤醒（边沿 + 心跳）都堵在它后面。
//
// 修法：Plan 跑在独立 goroutine 上，主侧 select 等 ctx；ctx 到了就**放弃
// 这一轮**、让 planner 循环继续（那个卡住的 goroutine 泄漏，但 planner 不再
// 失声）。
func TestRunPlannerRoundAbandonsStuckPlan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	out := runPlannerRound(ctx, func(context.Context) (bool, string, error) {
		// 模拟死锁：既不返回，也不响应 ctx。
		<-release
		return true, "should never be seen", nil
	})
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("runPlannerRound waited %v for a stuck plan — it must give up when ctx ends", elapsed)
	}
	if out.err == nil {
		t.Fatal("an abandoned round must report an error")
	}
	if out.met {
		t.Error("an abandoned round must not claim the goal was met")
	}
}

// 正常返回的规划轮必须原样透出结果，不能被超时逻辑吞掉。
func TestRunPlannerRoundPassesThroughResult(t *testing.T) {
	out := runPlannerRound(context.Background(), func(context.Context) (bool, string, error) {
		return true, "goal reached", nil
	})
	if !out.met {
		t.Error("met must be preserved")
	}
	if out.reason != "goal reached" {
		t.Errorf("reason = %q, want %q", out.reason, "goal reached")
	}
	if out.err != nil {
		t.Errorf("err = %v, want nil", out.err)
	}
}

// 规划轮出错时错误必须原样透出（不能变成超时）。
func TestRunPlannerRoundPassesThroughError(t *testing.T) {
	want := context.Canceled
	out := runPlannerRound(context.Background(), func(context.Context) (bool, string, error) {
		return false, "", want
	})
	if out.err != want {
		t.Errorf("err = %v, want %v", out.err, want)
	}
	if out.met {
		t.Error("met must be false on error")
	}
}

// 墙钟上限必须可注入，否则「卡住也不拖死循环」这件事没法在测试里验证
// （生产值是 15 分钟）。
func TestPlannerRoundLimitOverride(t *testing.T) {
	if plannerRoundLimit() != plannerRoundTimeout {
		t.Errorf("default limit = %v, want %v", plannerRoundLimit(), plannerRoundTimeout)
	}
	old := plannerRoundTimeoutOverride
	plannerRoundTimeoutOverride = 3 * time.Second
	t.Cleanup(func() { plannerRoundTimeoutOverride = old })
	if plannerRoundLimit() != 3*time.Second {
		t.Errorf("overridden limit = %v, want 3s", plannerRoundLimit())
	}
}
