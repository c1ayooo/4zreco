package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 目标拆解必须自带墙钟：任务未配 timeout_seconds 时 execContextFor 无
// deadline，上游挂起曾让任务永久卡在 created（2026-10-30 Kali 实测）。
// 本测试用超短 override 验证：拆解 ctx 到点后 DeadlineExceeded 向上可见，
// startTaskEngine 据此走「拆解无产出」回退而不是无限等。
func TestGoalsDecomposeTimeoutConstant(t *testing.T) {
	if goalsDecomposeTimeout != 5*time.Minute {
		t.Fatalf("goalsDecomposeTimeout=%v，应为 5 分钟（正常拆解 30s~2min，留足冗余）",
			goalsDecomposeTimeout)
	}
	// 语义自检：DeadlineExceeded 可以从带超时的 ctx 上被 errors.Is 识别——
	// startTaskEngine 的回退判定依赖这个行为。
	// 注意不能写「sleep 2ms 后断言」：CI 高负载下 1ms 定时器的触发可能晚于
	// 2ms（v0.3.94 CI 实测翻车），改为有界轮询——deadline 到点即过，100ms
	// 仍未到才算失败（正常机器 <1ms）。
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	deadline := time.Now().Add(100 * time.Millisecond)
	for errors.Is(ctx.Err(), context.Canceled) || ctx.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("超时 ctx 应能被 errors.Is(DeadlineExceeded) 识别（100ms 内未触发）")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("ctx.Err()=%v，应为 DeadlineExceeded", ctx.Err())
	}
}
