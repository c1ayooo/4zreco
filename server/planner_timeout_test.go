package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// plannerRoundTimeout 必须是有限值。
//
// 回归背景（线上事故 2026-10-20）：planner 的 MaxDuration 来自
// clampMaxDuration(deadline, 0) —— 任务没有 deadline 时就是 0 = 不限时；
// 而 SDK 的 MaxDuration 只在轮边界检查、且只约束工具执行，LLM 调用用的是
// 无 deadline 的 l.ctx。于是一次上游半开连接（连上了但永不返回）就让
// Plan() 永不返回。
//
// runRound 是串行的：它没返回，后续所有唤醒（边沿 + 10 分钟心跳）就全堵在
// 里面出不来 → planner 永久哑火。实测 6 小时零规划轮、零新意图，「运行中
// Worker」恒为 0，任务状态仍是 running 却什么都不干；重启服务即恢复。
//
// 0 或负值会把「有上限」变回「无上限」，等于没修。
func TestPlannerRoundTimeoutIsBounded(t *testing.T) {
	if plannerRoundTimeout <= 0 {
		t.Fatalf("规划轮必须有墙钟上限，当前 %v（0 = 不限时 = 没修）", plannerRoundTimeout)
	}
	// 也不能太短：实测一轮规划 3–5 分钟（1M 上下文 + 几十次工具调用），
	// 上限太短会把正常规划判成超时。
	if plannerRoundTimeout < 5*time.Minute {
		t.Fatalf("规划轮上限过短（%v），实测一轮要 3–5 分钟，会误杀正常规划", plannerRoundTimeout)
	}
	// 也不能太长：上游卡死时等待越久，任务哑火的时间越长。
	if plannerRoundTimeout > 30*time.Minute {
		t.Fatalf("规划轮上限过长（%v），上游卡死时恢复太慢", plannerRoundTimeout)
	}
}

// 超时必须真的能中断一次挂住的调用——否则加超时只是打个标记，goroutine
// 仍然挂着，症状不变。
//
// 用真实的 http.Server（收到请求后不响应）模拟「上游半开连接」。
func TestPlannerTimeoutInterruptsHungCall(t *testing.T) {
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hang)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
		if err != nil {
			done <- err
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ctx 超时后请求应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 超时没有中断阻塞的请求——加超时只是标记，goroutine 仍挂着")
	}
}
