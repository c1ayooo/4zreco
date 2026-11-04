package vulnintel

import (
	"context"
	"sync"
	"time"
)

// NVD 限速闸门：主同步与快通道**共享**同一个额度。
//
// ## 为什么需要它
//
// NVD 的限速是**按出口 IP 计**的，不是按客户端计：匿名约 5 次/30s，有 key
// 约 50 次/30s。主同步与快通道是两条独立的链路（不同的查询维度、不同的
// 游标、不同的 goroutine），但它们打的是**同一个 NVD**——各自按自己的节奏
// 算页间隔，加起来就超了。
//
// 实测（2026-10-22，首次实跑快通道）：主同步 90s 起跑、快通道 120s 起跑，
// 只差 30 秒 → 快通道第 0 页就 "nvd rate limited"，一页都没拉下来。
//
// 错开起跑时间只能缓解、不能根治（主同步一轮 30 分钟，快通道 30 分钟一轮，
// 迟早再次撞上）。真正要解决的是「两条链路共享额度」这件事。
//
// ## 机制
//
// 一个进程级令牌桶：每 PageDelay 毫秒放行一个令牌，请求前取一个。
// 桶的速率按 API key 推导（有 key 50 次/30s、无 key 5 次/30s）。
//
// 因为两条链路共用同一个桶实例，它们自动互相让路——不需要任何协调逻辑。

// rateLimiter 是一个简单的令牌桶（按固定间隔放行）。
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// allow 阻塞直到可以放行一次请求。
func (l *rateLimiter) allow(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.IsZero() || l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// nvdLimiter 是进程级的 NVD 限速闸门。
//
// 速率按**当前生效的 API key** 推导：主同步与快通道每次请求都从各自的
// client 带来同一个 key（同一份配置），key 不变时复用同一个闸门实例——
// 两条链路自然互相让路。key 变了（如先匿名跑过、之后在 UI 配置了 key）
// 则按新 key 重建，等价于重启进程后的状态。
//
// 重建只换间隔：旧实例上还在等待的请求按旧计时器自然结束，不会被打断。
var (
	nvdLimiterMu   sync.Mutex
	nvdLimiterKey  string
	nvdLimiterInst *rateLimiter
)

// nvdLimiter returns the process-wide NVD rate limiter, rebuilding it when
// the configured API key changes.
func nvdLimiter(apiKey string) *rateLimiter {
	nvdLimiterMu.Lock()
	defer nvdLimiterMu.Unlock()
	if nvdLimiterInst == nil || nvdLimiterKey != apiKey {
		nvdLimiterKey = apiKey
		nvdLimiterInst = &rateLimiter{interval: PageDelayFor(apiKey)}
	}
	return nvdLimiterInst
}

// waitNvdSlot blocks until this request may proceed under the shared NVD
// rate limit.
//
// 这个等待发生在**每次请求之前**，所以主同步与快通道会自然地互相让路。
func (c *NvdClient) waitNvdSlot(ctx context.Context) error {
	return nvdLimiter(c.APIKey).allow(ctx)
}
