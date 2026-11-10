// adaptiverate.go — 出站 LLM 请求的自适应限速（AIMD）。
//
// 背景：中转/网关按分组限 RPM（如 inferaichat 的 "group requests-per-minute
// limit exceeded"），静态 rate_per_minute 需要人知道额度才能配。本机制不需要：
// 平时不限速，一旦某个响应以 429 拒绝，就把「相邻请求发车间距」收紧（首次 2s，
// 之后翻倍，封顶 30s；Retry-After 头作下限）；连续成功若干次后间距减半、直至
// 归零完全解除。装在 quotaAwareTransport（每个 LLM profile 一个共享实例）上，
// worker/planner/chat/llmpool 全部调用方自动共用一个调节器——上游 SDK 与
// task-llm 的重试在发车前也要过这道闸，429 重试风暴因此自然变成排队。
//
// 与 norma 静态限速（Config.RateLimit）的关系：独立两层，静态桶先扣、本机制
// 再兜底；不配静态额度时本机制单独生效。判定逻辑保持纯 Go 普通函数（骨架/
// 器官分层约束，不感知 eino）。
package agent

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// 自适应参数（包级变量仅为测试可收缩；生产勿改）。
var (
	adaptiveGapStart = 2 * time.Second  // 首个 429 后的起始发车间距
	adaptiveGapMax   = 30 * time.Second // 间距封顶：最坏情况下每 30s 才发一请求
	adaptiveOkToEase = 8                // 连续成功这么多次后间距减半一档
)

// adaptiveGovernor spaces consecutive request starts by a gap that adapts to
// the endpoint's demonstrated tolerance: 429 doubles it (AIMD 的乘性退避)，
// success streaks halve it until fully lifted (加性恢复)。零值间距 = 不限速。
// Safe for concurrent use; one governor per provider (hence per profile)。
type adaptiveGovernor struct {
	mu       sync.Mutex
	gapVal   time.Duration // 当前强制间距；0 = 不限速
	next     time.Time     // 下一个可发车时刻（票号制：并发请求各领各的槽位）
	okStreak int
	params   adaptiveParams // 构造时从包级默认快照——实例不受后续包级变量改动影响
	now      func() time.Time
}

type adaptiveParams struct {
	start time.Duration
	max   time.Duration
	ease  int
}

func currentAdaptiveParams() adaptiveParams {
	return adaptiveParams{start: adaptiveGapStart, max: adaptiveGapMax, ease: adaptiveOkToEase}
}

func newAdaptiveGovernor(now func() time.Time) *adaptiveGovernor {
	if now == nil {
		now = time.Now
	}
	return &adaptiveGovernor{now: now, params: currentAdaptiveParams()}
}

// gap returns the current enforced spacing (test observation point).
func (g *adaptiveGovernor) gap() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gapVal
}

// reserve books the caller's start slot and returns how long until it arrives
// (0 = go now). The slot math is pure w.r.t. the injected clock, so tests verify
// spacing without real sleeps; wait wraps it with the actual block.
func (g *adaptiveGovernor) reserve() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	slot := g.next
	if slot.Before(now) {
		slot = now
	}
	g.next = slot.Add(g.gapVal) // 票号制：并发请求按间距排队，互不挤占
	return slot.Sub(now)
}

// wait blocks until the caller's reserved start slot arrives. Unlimited governors
// pass through immediately; ctx cancellation aborts the wait.
func (g *adaptiveGovernor) wait(ctx context.Context) error {
	d := g.reserve()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// onRejected records a 429-style rejection: doubles the gap (from the start
// value when previously unlimited), honoring Retry-After as a floor, capped at
// adaptiveGapMax. Any rejection also resets the success streak.
func (g *adaptiveGovernor) onRejected(retryAfter time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.okStreak = 0
	next := g.gapVal * 2
	if g.gapVal <= 0 {
		next = g.params.start
	}
	if retryAfter > next {
		next = retryAfter
	}
	if next > g.params.max {
		next = g.params.max
	}
	if next != g.gapVal {
		if g.gapVal == 0 {
			log.Printf("[llm-adaptive] 收到 429，出站请求开始限速：发车间距 %v（Retry-After=%v）", next, retryAfter)
		}
		g.next = g.now().Add(next) // 间距变化立即约束下一次发车
	}
	g.gapVal = next
}

// onAccepted records a success. After adaptiveOkToEase consecutive successes the
// gap halves once; below a second it snaps to zero (fully lifted). A rejection
// in between resets the streak (见 onRejected)。
func (g *adaptiveGovernor) onAccepted() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gapVal <= 0 {
		return // 已完全解除，无可放松
	}
	g.okStreak++
	if g.okStreak < g.params.ease {
		return
	}
	g.okStreak = 0
	g.gapVal /= 2
	if g.gapVal < time.Second {
		if g.gapVal > 0 { // 本次减半触发了归零 → 完全解除
			log.Printf("[llm-adaptive] 持续成功，出站限速解除")
		}
		g.gapVal = 0
	}
}

// parseRetryAfter reads the Retry-After header in either the delay-seconds or
// the HTTP-date form; unparseable/absent/past dates yield 0.
func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
