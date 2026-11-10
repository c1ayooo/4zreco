package agent

import (
	"net/http"
	"testing"
	"time"
)

// 注入时钟：不 sleep、不依赖真实墙钟，等待逻辑用假时钟推进（AGENTS.md §4 短 sleep 禁令）。
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	if d > 0 {
		c.now = c.now.Add(d)
	}
}

func newTestGovernor() (*adaptiveGovernor, *fakeClock) {
	clk := &fakeClock{now: time.Date(2026, 11, 10, 23, 0, 0, 0, time.UTC)}
	g := newAdaptiveGovernor(clk.Now)
	// 单元测试固定标准参数，与并行集成测试收缩的包级变量隔离
	g.params = adaptiveParams{start: 2 * time.Second, max: 30 * time.Second, ease: 8}
	return g, clk
}

func TestGovernorUnlimitedUntilFirst429(t *testing.T) {
	t.Parallel()
	g, clk := newTestGovernor()
	// 未见过 429：任何间隔都立即放行
	if d := g.reserve(); d != 0 {
		t.Fatalf("unlimited governor must not wait: %v", d)
	}
	// 一次 429 → 间距从 0 升到 gapStart
	g.onRejected(0)
	if g.gap() != 2*time.Second {
		t.Fatalf("first 429 must set gap to %v, got %v", 2*time.Second, g.gap())
	}
	// 下一发必须等到 gapStart 之后才放行
	clk.Advance(2*time.Second - time.Second)
	if d := g.reserve(); d != time.Second {
		t.Fatalf("want 1s remaining, got %v", d)
	}
	// 票号制：并发预约严格按间距排开（T0+2s、T0+4s……），互不挤占
	if d := g.reserve(); d != 3*time.Second {
		t.Fatalf("concurrent booking must take the next spaced slot, want 3s got %v", d)
	}
	// 时钟越过全部已预约槽位（最后一格 T0+6s）后，新调用立即可发
	clk.Advance(5 * time.Second)
	if d := g.reserve(); d != 0 {
		t.Fatalf("want immediate slot once slots elapsed, got %v", d)
	}
}

func TestGovernorDoublesGapOnConsecutive429(t *testing.T) {
	t.Parallel()
	g, _ := newTestGovernor()
	g.onRejected(0) // → gapStart
	if got := g.gap(); got != 2*time.Second {
		t.Fatalf("first: want %v got %v", 2*time.Second, got)
	}
	g.onRejected(0) // ×2
	if got := g.gap(); got != 2*2*time.Second {
		t.Fatalf("second: want %v got %v", 2*2*time.Second, got)
	}
	for i := 0; i < 10; i++ { // 连撞：封顶不无限涨
		g.onRejected(0)
	}
	if got := g.gap(); got != 30*time.Second {
		t.Fatalf("cap: want %v got %v", 30*time.Second, got)
	}
}

func TestGovernorRetryAfterFloorsGap(t *testing.T) {
	t.Parallel()
	g, _ := newTestGovernor()
	g.onRejected(10 * time.Second) // Retry-After 10s，比 gapStart 大 → 取大者
	if got := g.gap(); got != 10*time.Second {
		t.Fatalf("want Retry-After floor 10s, got %v", got)
	}
	g.onRejected(0) // 再撞一次 ×2，但仍不超过 cap；本例 20s < 30s
	if got := g.gap(); got != 20*time.Second {
		t.Fatalf("want doubled 20s, got %v", got)
	}
}

func TestGovernorEasesOnSuccessStreak(t *testing.T) {
	t.Parallel()
	g, _ := newTestGovernor()
	g.onRejected(0)          // gap = gapStart
	for i := 0; i < 8; i++ { // 连续 OK 达标 → 减半
		g.onAccepted()
	}
	if got := g.gap(); got != 2*time.Second/2 {
		t.Fatalf("after streak: want %v got %v", 2*time.Second/2, got)
	}
	for g.gap() > 0 { // 持续 OK → 一路减半直至归零（完全解除）
		prev := g.gap()
		for i := 0; i < 8; i++ {
			g.onAccepted()
		}
		if g.gap() >= prev {
			t.Fatalf("gap must shrink each streak: %v -> %v", prev, g.gap())
		}
		if g.gap() != 0 && g.gap() < time.Second {
			t.Fatalf("sub-second gap must snap to 0, got %v", g.gap())
		}
	}
	// 归零后任何 OK 都不该重新引入间距
	for i := 0; i < 8*2; i++ {
		g.onAccepted()
	}
	if g.gap() != 0 {
		t.Fatalf("fully eased governor must stay unlimited, got %v", g.gap())
	}
}

func TestGovernorFailureStallsEasing(t *testing.T) {
	t.Parallel()
	g, _ := newTestGovernor()
	g.onRejected(0)
	for i := 0; i < 8-1; i++ {
		g.onAccepted()
	}
	g.onRejected(0) // OK 连胜被 429 打断 → 间距只涨不减
	if got := g.gap(); got != 2*2*time.Second {
		t.Fatalf("want doubled %v, got %v", 2*2*time.Second, got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	if d := parseRetryAfter(h); d != 0 {
		t.Fatalf("empty header must yield 0, got %v", d)
	}
	h.Set("Retry-After", "17")
	if d := parseRetryAfter(h); d != 17*time.Second {
		t.Fatalf("seconds form: want 17s got %v", d)
	}
	h.Set("Retry-After", "Mon, 11 Nov 2026 00:00:10 GMT")
	if d := parseRetryAfter(h); d <= 0 {
		t.Fatalf("http-date form must yield positive duration, got %v", d)
	}
	h.Set("Retry-After", "garbage")
	if d := parseRetryAfter(h); d != 0 {
		t.Fatalf("unparseable must yield 0, got %v", d)
	}
}
