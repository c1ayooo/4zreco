package vulnintel

import (
	"context"
	"testing"
	"time"
)

// NVD 限速闸门：主同步与快通道共享同一份额度。
//
// 背景（2026-10-22 实测）：NVD 匿名访问限速约 5 次/30s，而限速是**按出口
// IP 计**的——主同步与快通道是两条独立链路（不同查询维度、不同游标、不同
// goroutine），但打的是同一个 NVD，各自按自己的节奏算页间隔，加起来就超了。
// 实测首次实跑快通道：第 0 页就 "nvd rate limited"，一页都没拉下来。
//
// 闸门是进程级单例，两条链路自动互相让路。

// 令牌桶必须按固定间隔放行。
func TestRateLimiterSpacesRequests(t *testing.T) {
	l := &rateLimiter{interval: 60 * time.Millisecond}
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.allow(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	// 第 1 次立即放行，第 2、3 次各等一个间隔 → 至少 2 个间隔。
	if elapsed < 110*time.Millisecond {
		t.Errorf("三次请求只用了 %v，间隔未生效（应至少 ~120ms）", elapsed)
	}
}

// 闸门必须能被 ctx 取消——同步超时后不能还卡在等令牌上。
func TestRateLimiterRespectsContextCancel(t *testing.T) {
	l := &rateLimiter{interval: 10 * time.Second}
	// 先消耗一次，让下一次需要等 10 秒。
	_ = l.allow(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if err := l.allow(ctx); err == nil {
		t.Error("ctx 超时时 allow 应返回错误")
	}
	if elapsed := time.Since(t0); elapsed > 2*time.Second {
		t.Errorf("ctx 取消后仍等了 %v，应立即返回", elapsed)
	}
}

// 同一个客户端的两次请求之间必须有间隔（否则限速形同虚设）。
func TestNvdClientFetchRespectsRateLimit(t *testing.T) {
	// 用一个很短的间隔做验证：闸门是进程级单例，速率在首次使用时固定，
	// 所以这里不能改速率——只能验证「确实排了队」。
	// 直接测闸门本身：连续两次 fetch 之间应至少间隔一个 interval。
	l := nvdLimiter("")
	if l == nil {
		t.Fatal("限速闸门未初始化")
	}
	interval := l.interval
	if interval <= 0 {
		t.Fatalf("闸门间隔=%v，应为正数", interval)
	}
	// 无 key 时必须按匿名限速（5 次/30s）来，不能是 0 或 1ms。
	if interval < time.Second {
		t.Errorf("匿名访问的限速间隔=%v，应按 5 次/30s 推导（~6.5s）", interval)
	}
}

// 有 API key 时限速要放宽（50 次/30s）。
func TestPageDelayForKeyAndAnonymous(t *testing.T) {
	anon := PageDelayFor("")
	withKey := PageDelayFor("some-key")
	if anon <= withKey {
		t.Errorf("匿名间隔(%v)应大于带 key 的间隔(%v)", anon, withKey)
	}
	// 实测值：匿名 6.5s、带 key 0.7s。
	if anon != 6500*time.Millisecond {
		t.Errorf("匿名间隔=%v，应为 6.5s（5 次/30s）", anon)
	}
	if withKey != 700*time.Millisecond {
		t.Errorf("带 key 间隔=%v，应为 0.7s（50 次/30s）", withKey)
	}
	// 空白 key 等同匿名。
	if PageDelayFor("   ") != anon {
		t.Error("空白 key 应按匿名限速处理")
	}
}

// 中途换 API key 必须重建限速间隔：先匿名跑过的进程，在 UI 配置 key 后
// 应立即按带 key 的速率同步，而不是等重启。回归背景见
// docs/项目评估报告-2026-10-29.md P2（原 sync.Once 实现注释与行为不符）。
func TestNvdLimiterRebuildsOnKeyChange(t *testing.T) {
	first := nvdLimiter("")
	if first.interval != PageDelayFor("") {
		t.Fatalf("匿名闸门间隔=%v，应按匿名推导", first.interval)
	}
	second := nvdLimiter("audit-key")
	if second == first {
		t.Fatal("换 key 后应重建闸门实例")
	}
	if second.interval != PageDelayFor("audit-key") {
		t.Fatalf("带 key 闸门间隔=%v，应按 key 推导", second.interval)
	}
	// 同一个 key 再次取必须复用实例（主同步与快通道共享份额的前提）。
	if again := nvdLimiter("audit-key"); again != second {
		t.Fatal("同 key 的两次获取应返回同一实例")
	}
}
