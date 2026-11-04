package agent

import (
	"testing"
	"time"
)

// 连续失败的压缩必须退避,否则会变成「每分钟烧一次 5 分钟」的无谓循环。
//
// 背景：一次失败的压缩要烧掉几百秒的 LLM 时间（实测思考型模型在长输入上
// 思考 300 秒以上才放弃），而基础冷却只有 60 秒。压缩失败不阻塞主流程
// （没有 digest 时 planner 直接看原始节点），所以退避只是省资源。
func TestCompactionBackoffOnRepeatedFailure(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	base := c.cooldown

	if got := c.cooldownFor(1); got != base {
		t.Fatalf("初始冷却应为 %v,得到 %v", base, got)
	}

	// 连续失败：冷却指数增长
	want := []time.Duration{base * 2, base * 4, base * 8}
	for i, w := range want {
		c.recordResult(1, false)
		if got := c.cooldownFor(1); got != w {
			t.Errorf("第 %d 次失败后冷却应为 %v,得到 %v", i+1, w, got)
		}
	}

	// 成功一次即清零
	c.recordResult(1, true)
	if got := c.cooldownFor(1); got != base {
		t.Errorf("成功后冷却应回到 %v,得到 %v", base, got)
	}
}

// 退避有上限(30 分钟),不无限增长。
func TestCompactionBackoffIsCapped(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	for i := 0; i < 20; i++ {
		c.recordResult(7, false)
	}
	if got := c.cooldownFor(7); got > 30*time.Minute {
		t.Errorf("退避应封顶 30 分钟,得到 %v", got)
	}
}

// 不同探索之间互不影响。
func TestCompactionBackoffIsPerExploration(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	base := c.cooldown
	c.recordResult(1, false)
	c.recordResult(1, false)
	if got := c.cooldownFor(2); got != base {
		t.Errorf("探索 2 的冷却不应受探索 1 影响,得到 %v", got)
	}
}
