package agent

import "testing"

// 未设置上下文窗口时必须按 1M 算，而不是 200K。
//
// 回归背景：本平台常用的 minimax-m3.1-flash-free 原生上下文是 1M（模型自报
// 1000000），而 profile 的 context_window_k 留空时代码按 200K（Claude 默认）
// 算压缩阈值。于是压缩在远未到上限时就触发——压缩本身要额外调一次 LLM
// （还要 32768 的输出预算），白白吃掉预算、拖慢流程。
//
// 阈值数学在 1M 下是安全的：effectiveWindow = 1M − 20K = 980K，buffer 50K，
// 自动压缩阈值 930K（norma 的 buffer 分档支持 >= 800000 这一档）。
func TestDefaultContextWindowIs1Million(t *testing.T) {
	if defaultWindowK != 1000 {
		t.Errorf("默认上下文窗口 %dK，应为 1000K(1M)", defaultWindowK)
	}
	c := Config{}
	got := c.CompactionWindow()
	if got != 1_000_000 {
		t.Errorf("未设置时 CompactionWindow=%d，应为 1000000", got)
	}
}

// 显式配置的值优先，且被夹在 [32K, 1M] 之间。
func TestCompactionWindowClamps(t *testing.T) {
	if got := (Config{ContextWindowK: 500}).CompactionWindow(); got != 500_000 {
		t.Errorf("显式 500K 应生效,得到 %d", got)
	}
	if got := (Config{ContextWindowK: 5}).CompactionWindow(); got != 32_000 {
		t.Errorf("低于下限应夹到 32K,得到 %d", got)
	}
	if got := (Config{ContextWindowK: 5000}).CompactionWindow(); got != 1_000_000 {
		t.Errorf("高于上限应夹到 1M,得到 %d", got)
	}
}
