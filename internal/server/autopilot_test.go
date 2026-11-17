package server

import (
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
)

// effectiveIntentThreshold：折算规则 = max(limit, 2*workers)，0=关闭保持 0。
func TestEffectiveIntentThreshold(t *testing.T) {
	cases := []struct {
		limit, workers, want int
	}{
		{0, 3, 0},   // 0=关闭节流
		{-1, 3, 0},  // 负值同关闭
		{8, 3, 8},   // 默认 8 > 2*3
		{4, 3, 6},   // 2*workers=6 > 4 → 6
		{8, 8, 16},  // worker 多时阈值跟随 2*workers
		{200, 3, 200}, // 高阈值照常生效（PUT 已夹逼 0–200）
	}
	for _, c := range cases {
		if got := effectiveIntentThreshold(c.limit, c.workers); got != c.want {
			t.Fatalf("effectiveIntentThreshold(%d,%d)=%d want %d", c.limit, c.workers, got, c.want)
		}
	}
}

// suppressAutopilotSettle：只抑制「没进展」类判据；硬上限与 goal_met 照旧。
func TestSuppressAutopilotSettle(t *testing.T) {
	off := &Task{} // autopilot 关
	for _, reason := range []string{"auto_idle", "auto_coverage", "auto_rounds", "goal_met", "timeout", "no_result"} {
		if suppressAutopilotSettle(off, reason) {
			t.Fatalf("autopilot 关闭时 %s 不应被抑制", reason)
		}
	}
	on := &Task{}
	on.SetAutopilot(true)
	suppressed := map[string]bool{"auto_idle": true, "auto_coverage": true, "auto_rounds": true}
	for _, reason := range []string{"auto_idle", "auto_coverage", "auto_rounds", "goal_met", "timeout", "no_result"} {
		got := suppressAutopilotSettle(on, reason)
		if got != suppressed[reason] {
			t.Fatalf("autopilot 开启时 %s: got %v want %v", reason, got, suppressed[reason])
		}
	}
	if suppressAutopilotSettle(nil, "auto_idle") {
		t.Fatal("nil Task 不应被抑制")
	}
}

// autopilotConfigFromPG(nil)：默认值兜底（读库失败绝不能让看门狗停摆）。
func TestAutopilotConfigDefaults(t *testing.T) {
	c := autopilotConfigFromPG(nil)
	if c.StallMinutes != defaultAutopilotStallMinutes || c.MaxExtensions != defaultAutopilotMaxExtensions {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if autopilotExtendWavesFromPG(nil) != defaultAutopilotExtendWaves {
		t.Fatalf("extend waves default = %d", autopilotExtendWavesFromPG(nil))
	}
}

// intentQueueLimitFromPG(nil)：默认 8。
func TestIntentQueueLimitDefault(t *testing.T) {
	if got := intentQueueLimitFromPG(nil); got != defaultIntentQueueLimit {
		t.Fatalf("intentQueueLimitFromPG(nil)=%d want %d", got, defaultIntentQueueLimit)
	}
}


// NotifyAutopilotStall 用独立 trigger kind 唤醒（不复用 hint——见 Task 注释）。
func TestNotifyAutopilotStallKind(t *testing.T) {
	tk := &Task{notify: make(chan struct{}, 1)}
	tk.NotifyAutopilotStall("停滞 10 分钟")
	if len(tk.pendingTriggers) != 1 || tk.pendingTriggers[0].Kind != "autopilot_stall" {
		t.Fatalf("kind=%v", tk.pendingTriggers)
	}
	if tk.pendingTriggers[0].Detail == "" {
		t.Fatal("detail 必须保留")
	}
	// 空文本不应入队
	tk.NotifyAutopilotStall("  ")
	if len(tk.pendingTriggers) != 1 {
		t.Fatalf("空 detail 不应入队: %d", len(tk.pendingTriggers))
	}
}

// autopilot_stall 不算「新方向」：freshDirection 只认 goal/hint 族，
// 看门狗唤醒不得重置 auto_finish 的 idle 计数。
func TestAutopilotStallNotFreshDirection(t *testing.T) {
	if freshDirection([]agent.TriggerEvent{{Kind: "autopilot_stall", Detail: "x"}}) {
		t.Fatal("autopilot_stall 不得被判为新方向")
	}
	if !freshDirection([]agent.TriggerEvent{{Kind: "goal", Goals: []string{"x"}}}) {
		t.Fatal("goal 仍应判为新方向")
	}
}
