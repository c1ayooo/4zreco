package agent

import (
	"testing"
	"time"
)

// Compactor.tryStart 自死锁。
//
// 回归背景（2026-10-21 线上事故）：planner 在第 23 轮规划后**永久哑火**——
// 没有新意图、没有 planner 日志、服务照常运行。goroutine dump（SIGQUIT）给出的
// 栈是：
//
//	Planner.Plan (planner.go:370)
//	  → Compactor.OnPlannerRound (compaction.go:179)
//	    → Compactor.tryStart (compaction.go:435)
//	      → Compactor.cooldownFor (compaction.go:444)
//	        → sync.Mutex.Lock   ← 永久阻塞
//
// tryStart 已经持有 c.mu，却调用了会再加一次锁的 cooldownFor。sync.Mutex 不可
// 重入 → 自死锁。
//
// 为什么长期没暴露：这条分支要求 c.lastRun[expID] 已存在，而 lastRun 只在
// 压缩 goroutine 结束（finish）时写入。所以某次探索的**第一次**压缩没事，压缩
// 跑完之后的**下一轮规划**必死。
//
// 为什么 ctx 超时救不了：死锁的 goroutine 永远不会返回，ctx 取消对它无效。
// v0.3.61 给规划轮加的墙钟上限因此形同虚设——症状（任务静默）一样，但根因
// 完全不是上游不响应。重启服务能恢复，所以先前一直误判为上游/网络问题。
func TestCompactorTryStartDoesNotSelfDeadlock(t *testing.T) {
	c := &Compactor{
		cooldown: 60 * time.Second,
		running:   map[int64]bool{},
		lastRun:   map[int64]time.Time{},
		consecFails: map[int64]int{},
	}
	const expID = int64(7)

	// 第一次：没有 lastRun，走不到冷却分支，应当成功占用。
	if !c.tryStart(expID) {
		t.Fatal("first tryStart must succeed")
	}
	c.finish(expID) // 模拟压缩 goroutine 结束：写入 lastRun

	// 第二次：lastRun 已存在且在冷却窗口内 → 必须返回 false 而不是死锁。
	// 用 goroutine + 超时来断言「没有死锁」——死锁时这个测试会超时而不是失败，
	// 所以用 select 给出明确信息。
	done := make(chan bool, 1)
	go func() { done <- c.tryStart(expID) }()
	select {
	case got := <-done:
		if got {
			t.Error("tryStart must respect the cooldown and return false")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tryStart deadlocked: it called a lock-taking method while holding c.mu")
	}

	// 冷却窗口过后应能再次占用（冷却时长按 consecFails 退避，这里无失败记录）。
	c.lastRun[expID] = time.Now().Add(-2 * c.cooldown)
	done2 := make(chan bool, 1)
	go func() { done2 <- c.tryStart(expID) }()
	select {
	case got := <-done2:
		if !got {
			t.Error("tryStart must succeed after the cooldown expired")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tryStart deadlocked on the cooldown path")
	}
}

// 连续失败会让冷却指数退避（封顶 30 分钟），且**不得**引入第二次加锁。
func TestCompactorCooldownBackoff(t *testing.T) {
	c := &Compactor{
		cooldown:    60 * time.Second,
		running:     map[int64]bool{},
		lastRun:     map[int64]time.Time{},
		consecFails: map[int64]int{},
	}
	const expID = int64(1)
	// 直接测 Locked 版（唯一的加锁入口）。
	c.consecFails[expID] = 0
	if got := c.cooldownForLocked(expID); got != 60*time.Second {
		t.Errorf("no failures → cooldown = %v, want 60s", got)
	}
	c.consecFails[expID] = 1
	if got := c.cooldownForLocked(expID); got != 120*time.Second {
		t.Errorf("1 failure → cooldown = %v, want 120s", got)
	}
	c.consecFails[expID] = 10
	if got := c.cooldownForLocked(expID); got != 30*time.Minute {
		t.Errorf("many failures → cooldown = %v, want 30m (capped)", got)
	}
}
