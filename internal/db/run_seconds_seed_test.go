package db

import (
	"testing"
)

// agent 的单次 run 墙钟预算的**种子默认**必须是 1200s（20 分钟）。
//
// 为什么锁死这个值（2026-10-21 修正）：
//
// 上游 4ZRECO-upstream 的种子默认就是 1200s，它靠「短 run → exhausted →
// 规划者看 trace 判进度 → 续派或换打法」形成小步快跑的闭环。
//
// 我们在 2026-10-20 把它迁到 3600s，理由是「89 个意图 exhausted vs 8 个
// done → 给太紧」。那个归因是错的：exhausted 不是失败信号，是「这一小步没
// 做完」的信号。拉长到 3600s 反而把闭环拆了——run 拖到 1 小时，撞的几乎
// 都是硬上限，规划者看到的一律是「运行超时」→ 续派同一条链 → 实测 4.1 小时
// 机时零事实产出。
//
// 另一个当时的干扰因素（上下文窗口 200K → 1M）已单独修掉。两个变量混在
// 一起归因到一个，是这次走弯路的根源。这个测试防止它第三次被改。
func TestBuiltinAgentsUseSeedRunSeconds(t *testing.T) {
	// 内置 agent 都不显式指定 run_seconds（nil → 走种子默认）。
	// pentest 是唯一的例外：它显式设 0 = 不限时（一人走完整条渗透链，
	// 不该被单次 run 的墙钟掐断）。
	for _, a := range builtinAgents {
		if a.key == "pentest" {
			if a.runSeconds == nil {
				t.Error("pentest 应显式设 run_seconds=0（不限时），实际是 nil")
			} else if *a.runSeconds != 0 {
				t.Errorf("pentest 的 run_seconds = %d, want 0", *a.runSeconds)
			}
			continue
		}
		if a.runSeconds != nil {
			t.Errorf("内置 agent %q 显式指定了 run_seconds=%d —— 应留 nil 走种子默认（1200），"+
				"否则调种子默认值时它不会跟着变", a.key, *a.runSeconds)
		}
	}
}

// 迁移方向必须是 3600→1200（把 run 拉短），不是反过来。
//
// 这条锁的是【方向】——之前那个 1200→3600 的迁移就是走弯路的根源，而它是一次
// 性迁移：跑过就没了，事后无从验证方向对错。把改写逻辑抽成 applyAgentRunSeconds
// 才能在单测里直接验证。
func TestApplyAgentRunSecondsDirection(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// key 必须匹配 CHECK (key ~ '^[a-z][a-z0-9_]*$')。
	const key = "runsec_migrate_test"
	if _, err := d.Exec(`DELETE FROM agents WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO agents(key,name,description,role,builtin,enabled,run_seconds)
VALUES ($1,'t','t','assistant',false,true,3600)`, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM agents WHERE key=$1`, key) })

	// 迁移的方向：3600 → 1200。
	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		t.Fatalf("applyAgentRunSeconds: %v", err)
	}

	var got int
	if err := d.QueryRow(`SELECT run_seconds FROM agents WHERE key=$1`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 1200 {
		t.Errorf("run_seconds = %d, want 1200（迁移方向必须是 3600→1200）", got)
	}
}

// 只改「仍是旧值」的行：用户自己调过的实例保持不变。
func TestApplyAgentRunSecondsOnlyTouchesMatchingRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	rows := []struct{ key string; secs int }{
		{"runsec_keep_a", 900},  // 用户自调 → 不动
		{"runsec_move_b", 3600}, // 旧默认值 → 改成 1200
	}
	for _, r := range rows {
		if _, err := d.Exec(`DELETE FROM agents WHERE key=$1`, r.key); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`INSERT INTO agents(key,name,description,role,builtin,enabled,run_seconds)
VALUES ($1,'t','t','assistant',false,true,$2)`, r.key, r.secs); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, r := range rows {
			d.Exec(`DELETE FROM agents WHERE key=$1`, r.key)
		}
	})

	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		t.Fatalf("applyAgentRunSeconds: %v", err)
	}

	for _, r := range rows {
		var got int
		if err := d.QueryRow(`SELECT run_seconds FROM agents WHERE key=$1`, r.key).Scan(&got); err != nil {
			t.Fatal(err)
		}
		want := r.secs
		if r.secs == 3600 {
			want = 1200
		}
		if got != want {
			t.Errorf("%s: run_seconds = %d, want %d", r.key, got, want)
		}
	}
}
