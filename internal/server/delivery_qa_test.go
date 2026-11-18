package server

import (
	"testing"
	"time"
)

// U5 交付质量巡检的纯判定面表驱动测试（上游 v0.4.57/58/63）。

// 覆盖矩阵缺口：意图文本命中即视为已覆盖；全没提到则全部点名（按声明顺序）。
func TestMissingCoverageClasses(t *testing.T) {
	all := []string{"sqli", "xss", "ssrf", "upload", "rce", "dirscan"}
	if got := missingCoverageClasses(nil); len(got) != len(all) {
		t.Fatalf("无意图文本应全部缺口，got %v", got)
	}
	// 全覆盖文本：每类的正则都命中。
	full := []string{
		"测 SQL注入 与 sqli", "验证 xss 跨站", "SSRF 回连测试", "文件上传 绕过",
		"命令执行 反序列化", "目录 爆破 ffuf",
	}
	if got := missingCoverageClasses(full); len(got) != 0 {
		t.Fatalf("全覆盖文本不应有缺口，got %v", got)
	}
	// 部分覆盖：只补缺口。
	partial := []string{"sqli 探测", "xss 验证"}
	got := missingCoverageClasses(partial)
	want := []string{"ssrf", "upload", "rce", "dirscan"}
	if len(got) != len(want) {
		t.Fatalf("部分覆盖缺口 = %v, want %v", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("缺口顺序 = %v, want %v", got, want)
		}
	}
}

// 纵深缺口判据：资产 ≥50 且高危=0 才催；49/50 边界。
func TestNeedsDepthNudge(t *testing.T) {
	cases := []struct {
		assets, high int
		want         bool
	}{
		{49, 0, false}, // 边界下
		{50, 0, true},  // 边界上
		{241, 0, true},
		{241, 1, false}, // 已有高危 → 不催
		{10, 0, false},
	}
	for _, c := range cases {
		if got := needsDepthNudge(c.assets, c.high); got != c.want {
			t.Errorf("needsDepthNudge(%d,%d)=%v want %v", c.assets, c.high, got, c.want)
		}
	}
}

// 空报告补写：退避轮次上限与 1/2/4/8h 指数退避。
func TestReportRecoverDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	// 从未唤起过（lastTS=0）→ 立即唤起。
	if due, atLimit := reportRecoverDue(0, 0, now); !due || atLimit {
		t.Fatalf("首次应唤起: due=%v atLimit=%v", due, atLimit)
	}
	// 退避间隔表：tries=0 → 1h；tries=1 → 2h；tries=2 → 4h；tries=3 → 8h。
	backoffs := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour}
	for tr, bo := range backoffs {
		last := now.Add(-bo).Add(time.Minute).Unix() // 刚过退避间隔前 1 分钟 → 跳过
		if due, _ := reportRecoverDue(tr, last, now); due {
			t.Errorf("tries=%d 退避期内不应唤起", tr)
		}
		last = now.Add(-bo - time.Minute).Unix() // 退避期已过 → 唤起
		if due, _ := reportRecoverDue(tr, last, now); !due {
			t.Errorf("tries=%d 退避期已过应唤起", tr)
		}
	}
	// 尝试上限：>=6 不再唤起；恰好第 6 次（=上限）atLimit=true（告警一次），
	// 之后 tries=7 时 atLimit=false（已告警过，不再重复）。
	if due, atLimit := reportRecoverDue(6, 0, now); due || !atLimit {
		t.Fatalf("第 6 次应 atLimit 告警: due=%v atLimit=%v", due, atLimit)
	}
	if due, atLimit := reportRecoverDue(7, 0, now); due || atLimit {
		t.Fatalf("第 7 次起应静默跳过: due=%v atLimit=%v", due, atLimit)
	}
}
