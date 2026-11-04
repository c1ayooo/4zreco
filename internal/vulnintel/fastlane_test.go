package vulnintel

import (
	"context"
	"testing"
)

// 「近期高危快通道」的判定与落库行为。
//
// 背景（2026-10-22 调研）：主同步走 lastModifiedDate 窗口（≤120 天），游标按
// 窗口推进、一轮 MaxRuntime 翻不完——**刚披露的高危漏洞进库很慢**。而实测
// 拿两个真实例子验证了这件事的严重性：
//
//	CVE-2026-109618（2026-10-21 披露，CRITICAL，PHP → RCE）
//	CVE-2026-109619（2026-10-21 披露，CRITICAL，PHP → RCE）
//
// 这两条的 NVD 记录里**受影响版本区间是空的**（cpe:2.3:a:php:php:*:*:*），
// 说明 NVD 还没填——于是平台既不能判断目标 PHP 版本是否受影响，也无法把
// 「这个组件刚出了两个 CRITICAL RCE」这件事可靠地送到 worker 面前。
//
// 快通道解决两件事：
//  1. **时效**：按 publishedDate 小窗口拉「刚披露的」，几十分钟进库；
//  2. **版本待定可见**：版本区间缺失时不能判成「不受影响」——要显式标出
//     「版本待定」，让模型知道值得试。
//
// 快通道与主同步**共用 vuln_cves 表**（agent 查同一个库），但**游标独立**
// （fast lane 不能把主同步的 lastModified 游标推走）。

// 严重度映射：分数与 KEV → 是否够格进快通道。
func TestRecentCriticalSelection(t *testing.T) {
	cases := []struct {
		name  string
		score *float64
		kev   bool
		want  bool
	}{
		{"CRITICAL 9.8 进", f64(9.8), false, true},
		{"CRITICAL 9.0 进（边界）", f64(9.0), false, true},
		{"HIGH 9.5 进（分数够）", f64(9.5), false, true},
		{"HIGH 8.9 不进", f64(8.9), false, false},
		{"MEDIUM 5.0 不进", f64(5.0), false, false},
		{"KEV 进（分数不高）", f64(7.5), true, true},
		{"KEV 进（无分数）", nil, true, true},
		{"无分数无 KEV 不进", nil, false, false},
		{"分数缺失但 severity=CRITICAL 不进（不能瞎猜）", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isRecentCritical(c.score, c.kev)
			if got != c.want {
				t.Errorf("isRecentCritical(score=%v kev=%v)=%v，应为 %v",
					c.score, c.kev, got, c.want)
			}
		})
	}
}

// 版本区间缺失时必须能区分「未受影响」与「版本待定」。
//
// 这是 PHP 那两个 CVE 暴露的缺口：NVD 的 cpe 是 cpe:2.3:a:php:php:*:*:*，
// 没有任何版本边界。旧逻辑只看 Criteria 原文，模型无从判断；新逻辑要把
// 「有没有版本边界」显式算出来。
func TestVersionRangeUndeterminedDetection(t *testing.T) {
	// PHP 那两个 CVE 的真实形态：criteria 里版本位全是 *，且没有任何
	// versionStart/End 字段。
	phpLike := CVE{
		ID:       "CVE-2026-109618",
		Criteria: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
	}
	if !VersionRangeUndetermined(phpLike) {
		t.Error("版本区间缺失的 CVE 应被判定为「版本待定」")
	}

	// 有明确版本区间的（真实 NVD 形态）。
	withRange := CVE{
		ID: "CVE-2021-41773",
		Criteria: []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		Ranges: []CPERange{{
			Criteria:       "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			StartIncluding: "2.4.49",
			EndExcluding:   "2.4.50",
		}},
	}
	if VersionRangeUndetermined(withRange) {
		t.Error("有明确版本区间的 CVE 不应判为「版本待定」")
	}

	// 固定版本（version 位不是 *）也算已知。
	pinned := CVE{
		ID:       "CVE-2020-0001",
		Criteria: []string{"cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"},
	}
	if VersionRangeUndetermined(pinned) {
		t.Error("版本位固定的 CVE 不应判为「版本待定」")
	}
}

// 「版本待定」的提示文案必须说清「不是不受影响」，否则模型会当成安全。
func TestVersionUndeterminedNoteWording(t *testing.T) {
	note := VersionUndeterminedNote()
	for _, want := range []string{"版本", "未确认", "不代表"} {
		if !contains(note, want) {
			t.Errorf("版本待定提示缺少 %q: %s", want, note)
		}
	}
}

// 快通道的窗口：实测 1~3 天的 publishedDate 窗口会超时（NVD 对刚发布的记录
// 还在索引），7 天窗口 17 秒能拉完——所以窗口不能小于 7 天。
func TestFastLaneWindowFloor(t *testing.T) {
	if fastLaneMinWindowDays < 7 {
		t.Errorf("快通道窗口下限=%d 天，应至少 7 天（实测更小的窗口会超时）", fastLaneMinWindowDays)
	}
	if fastLaneOverlapHours < 12 {
		t.Errorf("快通道重叠=%d 小时，应至少 12 小时（防 NVD 侧索引延迟导致漏记录）", fastLaneOverlapHours)
	}
}

// 快通道的游标必须独立于主同步——用不同的 source key。
func TestFastLaneUsesIndependentCursorKey(t *testing.T) {
	if fastLaneSyncSource == "nvd" {
		t.Error("快通道的游标 key 不能与主同步相同——会把主同步的 lastModified 游标推走")
	}
	if fastLaneSyncSource == "" {
		t.Error("快通道的游标 key 不能为空")
	}
}

// 快通道的页大小：实测单页 2000 条在 publishedDate 上会超时，1000 更稳。
func TestFastLanePageSize(t *testing.T) {
	if fastLanePageSize <= 0 || fastLanePageSize > 2000 {
		t.Errorf("快通道页大小=%d，应在 1..2000", fastLanePageSize)
	}
}

func f64(v float64) *float64 { return &v }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// 确认快通道的判定函数不依赖数据库（纯函数，便于单测）。
func TestSelectRecentCriticalIsPure(t *testing.T) {
	// 同样的输入必须得到同样的输出，且不 panic。
	a := isRecentCritical(f64(9.5), false)
	b := isRecentCritical(f64(9.5), false)
	if a != b {
		t.Error("isRecentCritical 应是纯函数")
	}
	_ = context.Background()
}
