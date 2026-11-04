package vulnintel

import (
	"testing"
	"time"
)

// 页级游标：NVD 同步的窗口可能大到单轮跑不完，游标只按「窗口」推进的话，
// 窗口内失败就整窗重跑——游标永远卡在同一个窗口，每轮都白跑。
//
// 实测（2026-10-21）：NVD 的 120 天窗口能到 14 万条（71 页 × 约 17 秒 +
// 限速延时），单轮 30 分钟的 MaxRuntime 跑不完；游标停在 2026-06-10，
// 最后一个窗口反复超时，40 万条的目录补到 14 万就再也补不上。
func TestPageCursorRoundTrip(t *testing.T) {
	winStart := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	raw := formatPageCursor(winStart, 10000)
	gotWin, gotIdx, ok := parsePageCursor(raw)
	if !ok {
		t.Fatalf("round trip failed: %q", raw)
	}
	if !gotWin.Equal(winStart) {
		t.Errorf("window = %v, want %v", gotWin, winStart)
	}
	if gotIdx != 10000 {
		t.Errorf("index = %d, want 10000", gotIdx)
	}
}

func TestParsePageCursorRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"no-separator",
		"not-a-time|100",
		"2026-06-09T00:00:00Z|notanumber",
		"2026-06-09T00:00:00Z|-5",
		"|100",
	}
	for _, raw := range cases {
		if _, _, ok := parsePageCursor(raw); ok {
			t.Errorf("must reject %q", raw)
		}
	}
}

// 页级游标里的窗口起点必须和实际窗口严格相等——差一点就会把上一个窗口的
// 进度套到下一个窗口上（跳页 = 漏数据）。
func TestPageCursorWindowMustMatchExactly(t *testing.T) {
	winStart := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	raw := formatPageCursor(winStart, 2000)
	gotWin, _, ok := parsePageCursor(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	other := winStart.AddDate(0, 0, 120)
	if gotWin.Equal(other) {
		t.Fatal("different windows must not compare equal")
	}
	// 同一时刻不同表示（UTC vs 本地时区）也要能对上
	local := winStart.In(time.FixedZone("CST", 8*3600))
	rawLocal := formatPageCursor(local, 2000)
	gotLocal, _, ok := parsePageCursor(rawLocal)
	if !ok {
		t.Fatal("parse failed for local-zone cursor")
	}
	if !gotLocal.Equal(winStart) {
		t.Errorf("same instant in another zone must compare equal: %v vs %v", gotLocal, winStart)
	}
}
