package server

import "testing"

// TestEstimateUSDCost 钉住定价匹配规则：特定前缀优先、:free 免费、未知模型
// 明确回报 known=false（不能静默算 0 让用户以为免费）。
func TestEstimateUSDCost(t *testing.T) {
	cases := []struct {
		model     string
		in, out   int
		wantUSD   float64
		wantKnown bool
	}{
		{"claude-sonnet-4-6", 1_000_000, 0, 3, true},
		{"claude-opus-4", 0, 1_000_000, 75, true},
		{"nvidia/nemotron-3-ultra:free", 1_000_000, 1_000_000, 0, true},
		{"GLM-4.7-Flash", 1_000_000, 0, 0.6, true},
		{"deepseek-v4.1-flash", 1_000_000, 0, 0.27, true},
		{"some-unknown-model", 1_000_000, 0, 0, false},
		{"", 100, 100, 0, false},
	}
	for _, c := range cases {
		got, known := estimateUSDCost(c.model, c.in, c.out)
		if known != c.wantKnown {
			t.Fatalf("%q known=%v want %v", c.model, known, c.wantKnown)
		}
		if got != c.wantUSD {
			t.Fatalf("%q cost=%v want %v", c.model, got, c.wantUSD)
		}
	}
}

func TestRound4(t *testing.T) {
	if round4(0.123456) != 0.1235 || round4(0) != 0 || round4(3) != 3 {
		t.Fatal("round4 regression")
	}
}
