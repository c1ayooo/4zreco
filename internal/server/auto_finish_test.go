package server

import (
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
)

func TestEvaluateAutoFinish(t *testing.T) {
	cfg := autoFinishConfig{Enabled: true, IdleRounds: 3, MinRounds: 5, CoveragePct: 0, MaxRounds: 80}
	cases := []struct {
		name         string
		round        int64
		idle         int
		active       bool
		coverage     int
		cfg          autoFinishConfig
		wantReason   string
		wantDecision bool
	}{
		{"below-min-rounds", 4, 9, false, 0, cfg, "", false},
		{"idle-below-threshold", 5, 2, false, 0, cfg, "", false},
		{"idle-active-intent", 5, 3, true, 0, cfg, "", false},
		{"idle-trigger", 5, 3, false, 0, cfg, "auto_idle", true},
		{"max-rounds-even-active", 80, 0, true, 0, cfg, "auto_rounds", true},
		{"coverage-disabled", 6, 1, false, 99, cfg, "", false},
		{"coverage-trigger", 6, 1, false, 95, autoFinishConfig{Enabled: true, IdleRounds: 3, MinRounds: 5, CoveragePct: 90, MaxRounds: 80}, "auto_coverage", true},
		{"coverage-needs-idle-round", 6, 0, false, 95, autoFinishConfig{Enabled: true, IdleRounds: 3, MinRounds: 5, CoveragePct: 90, MaxRounds: 80}, "", false},
		{"disabled", 100, 99, false, 100, autoFinishConfig{Enabled: false, IdleRounds: 3, MinRounds: 5, MaxRounds: 80}, "", false},
		{"max-zero-unlimited", 500, 0, false, 0, autoFinishConfig{Enabled: true, IdleRounds: 3, MinRounds: 5, MaxRounds: 0}, "", false},
	}
	for _, tc := range cases {
		reason, _, ok := evaluateAutoFinish(tc.round, tc.idle, tc.active, tc.coverage, tc.cfg)
		if ok != tc.wantDecision || reason != tc.wantReason {
			t.Fatalf("%s: got (%q,%v) want (%q,%v)", tc.name, reason, ok, tc.wantReason, tc.wantDecision)
		}
	}
}

func TestFreshDirection(t *testing.T) {
	cases := []struct {
		events []agent.TriggerEvent
		want   bool
	}{
		{nil, false},
		{[]agent.TriggerEvent{{Kind: "done"}}, false},
		{[]agent.TriggerEvent{{Kind: "finding"}}, false},
		{[]agent.TriggerEvent{{Kind: "goal"}}, true},
		{[]agent.TriggerEvent{{Kind: "hint"}}, true},
		{[]agent.TriggerEvent{{Kind: "goal_edited"}}, true},
		{[]agent.TriggerEvent{{Kind: "goal_deleted"}}, true},
	}
	for _, tc := range cases {
		if got := freshDirection(tc.events); got != tc.want {
			t.Fatalf("events=%+v got=%v want=%v", tc.events, got, tc.want)
		}
	}
}
