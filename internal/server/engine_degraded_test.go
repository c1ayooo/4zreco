package server

import (
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/norma/harness"
)

func TestZeroToolMisfire(t *testing.T) {
	t.Parallel()
	zero := agent.WriteCounts{}
	wrote := agent.WriteCounts{Facts: 2}
	tests := []struct {
		name       string
		reason     harness.TerminalReason
		err        error
		wrote      agent.WriteCounts
		toolCalls  int64
		chatDriven bool
		want       bool
	}{
		{"典型身份坍缩：完成态+零写回+零工具", harness.ReasonCompleted, nil, zero, 0, false, true},
		{"有写回不算退化", harness.ReasonCompleted, nil, wrote, 0, false, false},
		{"调过工具不算退化", harness.ReasonCompleted, nil, zero, 3, false, false},
		{"对话驱动的纯文本回复是合法行为", harness.ReasonCompleted, nil, zero, 0, true, false},
		{"模型错误走既有重试通道", harness.ReasonModelError, errFake, zero, 0, false, false},
		{"撞步数走 exhausted/B2 通道", harness.ReasonMaxTurns, nil, zero, 0, false, false},
		{"出错收场走 blocked", harness.ReasonCompleted, errFake, zero, 0, false, false},
		{"流中断走既有分支", harness.ReasonAbortedStreaming, nil, zero, 0, false, false},
	}
	for _, tt := range tests {
		if got := zeroToolMisfire(tt.reason, tt.err, tt.wrote, tt.toolCalls, tt.chatDriven); got != tt.want {
			t.Errorf("%s: zeroToolMisfire = %v, want %v", tt.name, got, tt.want)
		}
	}
}

var errFake = &fakeError{}

type fakeError struct{}

func (*fakeError) Error() string { return "fake" }

func TestDegradedAttemptsOf(t *testing.T) {
	t.Parallel()
	mk := func(payload any) *db.Node {
		n := &db.Node{}
		if payload != nil {
			b, _ := json.Marshal(payload)
			n.Payload = b
		}
		return n
	}
	cases := []struct {
		name string
		node *db.Node
		want int
	}{
		{"nil 节点", nil, 0},
		{"空 payload", mk(nil), 0},
		{"无该键", mk(map[string]any{"wall_ms": 12}), 0},
		{"JSON 数字是 float64 也要读对", mk(map[string]any{"degraded_attempts": 2}), 2},
		{"负值当 0", mk(map[string]any{"degraded_attempts": -1}), 0},
	}
	for _, tt := range cases {
		if got := degradedAttemptsOf(tt.node); got != tt.want {
			t.Errorf("%s: degradedAttemptsOf = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestDegradedRerunLimitReached(t *testing.T) {
	t.Parallel()
	if degradedRerunLimit < 1 {
		t.Fatalf("重派上限必须 ≥1，否则零工具收场永远不重派")
	}
}
