package report

import (
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// goals.go 移植：goal 节点 → 报告行（逐条达成状态进报告）。
func goalNode(t *testing.T, text, state, criteria string) *db.Node {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"text": text, "criteria": criteria})
	if err != nil {
		t.Fatal(err)
	}
	return &db.Node{Kind: db.KindGoal, Payload: payload, State: state}
}

func TestGoalLinesAndTally(t *testing.T) {
	nodes := []*db.Node{
		goalNode(t, "获取 admin 权限", "met", "拿到 admin cookie"),
		goalNode(t, "枚举子域名", "open", ""),
		// 无 text 的节点跳过（省略该条，不进报告）
		func() *db.Node {
			return &db.Node{Kind: db.KindGoal, Payload: json.RawMessage(`{"criteria":"x"}`), State: "met"}
		}(),
	}
	lines := GoalLines(nodes)
	if len(lines) != 2 {
		t.Fatalf("lines=%d want 2", len(lines))
	}
	if !lines[0].Met() || lines[0].Criteria != "拿到 admin cookie" {
		t.Fatalf("line0=%+v", lines[0])
	}
	if lines[1].Met() {
		t.Fatal("open goal must not be met")
	}
	met, total := GoalTally(lines)
	if met != 1 || total != 2 {
		t.Fatalf("tally=%d/%d want 1/2", met, total)
	}
}

func TestGoalLinesEmpty(t *testing.T) {
	if GoalLines(nil) != nil {
		t.Fatal("nil nodes must yield nil")
	}
	if GoalLines([]*db.Node{{Kind: db.KindGoal, Payload: json.RawMessage(`{}`)}}) != nil {
		t.Fatal("no-text nodes must yield nil (report omits section)")
	}
}
