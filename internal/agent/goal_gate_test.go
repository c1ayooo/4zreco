package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// 上游 0.4.80 #20：prove_goal 能力型目标证据等级——否定性 fact 与 low finding
// 不能把「获取 RCE」类目标标 met，high finding 可以（真实 PostgreSQL）。
func TestProveGoalCapabilityGate(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("prove_goal capability gate", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)

	goalID, err := ts.AddNode(db.KindGoal, map[string]any{"text": "获取 RCE / 命令执行权限"}, 0, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	factID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "未发现入口"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	lowID, err := ts.AddNode(db.KindFinding, map[string]any{"severity": "low", "name": "信息泄露"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	highID, err := ts.AddNode(db.KindFinding, map[string]any{"severity": "high", "name": "RCE"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	tset := &ToolSet{ts: ts, worker: "planner"}
	prove := func(evidence int64) {
		_, _ = tset.proveGoal().Call(ctx, json.RawMessage(fmt.Sprintf(
			`{"goal_id":%d,"evidence_id":%d,"reason":"test"}`, goalID, evidence)), nil)
	}

	prove(factID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "open" {
		t.Fatalf("否定性 fact 不应把能力型目标标 met，state=%v", n)
	}
	if tset.GoalMet {
		t.Fatal("fact 证明后 GoalMet 不应为 true")
	}

	prove(lowID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "open" {
		t.Fatalf("low finding 不应把能力型目标标 met，state=%v", n)
	}

	prove(highID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "met" {
		t.Fatalf("high finding 应能把能力型目标标 met，state=%v", n)
	}
	if !tset.GoalMet {
		t.Fatal("全部目标 met 后 GoalMet 应为 true")
	}
}

// 「确认是否存在」类目标用否定性 fact 证明是合法的，不能被能力门槛误伤。
func TestProveGoalNegativeGoalAllowsFact(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("prove_goal negative goal", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)

	goalID, err := ts.AddNode(db.KindGoal, map[string]any{"text": "确认目标是否存在未授权访问入口"}, 0, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	factID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "未发现未授权访问入口"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	tset := &ToolSet{ts: ts, worker: "planner"}
	_, _ = tset.proveGoal().Call(ctx, json.RawMessage(fmt.Sprintf(
		`{"goal_id":%d,"evidence_id":%d,"reason":"test"}`, goalID, factID)), nil)
	n, _ := ts.GetNode(goalID)
	if n == nil || n.State != "met" {
		t.Fatalf("存在性目标应允许 fact 证明，state=%v", n)
	}
}
