package db

import "testing"

// 零工具收场自动重派的持久层通道（PG 门控，无 DSN 时 skip）：
// ReopenDegradedIntent 只翻 done→open。手动重跑端点的「done 即终态」契约
// 不受影响（ReopenIntent 仍只收 blocked/exhausted/stopped）。
func TestReopenDegradedIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("degraded rerun", "goal")
	if err != nil {
		t.Fatalf("CreateExploration: %v", err)
	}
	s := d.Exploration(expID)

	mkIntent := func(state string) int64 {
		t.Helper()
		id, err := s.AddIntent(map[string]any{"description": "退化重派测试"}, 5, nil, "")
		if err != nil {
			t.Fatalf("AddIntent: %v", err)
		}
		if state != "open" {
			if err := s.SetIntentState(id, state); err != nil {
				t.Fatalf("SetIntentState(%s): %v", state, err)
			}
		}
		return id
	}

	doneID := mkIntent("done")
	reopened, err := s.ReopenDegradedIntent(doneID)
	if err != nil {
		t.Fatalf("reopen done: %v", err)
	}
	if !reopened {
		t.Fatal("done 意图必须可被退化通道重开")
	}
	node, err := s.GetNode(doneID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.State != "open" {
		t.Fatalf("重开后应为 open，得到 %s", node.State)
	}

	for _, st := range []string{"running", "blocked", "exhausted", "open"} {
		id := mkIntent(st)
		reopened, err := s.ReopenDegradedIntent(id)
		if err != nil {
			t.Fatalf("reopen %s: %v", st, err)
		}
		if reopened {
			t.Errorf("%s 意图不应被退化通道重开", st)
		}
	}
}
