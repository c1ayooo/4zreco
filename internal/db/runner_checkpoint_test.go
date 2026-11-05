package db

// 刀④ 两张落库面的定向测试（PG 门控，testmain 无 DSN 时 skip）：
//   - runner_checkpoints：装配指纹留痕（写 → 读最新一条）；
//   - exploration_nodes.empty_turn_nudges：空转预算「每条意图总量」计数
//     （原子自增、跨意图隔离、只作用于 intent 行）。

import (
	"context"
	"testing"
)

func TestRunnerCheckpointRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	if err := d.RecordRunnerCheckpoint(ctx, "exp9-worker-i3", "worker", "", "fp-abc"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	if err := d.RecordRunnerCheckpoint(ctx, "exp9-worker-i3", "worker", "ckpt-1", "fp-def"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}
	if err := d.RecordRunnerCheckpoint(ctx, "exp9-worker-i9", "planner", "", "fp-other"); err != nil {
		t.Fatalf("RecordRunnerCheckpoint: %v", err)
	}

	fp, err := d.LatestRunnerCheckpoint(ctx, "exp9-worker-i3")
	if err != nil {
		t.Fatalf("LatestRunnerCheckpoint: %v", err)
	}
	if fp != "fp-def" {
		t.Fatalf("latest fingerprint = %q, want the newest row", fp)
	}
	// checkpointID 只在非空时落库（P1 空、P2 补）。
	var ck string
	if err := d.QueryRowContext(ctx, `SELECT checkpoint_id FROM runner_checkpoints WHERE fingerprint='fp-abc'`).Scan(&ck); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ck != "" {
		t.Fatalf("empty checkpointID must stay NULL/empty, got %q", ck)
	}
}

func TestEmptyTurnNudgeCounter(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("nudge counter", "goal")
	if err != nil {
		t.Fatalf("CreateExploration: %v", err)
	}
	s := d.Exploration(expID)
	intentID, err := s.AddIntent(map[string]any{"description": "测空转计数"}, 0, nil, "")
	if err != nil {
		t.Fatalf("AddIntent: %v", err)
	}

	// 原子自增返回新值：1 → 2 → 3（「每条意图总量」，1-based 与 norma Add(1) 对齐）。
	for want := 1; want <= 3; want++ {
		n, err := s.IncrEmptyTurnNudges(intentID)
		if err != nil {
			t.Fatalf("IncrEmptyTurnNudges: %v", err)
		}
		if n != want {
			t.Fatalf("increment %d returned %d", want, n)
		}
	}
	if n, err := s.EmptyTurnNudges(intentID); err != nil || n != 3 {
		t.Fatalf("EmptyTurnNudges = %d err=%v, want 3", n, err)
	}

	// 隔离：另一条意图计数独立。
	intent2, err := s.AddIntent(map[string]any{"description": "第二条意图"}, 0, nil, "")
	if err != nil {
		t.Fatalf("AddIntent: %v", err)
	}
	if n, err := s.EmptyTurnNudges(intent2); err != nil || n != 0 {
		t.Fatalf("second intent counter = %d err=%v, want 0", n, err)
	}
}
