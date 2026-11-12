package server

// task_runtime_test.go — A8 无成果止损的纯判定函数表驱动测试（不碰 PG）。
// 移植自 ARTEX 0.3.29 server/engine_no_result_test.go 的 TestNoResultRemaining，
// 并按本地 taskLifecycleState（无 PauseReason 字段）改写。

import (
	"strings"
	"testing"
	"time"
)

func TestNoResultRemaining(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state taskLifecycleState
		want  time.Duration
	}{
		{"running", taskLifecycleState{Status: "running", ActiveRunSeconds: 20, RunSegmentStartedAt: 100}, 10 * time.Second},
		{"paused", taskLifecycleState{Status: "running", ActiveRunSeconds: 20, RunSegmentStartedAt: 100, Paused: true}, 40 * time.Second},
		{"queued", taskLifecycleState{Status: "running", ActiveRunSeconds: 20, RunSegmentStartedAt: 100, Queued: true}, 40 * time.Second},
		{"revived", taskLifecycleState{Status: "running", ActiveRunSeconds: 200, NoResultBaseSeconds: 200, RunSegmentStartedAt: 100}, 30 * time.Second},
		{"due", taskLifecycleState{Status: "running", ActiveRunSeconds: 60}, 0},
		{"overdue", taskLifecycleState{Status: "running", ActiveRunSeconds: 1000}, 0},
		{"no segment", taskLifecycleState{Status: "running"}, time.Minute},
		{"created", taskLifecycleState{Status: "created", ActiveRunSeconds: 20, RunSegmentStartedAt: 100}, 40 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := noResultRemaining(60, tc.state, 130); got != tc.want {
				t.Fatalf("remaining=%s, want %s", got, tc.want)
			}
		})
	}
}

func TestTaskRunSecondsAndFinalize(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		active, segmentStarted, now       int64
		status                            string
		paused, queued                    bool
		want                              int64
		wantFinalActive, wantFinalSegment int64
	}{
		{"open running segment", 20, 100, 130, "running", false, false, 50, 50, 0},
		{"paused keeps accumulated", 20, 100, 130, "running", true, false, 20, 50, 0},
		{"queued keeps accumulated", 20, 100, 130, "running", false, true, 20, 50, 0},
		{"non running status", 20, 100, 130, "created", false, false, 20, 50, 0},
		{"no segment", 20, 0, 130, "running", false, false, 20, 20, 0},
		{"negative clamp", -5, 0, 130, "running", false, false, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := taskRunSeconds(tc.active, tc.segmentStarted, tc.now, tc.status, tc.paused, tc.queued); got != tc.want {
				t.Fatalf("taskRunSeconds=%d, want %d", got, tc.want)
			}
			gotActive, gotSegment := finalizeTaskRunSeconds(tc.active, tc.segmentStarted, tc.now)
			if gotActive != tc.wantFinalActive || gotSegment != tc.wantFinalSegment {
				t.Fatalf("finalize=(%d,%d), want (%d,%d)", gotActive, gotSegment, tc.wantFinalActive, tc.wantFinalSegment)
			}
		})
	}
}

func TestEvaluateNoResultStop(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		runtime, count, seconds, min int64
		checkedAt                    int64
		wantOK                       bool
	}{
		{"due and no findings", 60, 0, 60, 1, 0, true},
		{"due and below minimum", 90, 2, 60, 3, 0, true},
		{"minimum clamped to 1", 60, 0, 60, 0, 0, true},
		{"not due", 59, 0, 60, 1, 0, false},
		{"qualifying count", 60, 1, 60, 1, 0, false},
		{"already checked", 120, 0, 60, 1, 1700000000, false},
		{"disabled", 120, 0, 0, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail, ok := evaluateNoResultStop(tc.runtime, tc.count, tc.seconds, tc.min, tc.checkedAt)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v detail=%q, want %v", ok, detail, tc.wantOK)
			}
			if ok && !strings.Contains(detail, "无成果止损") {
				t.Fatalf("detail missing label: %q", detail)
			}
		})
	}
}

func TestNeedsNoResultCoordinator(t *testing.T) {
	if needsNoResultCoordinator(nil) {
		t.Fatal("nil task needs no coordinator")
	}
	if needsNoResultCoordinator(&Task{ID: "1"}) {
		t.Fatal("task without budget needs no coordinator")
	}
	armed := &Task{ID: "1", NoResultSeconds: 60}
	if !needsNoResultCoordinator(armed) {
		t.Fatal("unchecked armed task needs coordinator")
	}
	armed.updateLifecycle(func(s *taskLifecycleState) { s.NoResultCheckedAt = 1700000000 })
	if needsNoResultCoordinator(armed) {
		t.Fatal("checked (passed) task needs no coordinator")
	}
	armed.updateLifecycle(func(s *taskLifecycleState) { s.StopReason = "no_result" })
	if !needsNoResultCoordinator(armed) {
		t.Fatal("committed stop awaiting settle needs coordinator")
	}
}
