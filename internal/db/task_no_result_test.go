package db

// task_no_result_test.go — A8 无成果止损持久层测试。NormalizeNoResultOptions 是
// 纯函数（无 DSN 也跑）；其余连真 PG（testDSN 不可用时 skip，与 tasks_test.go
// 同款门控）。移植自 ARTEX 0.3.29 db/task_no_result_test.go，断言按本地
// findings 直数口径（无 finding_cases JOIN）改写。

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeNoResultOptions(t *testing.T) {
	for _, tc := range []struct{ seconds, count, wantSeconds, wantCount int }{
		{0, 0, 0, 1}, {-1, -1, 0, 1}, {1, 0, 60, 1}, {59, 2, 60, 2}, {60, 1, 60, 1}, {7200, 3, 7200, 3},
	} {
		opts := TaskCreateOptions{NoResultSeconds: tc.seconds, NoResultMinFindings: tc.count}
		if err := NormalizeNoResultOptions(&opts); err != nil || opts.NoResultSeconds != tc.wantSeconds || opts.NoResultMinFindings != tc.wantCount {
			t.Fatalf("normalize %+v = %+v, %v", tc, opts, err)
		}
	}
	for _, severity := range []string{"", "low", "medium", "high", "critical"} {
		if err := NormalizeNoResultOptions(&TaskCreateOptions{NoResultMinSeverity: severity}); err != nil {
			t.Fatalf("severity %q rejected: %v", severity, err)
		}
	}
	if err := NormalizeNoResultOptions(&TaskCreateOptions{NoResultMinSeverity: "unknown"}); err == nil {
		t.Fatal("invalid severity accepted")
	}
}

func noResultTestDB(t *testing.T) (*DB, *Task) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("no-result 止损测试", "goal", TaskCreateOptions{NoResultSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID); err != nil {
			t.Error(err)
		}
		if err := d.DeleteTask(task.ID); err != nil {
			t.Error(err)
		}
	})
	return d, task
}

// addFinding 直插一条漏洞（绕开 RecordFindingTx 的去重/通知，只服务计数口径测试）。
func addFinding(t *testing.T, d *DB, taskID int64, severity, status string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO findings(task_id, vulnclass, name, severity, status, worker)
VALUES ($1,'test','test',$2,$3,'test')`, taskID, severity, status); err != nil {
		t.Fatal(err)
	}
}

func TestCountQualifyingFindings(t *testing.T) {
	d, task := noResultTestDB(t)
	addFinding(t, d, task.ID, "high", "pending")
	addFinding(t, d, task.ID, "medium", "pending")
	addFinding(t, d, task.ID, "low", "resolved")
	addFinding(t, d, task.ID, "critical", "false_positive") // 误报永不计入
	// 严重度阈值折叠在 SQL 里：低于阈值的漏洞不计入达标数。
	for severity, want := range map[string]int{"": 3, "low": 3, "medium": 2, "high": 1, "critical": 0} {
		got, err := d.CountQualifyingFindings(task.ID, severity)
		if err != nil || got != want {
			t.Errorf("severity %q: count=%d, err=%v, want %d", severity, got, err, want)
		}
	}
}

func TestCreateTaskNormalizesNoResultOptions(t *testing.T) {
	d, task := noResultTestDB(t)
	if task.NoResultSeconds != 60 || task.NoResultMinFindings != 1 || task.NoResultMinSeverity != "" {
		t.Fatalf("creation normalize: %+v", task)
	}
	// 落库回读一致（taskCols 扩列后的往返）。
	stored, err := d.GetTask(task.ID)
	if err != nil || stored == nil {
		t.Fatalf("GetTask: %v, %v", stored, err)
	}
	if stored.NoResultSeconds != 60 || stored.NoResultMinFindings != 1 || stored.NoResultBaseSeconds != 0 ||
		stored.NoResultCheckedAt != nil || stored.StopReason != "" || stored.ActiveRunSeconds != 0 ||
		stored.RunSegmentStartedAt != nil {
		t.Fatalf("stored defaults: %+v", stored)
	}
	_ = d
}

func TestNoResultCheckpointClaimsOnce(t *testing.T) {
	d, task := noResultTestDB(t)
	ctx := t.Context()
	// 0 达标漏洞 → stop=true，检查点认领。
	count, stop, checked, err := d.CheckNoResultCheckpoint(ctx, task.ID, 1, "high")
	if err != nil || count != 0 || !stop || checked == nil {
		t.Fatalf("first check: count=%d stop=%v checked=%v err=%v", count, stop, checked, err)
	}
	// 二次检查不认领（一次性）。
	if _, _, checked2, err := d.CheckNoResultCheckpoint(ctx, task.ID, 1, "high"); err != nil || checked2 != nil {
		t.Fatalf("second check claimed again: %v, %v", checked2, err)
	}
	stored, err := d.GetTask(task.ID)
	if err != nil || stored == nil {
		t.Fatalf("GetTask: %v, %v", stored, err)
	}
	if stored.StopReason != StopReasonNoResult || stored.NoResultCheckedAt == nil || !stored.NoResultCheckedAt.Equal(*checked) {
		t.Fatalf("persisted decision: %+v", stored)
	}
	// 检查后再写入的漏洞不能推翻已落库的判定。
	addFinding(t, d, task.ID, "high", "pending")
	if stored2, err := d.GetTask(task.ID); err != nil || stored2.StopReason != StopReasonNoResult {
		t.Fatalf("later finding reversed stop: %+v, %v", stored2, err)
	}
	if count, err := d.CountQualifyingFindings(task.ID, "high"); err != nil || count != 1 {
		t.Fatalf("later finding not committed: %d, %v", count, err)
	}
}

func TestNoResultCheckpointWaitsForFindingCommit(t *testing.T) {
	d, task := noResultTestDB(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// 漏洞写事务持有 tasks 行锁（RecordFindingTx 的 LockTaskEvidenceTx 同款锁），
	// 检查点必须等它提交后才能看到这条漏洞——对齐「已提交才计入」。
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := LockTaskEvidenceTx(tx, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO findings(task_id, vulnclass, name, severity, status, worker)
VALUES ($1,'test','late','high','pending','test')`, task.ID); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	type decision struct {
		count   int
		stop    bool
		checked *time.Time
		err     error
	}
	result := make(chan decision, 1)
	go func() {
		count, stop, checked, err := d.CheckNoResultCheckpoint(ctx, task.ID, 1, "high")
		result <- decision{count, stop, checked, err}
	}()
	// 有界轮询等锁等待真实出现（不靠短 sleep 猜调度），再确认检查点未提前返回。
	waitForNoResultLockWait(t, d, pid)
	select {
	case got := <-result:
		t.Fatalf("checkpoint returned before finding commit: %+v", got)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || got.count != 1 || got.stop || got.checked == nil {
		t.Fatalf("checkpoint after finding commit: %+v", got)
	}
}

// waitForNoResultLockWait 观察到 PostgreSQL 真实的锁等待（pg_blocking_pids）再返回，
// 而不是假设 goroutine 已被调度。
func waitForNoResultLockWait(t *testing.T, d *DB, blockerPID int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := d.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("operation never waited for the task row lock")
		case <-tick.C:
		}
	}
}

func TestNoResultCheckpointSkipsUnavailableTasks(t *testing.T) {
	for _, status := range []string{"done", "failed", "timeout", "deleted", "missing"} {
		t.Run(status, func(t *testing.T) {
			d, task := noResultTestDB(t)
			id := task.ID
			switch status {
			case "deleted":
				if _, err := d.Exec(`UPDATE tasks SET deleted_at=clock_timestamp() WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
			case "missing":
				id = -1
			default:
				if err := d.SetStatus(id, status); err != nil {
					t.Fatal(err)
				}
			}
			if count, stop, checked, err := d.CheckNoResultCheckpoint(t.Context(), id, 1, ""); err != nil || count != 0 || stop || checked != nil {
				t.Fatalf("unavailable task claimed: %d %v %v %v", count, stop, checked, err)
			}
		})
	}
}

// TestNoResultStopReasonLifecycle 覆盖 stop_reason 随终态的写入/守卫/复原语义。
func TestNoResultStopReasonLifecycle(t *testing.T) {
	d, task := noResultTestDB(t)
	// timeout + stop_reason 一起落库。
	if won, err := d.SetTerminalStatusGuardedReason(task.ID, "timeout", StopReasonNoResult); err != nil || !won {
		t.Fatalf("timeout stop: won=%v err=%v", won, err)
	}
	// 终态守卫：后写的 done 不得覆盖（第一终态写入者赢）。
	if won, err := d.SetTerminalStatusGuardedReason(task.ID, "done", ""); err != nil || won {
		t.Fatalf("terminal guard: won=%v err=%v", won, err)
	}
	stored, err := d.GetTask(task.ID)
	if err != nil || stored.Status != "timeout" || stored.StopReason != StopReasonNoResult {
		t.Fatalf("persisted stop: %+v, %v", stored, err)
	}
	// 非终态转出（SetStatus running）清 stop_reason（A8 复原语义）。
	if err := d.SetStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if stored, err := d.GetTask(task.ID); err != nil || stored.StopReason != "" {
		t.Fatalf("nonterminal reason not cleared: %+v, %v", stored, err)
	}
	// done 终态强制清 stop_reason（达成不算止损）。
	if won, err := d.SetTerminalStatusGuardedReason(task.ID, "done", StopReasonNoResult); err != nil || !won {
		t.Fatalf("done stop: won=%v err=%v", won, err)
	}
	if stored, err := d.GetTask(task.ID); err != nil || stored.StopReason != "" {
		t.Fatalf("done must clear stop reason: %+v, %v", stored, err)
	}
}

// TestTaskRunSegmentFold 覆盖活跃段的打开/折叠与暂停不计时。段起点被显式回拨
// 2 秒，避免依赖真实耗时（亚秒开合会被 FLOOR 取整成 0 而测不到折叠）。
func TestTaskRunSegmentFold(t *testing.T) {
	d, task := noResultTestDB(t)
	if err := d.SetStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if _, started, err := d.StartTaskRunSegment(task.ID); err != nil || started == nil {
		t.Fatalf("start segment: started=%v err=%v", started, err)
	}
	if _, err := d.Exec(`UPDATE tasks SET run_segment_started_at = now() - interval '2 seconds' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	// 幂等：重复打开不动（回拨后的）起点。
	_, started2, err := d.StartTaskRunSegment(task.ID)
	if err != nil || started2 == nil || time.Since(*started2) < 2*time.Second {
		t.Fatalf("restart segment kept backdated start: %v %v", started2, err)
	}
	// 暂停折叠：段折进累计值（≥2s）、段起点清空——暂停从此不再计时。
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetTask(task.ID)
	if err != nil || stored.RunSegmentStartedAt != nil || stored.ActiveRunSeconds < 2 {
		t.Fatalf("pause fold: %+v, %v", stored, err)
	}
	// 无开放段后，重复折叠是安全空操作（暂停/终态路径可重复调用）。
	if active3, _, err := d.FinalizeTaskRunSegment(task.ID); err != nil || active3 != stored.ActiveRunSeconds {
		t.Fatalf("finalize no-op: %d %v", active3, err)
	}
}
