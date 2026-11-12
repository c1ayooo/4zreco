package server

// engine_no_result_pg_test.go — A8 无成果止损引擎侧 DSN 门控测试（NewManager 连
// 不上 PG 时 skip，与 task_admission_test.go 同款门控）。移植自 ARTEX 0.3.29
// server/engine_no_result_test.go 的检查点/复活语义；收尾时序（终局规划轮）由
// settleTaskWithReason 既有路径覆盖，这里不重复起协调器。

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

func newNoResultFixture(t *testing.T, severity string) (*Manager, *Task, *Engine) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTaskWithOptions("no-result 引擎测试", "goal", db.TaskCreateOptions{
		NoResultSeconds: 60, NoResultMinFindings: 1, NoResultMinSeverity: severity,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := m.pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID); err != nil {
			t.Error(err)
		}
		if _, err := m.pg.DeleteTaskCascade(mustTaskID(t, task.ID), false, false); err != nil {
			t.Error(err)
		}
	})
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	// 活跃秒数直接落库到预算线（绕开真实计时；段计时的折叠语义由 db 层测试覆盖）。
	if _, err := m.pg.Exec(`UPDATE tasks SET active_run_seconds=60 WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	// 落库的运行态同步回内存句柄（镜像 mirrorTaskRuntime 的职责）。
	return m, reloadNoResultTask(t, m, task.ID), NewEngine(m)
}

func reloadNoResultTask(t *testing.T, m *Manager, id string) *Task {
	t.Helper()
	pt, err := m.pg.GetTask(mustTaskID(t, id))
	if err != nil || pt == nil {
		t.Fatalf("GetTask %s: %v, %v", id, pt, err)
	}
	task := taskFromPG(pt, m, m.pg.Exploration(pt.ExplorationID))
	m.mu.Lock()
	m.tasks[id] = task
	m.mu.Unlock()
	return task
}

func TestNoResultCheckpointStopsAndRevives(t *testing.T) {
	m, task, e := newNoResultFixture(t, "")
	id := mustTaskID(t, task.ID)
	// 0 达标漏洞 → 止损成立，判定落库（stop_reason + checked_at）。
	stop, err := e.checkNoResultCheckpoint(task)
	if err != nil || !stop {
		t.Fatalf("stop=%v err=%v", stop, err)
	}
	state := task.lifecycleSnapshot()
	if state.StopReason != "no_result" || state.NoResultCheckedAt == 0 {
		t.Fatalf("decision not mirrored: %+v", state)
	}
	if stored, err := m.pg.GetTask(id); err != nil || stored.StopReason != "no_result" || stored.NoResultCheckedAt == nil {
		t.Fatalf("decision not durable: %+v, %v", stored, err)
	}
	// 一次性：重复检查（含换新句柄重载）不再认领、不再触发。
	if stop2, err := e.checkNoResultCheckpoint(task); err != nil || stop2 {
		t.Fatalf("rechecked: %v, %v", stop2, err)
	}
	live := reloadNoResultTask(t, m, task.ID)
	if stop3, err := e.checkNoResultCheckpoint(live); err != nil || stop3 {
		t.Fatalf("reloaded rechecked: %v, %v", stop3, err)
	}
	// 收尾期间新到的漏洞不能推翻判定。
	if _, err := m.pg.Exec(`INSERT INTO findings(task_id, vulnclass, name, severity, status, worker)
VALUES ($1,'test','late','high','pending','test')`, id); err != nil {
		t.Fatal(err)
	}
	if stored, err := m.pg.GetTask(id); err != nil || stored.StopReason != "no_result" {
		t.Fatalf("late finding reversed decision: %+v, %v", stored, err)
	}
	// 复活（timeout→running 准入）：一次性检查点重置，止损预算以当时活跃秒数
	// 重新满额，stop_reason 清空。先把行落成 timeout（真实收尾由
	// settleTaskWithReason 完成，这里只复现准入前置状态）。
	if err := m.SetTaskStatus(task.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyTaskAdmission(task.ID, "timeout", "running", false, "resume", false); err != nil {
		t.Fatal(err)
	}
	// ApplyTaskAdmission 镜像的是 manager 登记的句柄（reload 已换过指针），从
	// manager 取回当前句柄再断言。
	mirrored, ok := m.Task(task.ID)
	if !ok {
		t.Fatal("task missing from manager after admission")
	}
	state = mirrored.lifecycleSnapshot()
	if state.NoResultCheckedAt != 0 || state.StopReason != "" {
		t.Fatalf("revival not mirrored: %+v", state)
	}
	if state.NoResultBaseSeconds != state.ActiveRunSeconds {
		t.Fatalf("base not re-armed: base=%d active=%d", state.NoResultBaseSeconds, state.ActiveRunSeconds)
	}
	if remaining := noResultRemaining(60, state, time.Now().Unix()); remaining != time.Minute {
		t.Fatalf("revived remaining=%s, want full budget", remaining)
	}
	if stored, err := m.pg.GetTask(id); err != nil || stored.NoResultCheckedAt != nil || stored.StopReason != "" || stored.NoResultBaseSeconds != 60 {
		t.Fatalf("revival not durable: %+v, %v", stored, err)
	}
}

func TestNoResultCheckpointPassesWithQualifyingFinding(t *testing.T) {
	m, task, e := newNoResultFixture(t, "high")
	id := mustTaskID(t, task.ID)
	if _, err := m.pg.Exec(`INSERT INTO findings(task_id, vulnclass, name, severity, status, worker)
VALUES ($1,'test','qualifying','high','pending','test')`, id); err != nil {
		t.Fatal(err)
	}
	// 高危漏洞达标 → 检查通过，任务继续，之后不再检查（删掉漏洞也不重开检查）。
	stop, err := e.checkNoResultCheckpoint(task)
	if err != nil || stop {
		t.Fatalf("stop=%v err=%v", stop, err)
	}
	if task.lifecycleSnapshot().NoResultCheckedAt == 0 {
		t.Fatal("pass did not claim checkpoint")
	}
	if _, err := m.pg.Exec(`DELETE FROM findings WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if stop2, err := e.checkNoResultCheckpoint(task); err != nil || stop2 {
		t.Fatalf("rechecked after pass: %v, %v", stop2, err)
	}
	if status := m.TaskStatus(task.ID); status != "running" {
		t.Fatalf("passed task stopped: %s", status)
	}
}

func TestNoResultCheckpointBelowSeverityThresholdStops(t *testing.T) {
	m, task, e := newNoResultFixture(t, "high")
	// 有一条 low 漏洞：低于 high 阈值不计入达标数 → 止损成立。
	if _, err := m.pg.Exec(`INSERT INTO findings(task_id, vulnclass, name, severity, status, worker)
VALUES ($1,'test','low only','low','pending','test')`, task.ID); err != nil {
		t.Fatal(err)
	}
	stop, err := e.checkNoResultCheckpoint(task)
	if err != nil || !stop {
		t.Fatalf("stop=%v err=%v", stop, err)
	}
}

func TestCreateTaskRejectsInvalidNoResultSeverity(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.createTask(w, httptest.NewRequest("POST", "/api/tasks",
		strings.NewReader(`{"description":"test","goal":"test","no_result_min_severity":"urgent"}`)))
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
