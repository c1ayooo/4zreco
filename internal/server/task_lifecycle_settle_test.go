package server

import (
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// TestResetRunningIntentsRecordsShutdownReason 钉住服务重启恢复路径（上游 0.4.37）：
// 残留 running 意图回 open 时把 server_shutdown 原因落库——重启不是 worker 的错，
// 界面/规划者能看到「这条为什么被打断」。
func TestResetRunningIntentsRecordsShutdownReason(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("reset running shutdown reason", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	id, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "in-flight when restart hit"}, 0, "running", "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	n, err := task.Store.ResetRunningIntents()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("重置条数=%d，期望 1", n)
	}
	node, err := task.Store.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	if node.State != "open" {
		t.Fatalf("意图状态=%q，期望 open", node.State)
	}
	if node.BlockedReason != db.IntentStopShutdown {
		t.Fatalf("重开原因=%q，期望 %s", node.BlockedReason, db.IntentStopShutdown)
	}
}

// TestRevivalReopensCanceledIntents 钉住终态复活自愈（上游 0.4.57）：
// blocked=context canceled 的遗留意图（部署重启的遗留物）在任务从终态复活时
// 自动重开；用户手动 block 的意图不受影响。顺带覆盖 done 复活的时钟重置
// （上游 task 13 事故：done 复活沿用过期 deadline，人工跟进被秒收）。
func TestRevivalReopensCanceledIntents(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	oldEnabled, oldLimit := m.ConcurrencyLimit()
	if oldLimit < 1 {
		oldLimit = defaultConcurrencyLimit
	}
	defer m.SetConcurrency(oldEnabled, oldLimit)
	if err := m.SetConcurrency(false, 0); err != nil {
		t.Fatal(err)
	}

	task, err := m.CreateTask("revival reopen canceled", "follow-up must reach the canceled intents", nil, 3600, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	// 两条 blocked 意图：一条是部署重启遗留物（context canceled），一条是人工 block。
	canceledID, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "killed by restart"}, 0, "blocked", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentStopReason(canceledID, "error: context canceled"); err != nil {
		t.Fatal(err)
	}
	manualID, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "user blocked on purpose"}, 0, "blocked", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentStopReason(manualID, "user decided to stop this direction"); err != nil {
		t.Fatal(err)
	}

	// 任务因目标全达成落 done，first_run_at/deadline_at 留着已过期的一轮预算。
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatal(err)
	}

	s := newAdmissionTestServer(m, nil)
	queued, err := s.admitTask(task, "resume")
	if err != nil {
		t.Fatalf("admit revived task: %v", err)
	}
	if queued {
		t.Fatal("并发已关，复活应直接启动而不是排队")
	}

	canceled, err := task.Store.GetNode(canceledID)
	if err != nil {
		t.Fatal(err)
	}
	if canceled.State != "open" {
		t.Fatalf("canceled 意图状态=%q，期望 open（复活自愈未生效）", canceled.State)
	}
	manual, err := task.Store.GetNode(manualID)
	if err != nil {
		t.Fatal(err)
	}
	if manual.State != "blocked" {
		t.Fatalf("人工 block 的意图状态=%q，期望保持 blocked", manual.State)
	}

	// done 复活的时钟重置：first_run_at/deadline_at 必须清零，等下一次真实运行重新盖章。
	var firstNull, deadlineNull bool
	if err := m.pg.QueryRow(`SELECT first_run_at IS NULL, deadline_at IS NULL FROM tasks WHERE id=$1`,
		task.ID).Scan(&firstNull, &deadlineNull); err != nil {
		t.Fatal(err)
	}
	if !firstNull || !deadlineNull {
		t.Fatalf("终态复活必须清时钟: first_run_at null=%v deadline_at null=%v", firstNull, deadlineNull)
	}
}

// TestResumeExtendsDeadlineByPausedDuration 钉住暂停恢复 deadline 顺延
// （上游 0.4.80 #22）：恢复时按暂停时长把 deadline_at 往后顺延，并把 paused_at
// 清空——任务预算不因暂停而缩水。
func TestResumeExtendsDeadlineByPausedDuration(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("pause deadline extension", "goal", nil, 600, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	if _, err := m.pg.Exec(`UPDATE tasks SET status='running', first_run_at=now()-interval '10 minutes', deadline_at=now()+interval '5 minutes' WHERE id=$1`,
		task.ID); err != nil {
		t.Fatal(err)
	}

	if err := m.ApplyTaskPause(task.ID); err != nil {
		t.Fatal(err)
	}
	// 模拟已暂停 20 分钟。
	if _, err := m.pg.Exec(`UPDATE tasks SET paused_at=now()-interval '20 minutes' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyTaskAdmission(task.ID, "running", "running", false, "resume", false); err != nil {
		t.Fatal(err)
	}

	var deadlineAt, pausedAt *time.Time
	if err := m.pg.QueryRow(`SELECT deadline_at, paused_at FROM tasks WHERE id=$1`, task.ID).Scan(&deadlineAt, &pausedAt); err != nil {
		t.Fatal(err)
	}
	if pausedAt != nil {
		t.Fatal("恢复后 paused_at 应清空")
	}
	if deadlineAt == nil {
		t.Fatal("deadline_at 不应为空")
	}
	// 原 deadline 在 5 分钟后；暂停 20 分钟应顺延到约 25 分钟后。
	if got := time.Until(*deadlineAt); got < 19*time.Minute {
		t.Fatalf("deadline 只剩 %v，期望按 20 分钟暂停时长顺延到约 25 分钟后", got)
	}
}
