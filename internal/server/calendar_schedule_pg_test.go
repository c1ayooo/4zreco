package server

// calendar_schedule_pg_test.go — 日历计划调度联动的 DSN 门控测试（NewManager 连
// 不上 PG 时 skip，与 task_admission_test.go 同款门控）：
//   - 窗口打开 → fireTaskSchedulesAt 暂停运行任务并落 schedule_paused + 历史；
//   - 人工暂停优先：schedule_paused=false 时调度器不得自动恢复；
//   - 计划暂停的任务在窗口打开时自动恢复（并发占满则进 FIFO 队列），恢复后
//     schedule_paused 清除。

import (
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

// newScheduleFireFixture 建一个真实 Manager + 最小 Server/Scheduler。
func newScheduleFireFixture(t *testing.T) (*Manager, *Server, *Scheduler) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	s := newAdmissionTestServer(m, nil)
	sc := &Scheduler{s: s, pg: m.pg, startedAt: time.Now()}
	return m, s, sc
}

// alwaysOpenSchedule 全周每天 00:00 起的无界按周窗口：任一时刻（本地/北京）都 active。
func alwaysOpenSchedule() db.TaskScheduleInput {
	return db.TaskScheduleInput{
		Name: "A7 联动常开窗口", Enabled: true, TimezoneMode: "system", ScheduleType: "weekly",
		Weekdays: []int{1, 2, 3, 4, 5, 6, 7}, StartTime: "00:00",
	}
}

func scheduleHistoryActions(t *testing.T, d *db.DB, scheduleID int64) map[string]int {
	t.Helper()
	items, err := d.ListScheduleHistory(scheduleID)
	if err != nil {
		t.Fatalf("ListScheduleHistory: %v", err)
	}
	counts := map[string]int{}
	for _, item := range items {
		counts[item.Action]++
	}
	return counts
}

// closedSchedule 昨天全天的 once 窗口：任一时刻都 complete（窗口已关闭）。
func closedSchedule() db.TaskScheduleInput {
	return db.TaskScheduleInput{
		Name: "A7 联动已关窗口", Enabled: true, TimezoneMode: "system", ScheduleType: "once",
		RunDate: time.Now().AddDate(0, 0, -1).Format("2006-01-02"),
		EndDate: time.Now().AddDate(0, 0, -1).Format("2006-01-02"),
		StartTime: "00:00", EndTime: "23:59",
	}
}

func TestScheduleFirePausesTaskOutsideWindow(t *testing.T) {
	m, _, sc := newScheduleFireFixture(t)
	d := m.pg

	task, err := m.CreateTask("A7 窗口外暂停", "联动验证", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskNum := mustTaskID(t, task.ID)
	item, err := d.CreateTaskSchedule(closedSchedule())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTaskSchedule(item.ID) })
	// 绑定任务到计划（CreateTaskSchedule 已校验任务存在，这里直接补绑）
	if _, err := d.Exec(`INSERT INTO task_schedule_tasks(schedule_id,task_id) VALUES($1,$2)`,
		item.ID, taskNum); err != nil {
		t.Fatal(err)
	}

	sc.fireTaskSchedulesAt(time.Now())

	if paused, err := d.TaskPausedBySchedule(taskNum); err != nil || !paused {
		t.Fatalf("窗口外应暂停任务并落 schedule_paused: %v %v", paused, err)
	}
	lifecycle := task.lifecycleSnapshot()
	if !lifecycle.Paused {
		t.Fatalf("任务应处于暂停态: %+v", lifecycle)
	}
	got, err := d.GetTaskSchedule(item.ID)
	if err != nil || got.Status != "completed" {
		t.Fatalf("已关窗口的计划应进入 completed: %+v err=%v", got, err)
	}
	counts := scheduleHistoryActions(t, d, item.ID)
	if counts["pause"] != 1 {
		t.Fatalf("应记录一条 pause 历史: %v", counts)
	}

	// 再 tick 一次：已暂停且窗口仍关 → 无重复动作
	sc.fireTaskSchedulesAt(time.Now())
	counts = scheduleHistoryActions(t, d, item.ID)
	if counts["pause"] != 1 || counts["resume"] != 0 {
		t.Fatalf("重复 tick 不应重复联动: %v", counts)
	}
}

func TestScheduleFireDoesNotResumeUserPausedTask(t *testing.T) {
	m, s, sc := newScheduleFireFixture(t)
	d := m.pg

	task, err := m.CreateTask("A7 人工暂停优先", "联动验证", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskNum := mustTaskID(t, task.ID)
	if err := m.SetTaskPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	s.engine.Pause(task.ID, agent.AbortPausedByUser)
	// 人工暂停：schedule_paused=false（ApplyTaskPause 已清，显式断言基线）
	if paused, _ := d.TaskPausedBySchedule(taskNum); paused {
		t.Fatal("人工暂停不应带 schedule_paused 标记")
	}

	item, err := d.CreateTaskSchedule(alwaysOpenSchedule())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTaskSchedule(item.ID) })
	if _, err := d.Exec(`INSERT INTO task_schedule_tasks(schedule_id,task_id) VALUES($1,$2)`,
		item.ID, taskNum); err != nil {
		t.Fatal(err)
	}

	sc.fireTaskSchedulesAt(time.Now())

	if !task.lifecycleSnapshot().Paused {
		t.Fatal("人工暂停的任务不得被计划自动恢复")
	}
	counts := scheduleHistoryActions(t, d, item.ID)
	if counts["resume"] != 0 {
		t.Fatalf("人工暂停不应产生 resume 历史: %v", counts)
	}
	if got, _ := d.GetTaskSchedule(item.ID); got.Status != "running" {
		t.Fatalf("窗口态仍应推进为 running: %+v", got)
	}
}

func TestScheduleFireResumesSchedulePausedTask(t *testing.T) {
	m, s, sc := newScheduleFireFixture(t)
	d := m.pg
	// 并发上限占满：恢复进 FIFO 队列，避免测试环境真的拉起 planner。
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	holder, err := m.CreateTask("A7 并发占位", "hold", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(holder.ID, DeleteTaskOptions{}) })

	task, err := m.CreateTask("A7 计划恢复", "联动验证", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskNum := mustTaskID(t, task.ID)
	if err := m.SetTaskPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	s.engine.Pause(task.ID, agent.AbortPausedBySchedule)
	// 模拟「调度器已暂停该任务」的持久态
	if _, err := d.Exec(`UPDATE tasks SET schedule_paused=true, queue_mode='bootstrap' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}

	item, err := d.CreateTaskSchedule(alwaysOpenSchedule())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTaskSchedule(item.ID) })
	if _, err := d.Exec(`INSERT INTO task_schedule_tasks(schedule_id,task_id) VALUES($1,$2)`,
		item.ID, taskNum); err != nil {
		t.Fatal(err)
	}

	sc.fireTaskSchedulesAt(time.Now())

	if paused, _ := d.TaskPausedBySchedule(taskNum); paused {
		t.Fatal("计划恢复后 schedule_paused 应清除")
	}
	lifecycle := task.lifecycleSnapshot()
	if lifecycle.Paused || !lifecycle.Queued {
		t.Fatalf("计划恢复应让任务退出暂停（并发占满进队列）: %+v", lifecycle)
	}
	counts := scheduleHistoryActions(t, d, item.ID)
	if counts["resume"] != 1 {
		t.Fatalf("应记录一条 resume 历史: %v", counts)
	}
}
