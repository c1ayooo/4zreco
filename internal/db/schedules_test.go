package db

// schedules_test.go — 日历式计划任务持久层的 DSN 门控测试（ZRECO_PG_DSN 缺省
// skip，与 hitl_test.go 同款门控）：
//   - 计划 CRUD 往返（weekdays JSON、时间列 to_char 归一、remark 元数据补丁不动窗口态）；
//   - 历史/统计（RecordScheduleHistory → ScheduleRunStats 只数 schedule 级 running）；
//   - 任务↔计划绑定（task_schedule_tasks 级联、paused_by_schedule 标记）；
//   - CreateTaskWithOptions 携带 Schedule：非立即启动 → 落库即暂停
//     （paused+schedule_paused+queue_mode='bootstrap'），立即启动 → 不暂停。

import (
	"testing"
)

func scheduleTestDB(t *testing.T) *DB {
	t.Helper()
	return hitlTestDB(t)
}

func TestTaskScheduleCRUDAndMetadata(t *testing.T) {
	d := scheduleTestDB(t)

	in := TaskScheduleInput{
		Name: "A7 计划 CRUD", TimezoneMode: "beijing", ScheduleType: "weekly",
		Weekdays: []int{6, 1}, StartTime: "18:00", EndTime: "09:00",
	}
	s, err := d.CreateTaskSchedule(in)
	if err != nil {
		t.Fatalf("CreateTaskSchedule: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTaskSchedule(s.ID) })
	if s.ID == 0 || s.Status != "waiting" || s.Remark != "" {
		t.Fatalf("新建计划字段不符: %+v", s)
	}
	if len(s.Weekdays) != 2 || s.Weekdays[0] != 1 || s.Weekdays[1] != 6 {
		t.Fatalf("weekdays 应排序去重为 [1 6]: %v", s.Weekdays)
	}
	if s.StartTime != "18:00:00" || s.EndTime != "09:00:00" {
		t.Fatalf("时间列应归一为 HH:MM:SS: %q %q", s.StartTime, s.EndTime)
	}

	// 元数据补丁：只改 name/remark，不动窗口态与绑定
	patched, err := d.UpdateTaskScheduleMetadata(s.ID, TaskSchedulePatch{Name: strPtr("A7 改名"), Remark: strPtr("备注一下")})
	if err != nil || patched == nil {
		t.Fatalf("UpdateTaskScheduleMetadata: %v %v", patched, err)
	}
	if patched.Name != "A7 改名" || patched.Remark != "备注一下" || patched.Status != "waiting" || patched.LastWindowKey != "" {
		t.Fatalf("元数据补丁不应触碰窗口态: %+v", patched)
	}
	if _, err := d.UpdateTaskScheduleRemark(s.ID, "只改备注"); err != nil {
		t.Fatalf("UpdateTaskScheduleRemark: %v", err)
	}

	// 启停与窗口触写
	if err := d.SetTaskScheduleEnabled(s.ID, false); err != nil {
		t.Fatalf("SetTaskScheduleEnabled(false): %v", err)
	}
	if g, _ := d.GetTaskSchedule(s.ID); g.Enabled || g.Status != "paused" {
		t.Fatalf("停用后应 paused: %+v", g)
	}
	if err := d.TouchTaskSchedule(s.ID, "running", "active:2026-11-13T18:00", ""); err != nil {
		t.Fatalf("TouchTaskSchedule: %v", err)
	}
	if g, _ := d.GetTaskSchedule(s.ID); g.Status != "running" || g.LastWindowKey != "active:2026-11-13T18:00" {
		t.Fatalf("窗口触写不回环: %+v", g)
	}

	// 全量列表包含本计划
	list, err := d.ListTaskSchedules()
	if err != nil {
		t.Fatalf("ListTaskSchedules: %v", err)
	}
	found := false
	for _, item := range list {
		if item.ID == s.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("ListTaskSchedules 缺少新建计划")
	}
}

func TestTaskScheduleHistoryAndStats(t *testing.T) {
	d := scheduleTestDB(t)
	s, err := d.CreateTaskSchedule(TaskScheduleInput{Name: "A7 历史统计", ScheduleType: "weekly", Weekdays: []int{3}, StartTime: "08:00"})
	if err != nil {
		t.Fatalf("CreateTaskSchedule: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTaskSchedule(s.ID) })

	// schedule 级 running 行计一次运行；task 级行不计入 run_count
	if err := d.RecordScheduleHistory(s.ID, 0, "running", true, "计划窗口"); err != nil {
		t.Fatalf("RecordScheduleHistory(schedule): %v", err)
	}
	if err := d.RecordScheduleHistory(s.ID, 42, "pause", true, "计划窗口"); err != nil {
		t.Fatalf("RecordScheduleHistory(task): %v", err)
	}
	if err := d.RecordScheduleHistory(s.ID, 0, "error", false, "任务 #42: x"); err != nil {
		t.Fatalf("RecordScheduleHistory(error): %v", err)
	}
	stats, err := d.ScheduleRunStats(s.ID)
	if err != nil {
		t.Fatalf("ScheduleRunStats: %v", err)
	}
	if stats.RunCount != 1 || stats.LastRunAt == nil {
		t.Fatalf("run_count 应为 1 且有 last_run_at: %+v", stats)
	}
	items, err := d.ListScheduleHistory(s.ID)
	if err != nil || len(items) != 3 {
		t.Fatalf("ListScheduleHistory: n=%d err=%v", len(items), err)
	}
	if items[0].Action != "error" {
		t.Fatalf("历史应按 id DESC 返回: %+v", items[0])
	}
	var taskID *int64
	for _, item := range items {
		if item.TaskID != nil {
			taskID = item.TaskID
		}
	}
	if taskID == nil || *taskID != 42 {
		t.Fatalf("task 级历史应带 task_id=42: %+v", items)
	}
}

func TestTaskScheduleTaskBindingAndCreateWithSchedule(t *testing.T) {
	d := scheduleTestDB(t)

	// 非立即启动：任务落库即暂停，等待第一个窗口
	task, err := d.CreateTaskWithOptions("A7 计划绑定任务", "目标", TaskCreateOptions{
		Schedule: &TaskScheduleInput{Name: "A7 建任务计划", ScheduleType: "weekly", Weekdays: []int{1}, StartTime: "09:00"},
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions(schedule): %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	if !task.Paused || task.QueueMode != "bootstrap" {
		t.Fatalf("非立即启动任务应 paused+bootstrap: %+v", task)
	}
	paused, err := d.TaskPausedBySchedule(task.ID)
	if err != nil || !paused {
		t.Fatalf("schedule_paused 应为 true: %v %v", paused, err)
	}
	schedIDs, err := d.TaskScheduleTasks(task.ID)
	if err != nil || len(schedIDs) != 1 {
		t.Fatalf("TaskScheduleTasks: %v %v", schedIDs, err)
	}
	got, err := d.GetTaskSchedule(schedIDs[0])
	if err != nil || len(got.TaskIDs) != 1 || got.TaskIDs[0] != task.ID {
		t.Fatalf("计划应绑定本任务: %+v err=%v", got, err)
	}
	// 绑定行的 paused_by_schedule 标记
	if err := d.SetSchedulePaused(schedIDs[0], task.ID, true); err != nil {
		t.Fatalf("SetSchedulePaused: %v", err)
	}
	var flag bool
	if err := d.QueryRow(`SELECT paused_by_schedule FROM task_schedule_tasks WHERE schedule_id=$1 AND task_id=$2`, schedIDs[0], task.ID).Scan(&flag); err != nil || !flag {
		t.Fatalf("paused_by_schedule 标记不回环: %v %v", flag, err)
	}

	// 立即启动：不暂停
	task2, err := d.CreateTaskWithOptions("A7 立即启动任务", "目标", TaskCreateOptions{
		Schedule: &TaskScheduleInput{Name: "A7 立即计划", ScheduleType: "once", RunDate: "2099-01-01", StartTime: "09:00", StartImmediately: true},
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions(immediate): %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task2.ID) })
	if task2.Paused {
		t.Fatal("立即启动任务不应暂停")
	}
	if paused2, _ := d.TaskPausedBySchedule(task2.ID); paused2 {
		t.Fatal("立即启动任务 schedule_paused 应为 false")
	}

	// 非法输入随任务创建路径被拒（复用 normalize 校验）
	if _, err := d.CreateTaskWithOptions("A7 非法计划", "目标", TaskCreateOptions{
		Schedule: &TaskScheduleInput{Name: "", ScheduleType: "weekly", StartTime: "09:00"},
	}); err == nil {
		t.Fatal("空名称计划应被拒绝")
	}

	// 计划删除级联清绑定
	if err := d.DeleteTaskSchedule(schedIDs[0]); err != nil {
		t.Fatalf("DeleteTaskSchedule: %v", err)
	}
	ids, err := d.TaskScheduleTasks(task.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("删除计划后绑定应级联清空: %v %v", ids, err)
	}
}

func TestValidateTaskScheduleInputTable(t *testing.T) {
	cases := []struct {
		name    string
		in      TaskScheduleInput
		wantErr string
	}{
		{"空名称", TaskScheduleInput{ScheduleType: "weekly", StartTime: "09:00"}, "计划名称不能为空"},
		{"坏时区", TaskScheduleInput{Name: "x", TimezoneMode: "utc", ScheduleType: "weekly", StartTime: "09:00"}, "时区必须选择北京时间或系统当前时区"},
		{"坏规则", TaskScheduleInput{Name: "x", ScheduleType: "daily", StartTime: "09:00"}, "规则必须选择一次性或按周"},
		{"坏开始时间", TaskScheduleInput{Name: "x", ScheduleType: "weekly", Weekdays: []int{1}, StartTime: "9点"}, "开始时间格式不正确，请使用 HH:MM"},
		{"按周无星期", TaskScheduleInput{Name: "x", ScheduleType: "weekly", StartTime: "09:00"}, "按周计划至少选择一天"},
		{"重复星期", TaskScheduleInput{Name: "x", ScheduleType: "weekly", Weekdays: []int{1, 1}, StartTime: "09:00"}, "星期选择必须为周一至周日且不能重复"},
		{"once 无日期", TaskScheduleInput{Name: "x", ScheduleType: "once", StartTime: "09:00"}, "开始日期格式不正确"},
		{"截止早于开始", TaskScheduleInput{Name: "x", ScheduleType: "once", RunDate: "2099-01-02", EndDate: "2099-01-01", StartTime: "09:00"}, "截止日期不能早于开始日期"},
		{"同日结束早于开始", TaskScheduleInput{Name: "x", ScheduleType: "once", RunDate: "2099-01-01", EndDate: "2099-01-01", StartTime: "18:00", EndTime: "09:00"}, "同一天的结束时间必须晚于开始时间"},
		{"任务 id 重复", TaskScheduleInput{Name: "x", ScheduleType: "weekly", Weekdays: []int{1}, StartTime: "09:00", TaskIDs: []int64{3, 3}}, "绑定任务编号无效或重复"},
	}
	for _, tc := range cases {
		if err := ValidateTaskScheduleInput(tc.in); err == nil || err.Error() != tc.wantErr {
			t.Fatalf("%s: err=%v, want %q", tc.name, err, tc.wantErr)
		}
	}
	// 24:00 是合法结束时间；once+EndDate+24:00 同日不算早于开始
	if err := ValidateTaskScheduleInput(TaskScheduleInput{Name: "x", ScheduleType: "once", RunDate: "2099-01-01", EndDate: "2099-01-01", StartTime: "18:00", EndTime: "24:00"}); err != nil {
		t.Fatalf("24:00 应合法: %v", err)
	}
}
