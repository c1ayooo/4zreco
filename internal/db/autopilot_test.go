package db

import (
	"fmt"
	"testing"
	"time"
)

// TestAutopilotFlagAndDeadlineExtend：autopilot 开关持久化 + ExtendTaskDeadline 的
// 守卫语义（autopilot 开/关、次数上限、只在原 deadline 基础上追加）。DSN 门控。
func TestAutopilotFlagAndDeadlineExtend(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("autopilot 开关与 deadline 延长", "目标X", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	if _, err := es.AddIntent(map[string]any{"summary": " autopilot 测试方向"}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}

	// 默认关闭；打开后 scanTask 读回。
	if got, _ := d.GetTask(tk.ID); got == nil || got.Autopilot {
		t.Fatalf("新任务 autopilot 应默认 false: %+v", got)
	}
	if err := d.SetTaskAutopilot(tk.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTask(tk.ID)
	if err != nil || got == nil || !got.Autopilot {
		t.Fatalf("autopilot 未持久化: %+v err=%v", got, err)
	}
	if got.AutopilotExtensions != 0 {
		t.Fatalf("初始延长次数应 0: %d", got.AutopilotExtensions)
	}

	// deadline 伸展前提：任务 running + 已盖章 deadline。走 admission 同款置位。
	if err := d.SetPaused(tk.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE tasks SET status='running', deadline_at=now() + interval '30 minutes' WHERE id=$1`, tk.ID); err != nil {
		t.Fatal(err)
	}

	// 未开 autopilot（这里已开）先验证关闸路径：关掉后 Extend 不生效。
	if err := d.SetTaskAutopilot(tk.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := d.ExtendTaskDeadline(tk.ID, 900, 2); err != nil || ok {
		t.Fatalf("autopilot 关闭时延长应被拒: ok=%v err=%v", ok, err)
	}
	if err := d.SetTaskAutopilot(tk.ID, true); err != nil {
		t.Fatal(err)
	}

	dl1, used1, ok1, err := d.ExtendTaskDeadline(tk.ID, 900, 2)
	if err != nil || !ok1 {
		t.Fatalf("第一次延长失败: ok=%v err=%v", ok1, err)
	}
	if used1 != 1 {
		t.Fatalf("used=%d want 1", used1)
	}
	got, _ = d.GetTask(tk.ID)
	if got == nil || got.AutopilotExtensions != 1 {
		t.Fatalf("延长计数未落库: %+v", got)
	}
	if base := time.Now().Add(30 * time.Minute); !dl1.After(base.Add(14 * time.Minute)) {
		// GREATEST(deadline_at, now()) + 900s ≈ 原 deadline + 15min，不能被重置成 now+15
		t.Fatalf("延长后的 deadline 应≈原 deadline+15min: %v", dl1)
	}

	// 第二次成功；第三次超上限被拒。
	dl2, used2, ok2, err := d.ExtendTaskDeadline(tk.ID, 900, 2)
	if err != nil || !ok2 || used2 != 2 {
		t.Fatalf("第二次延长: ok=%v used=%d err=%v", ok2, used2, err)
	}
	if !dl2.After(dl1) {
		t.Fatalf("第二次延长应继续后移: %v -> %v", dl1, dl2)
	}
	if _, _, ok3, _ := d.ExtendTaskDeadline(tk.ID, 900, 2); ok3 {
		t.Fatal("超出上限的延长应被拒")
	}

	// 事件留痕 + 任务删除级联清理。
	if err := d.InsertAutopilotEvent(fmt.Sprintf("%d", tk.ID), "stall_nudge", "测试留痕"); err != nil {
		t.Fatal(err)
	}
	evs, err := d.ListAutopilotEvents(fmt.Sprintf("%d", tk.ID), 10)
	if err != nil || len(evs) != 1 || evs[0].Kind != "stall_nudge" {
		t.Fatalf("事件留痕异常: %+v err=%v", evs, err)
	}
	if err := d.DeleteTask(tk.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM autopilot_events WHERE task_id=$1`, tk.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("任务删除后事件应级联清理，剩 %d 条", n)
	}
}

// TestAutopilotTaskStatesScan：看门狗扫描只回「running + autopilot + 未暂停未排队」
// 的任务，并带出 goal/intent/进度计数。
func TestAutopilotTaskStatesScan(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("autopilot 看门狗扫描", "目标Y", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "看门狗扫描方向"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	goalID, err := es.AddGoal(map[string]any{"text": "看门狗扫描目标"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_ = d.DeleteTask(tk.ID)
	}
	defer cleanup()

	if err := d.SetTaskAutopilot(tk.ID, true); err != nil {
		t.Fatal(err)
	}

	// created 状态不应出现。
	states, err := d.AutopilotTaskStates()
	if err != nil {
		t.Fatal(err)
	}
	if _, hit := states[fmt.Sprintf("%d", tk.ID)]; hit {
		t.Fatal("created 状态的任务不应进看门狗扫描")
	}

	if _, err := d.Exec(`UPDATE tasks SET status='running' WHERE id=$1`, tk.ID); err != nil {
		t.Fatal(err)
	}
	states, err = d.AutopilotTaskStates()
	if err != nil {
		t.Fatal(err)
	}
	st, hit := states[fmt.Sprintf("%d", tk.ID)]
	if !hit {
		t.Fatal("running + autopilot 任务应进扫描")
	}
	if st.OpenIntents != 1 || st.RunningIntents != 0 {
		t.Fatalf("open=%d running=%d want 1/0", st.OpenIntents, st.RunningIntents)
	}
	if st.GoalsTotal != 1 || st.GoalsMet != 0 {
		t.Fatalf("goals total=%d met=%d want 1/0", st.GoalsTotal, st.GoalsMet)
	}
	if !st.Unmet() {
		t.Fatal("0/1 目标应判 Unmet")
	}

	// 暂停后退出扫描。
	if err := d.SetPaused(tk.ID, true); err != nil {
		t.Fatal(err)
	}
	states, _ = d.AutopilotTaskStates()
	if _, hit := states[fmt.Sprintf("%d", tk.ID)]; hit {
		t.Fatal("暂停任务不应进扫描")
	}
	if err := d.SetPaused(tk.ID, false); err != nil {
		t.Fatal(err)
	}

	// 意图被领取（open→running）与目标 met 的计数口径。
	if ok, _ := es.ClaimIntent(intentID, "work#1"); !ok {
		t.Fatal("claim 失败")
	}
	if err := es.SetNodeState(goalID, "met"); err != nil {
		t.Fatal(err)
	}
	states, _ = d.AutopilotTaskStates()
	st, hit = states[fmt.Sprintf("%d", tk.ID)]
	if !hit {
		t.Fatal("running 任务应仍在扫描")
	}
	if st.RunningIntents != 1 || st.OpenIntents != 0 {
		t.Fatalf("claim 后 open=%d running=%d want 0/1", st.OpenIntents, st.RunningIntents)
	}
	if st.GoalsMet != 1 || st.Unmet() {
		t.Fatalf("met=%d total=%d 应全部达成", st.GoalsMet, st.GoalsTotal)
	}

	// 关掉 autopilot 即退出扫描（运行态镜像现查的持久层半边）。
	if err := d.SetTaskAutopilot(tk.ID, false); err != nil {
		t.Fatal(err)
	}
	states, _ = d.AutopilotTaskStates()
	if _, hit := states[fmt.Sprintf("%d", tk.ID)]; hit {
		t.Fatal("关闭 autopilot 后不应进扫描")
	}
}

// TestCountActiveIntents：派发节流的积压口径（open+running）。
func TestCountActiveIntents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("count active intents", "目标Z", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(tk.ID) }()
	es := d.Exploration(tk.ExplorationID)
	i1, err := es.AddIntent(map[string]any{"summary": "计数方向一"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	i2, err := es.AddIntent(map[string]any{"summary": "计数方向二"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := es.CountActiveIntents(); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v want 2", n, err)
	}
	if ok, _ := es.ClaimIntent(i1, "work#1"); !ok {
		t.Fatal("claim 失败")
	}
	if n, _ := es.CountActiveIntents(); n != 2 {
		t.Fatalf("claim 后仍应 2（open+running）: %d", n)
	}
	if err := es.SetNodeState(i2, "done"); err != nil {
		t.Fatal(err)
	}
	if n, _ := es.CountActiveIntents(); n != 1 {
		t.Fatalf("终态后应 1: %d", n)
	}
}

// TestOpenIntentHygiene：积压治理视图——排太久的 open 意图入列，短龄且无告警的不入列。
func TestOpenIntentHygiene(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("open intent hygiene", "目标W", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(tk.ID) }()
	es := d.Exploration(tk.ExplorationID)
	oldID, err := es.AddIntent(map[string]any{"summary": "排队很久的方向"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.AddIntent(map[string]any{"summary": "刚派的新方向"}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}
	// 把第一条的 created_at 拨到 3 小时前（> 2h 阈值）。
	if _, err := d.Exec(`UPDATE exploration_nodes SET created_at = now() - interval '3 hours' WHERE id=$1`, oldID); err != nil {
		t.Fatal(err)
	}
	items, err := es.OpenIntentHygiene(2*time.Hour, 40)
	if err != nil {
		t.Fatal(err)
	}
	var found *IntentHygiene
	for i := range items {
		if items[i].ID == oldID {
			found = &items[i]
		}
	}
	if found == nil {
		t.Fatalf("3 小时老意图应入列: %+v", items)
	}
	if found.AgeHours < 2 {
		t.Fatalf("AgeHours=%.2f 应 >2", found.AgeHours)
	}
	for _, it := range items {
		if it.ID == oldID {
			continue
		}
		if it.AgeHours >= 2 {
			t.Fatalf("新意图不应入列: #%d %.2fh", it.ID, it.AgeHours)
		}
	}
	// 退役后退出治理视图（retire_intent 的持久层半边）。
	if _, err := es.SoftDeleteIntent(oldID, "planner 退役：测试"); err != nil {
		t.Fatal(err)
	}
	items, _ = es.OpenIntentHygiene(2*time.Hour, 40)
	for _, it := range items {
		if it.ID == oldID {
			t.Fatal("已退役意图不应再入治理视图")
		}
	}
}
