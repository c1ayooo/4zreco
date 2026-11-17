package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

// TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec 钉住收尾判据的
// 登记顺序（上游 0.4.81 #27）：cancelExec 取消的就是本轮 ectx，若先取消再检查
// ectx.Err()，goal_met 收尾在 met 轮永远登记不上（任务只能等心跳/超时结束）。
func TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t1"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "goal_met" {
		t.Fatalf("挂起收尾 reason=%q，期望 goal_met（登记被 cancelExec 遮掉了）", reason)
	}
	if ectx.Err() == nil {
		t.Fatal("判定目标达成后在跑 worker 未被取消")
	}
	if code, _, _, ok := agent.AbortReason(ectx); !ok || code != "goal_met" {
		t.Fatalf("取消原因 code=%q ok=%v，期望 goal_met", code, ok)
	}
}

// TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel 本轮已被外部取消
// （pause / 收尾硬取消）时不得登记收尾：否则 pause 期间攒下的 goal_met 会在
// resume 后立刻把任务收掉。
func TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t2"}
	ectx := e.execContextFor(context.Background(), task.ID)
	e.Pause(task.ID, agent.AbortPausedByUser)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("外部取消后仍登记了收尾 %q", reason)
	}
}

// TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError 半成功的轮不能用来
// 收尾：Plan 可能在 prove_goal 置位 GoalMet 之后才因 LLM/传输错误返回非 nil err，
// 此时既不该登记收尾，也不该杀 worker。
func TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t3"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, err: errors.New("llm down")}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("规划出错却登记了收尾 %q", reason)
	}
	if ectx.Err() != nil {
		t.Fatal("规划出错却取消了在跑 worker")
	}
}

// TestSettleTerminalStatus 覆盖收尾终态的真值表（上游 0.4.81 #28）。
//
// 关键格是「有目标、全部 met、reason=timeout、终局轮未再次证明」——旧实现把它
// 判成 timeout（目标全部达成却记为未完成），新实现以数据库为准判 done。
//
// 与上游唯一的语义差异：4zreco 的 goal_met 允许「整体声称」收官（未 prove 的目标
// 打 unverified 留痕、state 仍 open，v0.3.19 ARTEX 语义），故 reason=goal_met 一律
// done——上游的 partial-goal-met 格在本实现中同样落 done。
func TestSettleTerminalStatus(t *testing.T) {
	cases := []struct {
		name          string
		metGoals      int
		totalGoals    int
		reason        string
		finalRoundMet bool
		want          string
	}{
		// 无目标：沿用旧语义，由终局轮判定。
		{"goalless-timeout-not-proven", 0, 0, "timeout", false, "timeout"},
		{"goalless-timeout-proven", 0, 0, "timeout", true, "done"},
		{"goalless-goal-met", 0, 0, "goal_met", true, "done"},
		{"goalless-auto-idle", 0, 0, "auto_idle", false, "done"},
		{"goalless-no-result-not-proven", 0, 0, "no_result", false, "timeout"},

		// 有目标且全部 met：数据库即事实，终局轮不再有否决权。
		{"all-met-timeout-not-proven", 5, 5, "timeout", false, "done"},
		{"all-met-timeout-proven", 5, 5, "timeout", true, "done"},
		{"all-met-auto-idle", 5, 5, "auto_idle", false, "done"},
		{"all-met-auto-rounds", 5, 5, "auto_rounds", false, "done"},
		{"all-met-goal-met", 5, 5, "goal_met", true, "done"},

		// 有未达成目标：一律 timeout，终局轮的 met 不能翻案。
		{"partial-timeout-not-proven", 2, 5, "timeout", false, "timeout"},
		{"partial-timeout-proven", 2, 5, "timeout", true, "timeout"},
		{"partial-auto-rounds", 4, 5, "auto_rounds", false, "timeout"},

		// 目标存在但一个都没达成（含 abandoned 口径：非 met 一律按未达成计）。
		{"none-met-timeout-proven", 0, 3, "timeout", true, "timeout"},
		{"none-met-auto-coverage", 0, 3, "auto_coverage", false, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := settleTerminalStatus(tc.metGoals, tc.totalGoals, tc.reason, tc.finalRoundMet); got != tc.want {
				t.Fatalf("settleTerminalStatus(%d, %d, %q, %v) = %q, want %q",
					tc.metGoals, tc.totalGoals, tc.reason, tc.finalRoundMet, got, tc.want)
			}
		})
	}
}

// TestMaybePendingSettleRevokesGoalMetOnNewGoal 钉住 goal_met 收尾前的数据库复核
// （上游 0.4.81 #27）：planner 判定「目标达成」依据的是**当时**的目标集，而新增
// 目标先落库、再由 NotifyGoal 追加内存触发，两者之间存在窗口。若这期间多了一个
// 目标，按旧目标集收尾会把刚加进来的目标连同任务一起终结。
//
// 4zreco 与上游的差异：goal_met 允许「整体声称」收官（未 prove 目标仍 open），所以
// 复核判据是「目标集是否扩大」而不是「仍有 open 目标」——本测试里目标集从 1 变 2。
func TestMaybePendingSettleRevokesGoalMetOnNewGoal(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("settle recheck", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	if task.Store == nil {
		t.Fatal("task.Store 为 nil")
	}
	if _, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "goal at judgment time"}, 0, "open", "test", nil); err != nil {
		t.Fatal(err)
	}

	task.requestGoalMetSettle("planner 判定目标达成")
	// 判定登记之后、消费之前：用户新增了一个目标（落库在先、触发在后）。
	if _, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "goal added in the window"}, 0, "open", "test", nil); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(m)
	if e.maybePendingSettle(context.Background(), task) {
		t.Fatal("目标集已扩大却执行了收尾")
	}
	// 复核不通过要撤销挂起收尾，交回规划轮重判；否则下一次唤醒会再试一次。
	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("复核撤销后仍留有挂起收尾 %q", reason)
	}
}

// TestMaybePendingSettleConsumesGoalMetWithUnprovenGoals 是上一条的正向对照，同时
// 钉住 4zreco 的 goal_met「整体声称」语义（v0.3.19 ARTEX）：未逐条 prove 的目标
// 打 unverified 留痕、state 仍是 open——只要目标集没有扩大，挂起的 goal_met 收尾
// 必须被消费并落 done，不能因为「仍有 open 目标」被误撤销（那是上游的判据）。
func TestMaybePendingSettleConsumesGoalMetWithUnprovenGoals(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("settle unproven claim", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	if task.Store == nil {
		t.Fatal("task.Store 为 nil")
	}
	id, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "claimed done, unverified"}, 0, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 goal_met 工具的落痕：目标 state 仍 open，只打 unverified 标记。
	if err := task.Store.MarkGoalUnverified(id, "整体收官声称"); err != nil {
		t.Fatal(err)
	}

	task.requestGoalMetSettle("planner 判定目标达成")

	e := NewEngine(m)
	if !e.maybePendingSettle(context.Background(), task) {
		t.Fatal("目标集未扩大（仅 unverified 留痕）却未执行收尾")
	}
	if got := task.lifecycleSnapshot().Status; got != "done" {
		t.Fatalf("终态=%q，期望 done", got)
	}
}

// TestResumeClearsDeadlineCacheAndAutopilotBaseline 钉住暂停恢复的引擎侧清理
// （上游 0.4.80 #22）：Resume 后进程内 deadline 缓存必须清掉——ApplyTaskAdmission
// 已把暂停时长折算回 deadline_at，留着旧值会在顺延后的 deadline 之前提前收尾；
// 自主推进看门狗基线同理，暂停时长不应被算成「无进展」误触发 stall nudge。
func TestResumeClearsDeadlineCacheAndAutopilotBaseline(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t9", notify: make(chan struct{}, 1)}
	e.deadline.Store(task.ID, int64(1234567890))
	e.autoTrack.Store(task.ID, &autopilotTrack{lastProgressAt: time.Now().Add(-time.Hour)})

	e.Resume(task)

	if _, ok := e.deadline.Load(task.ID); ok {
		t.Fatal("Resume 后 deadline 缓存未清除，恢复后会按旧 deadline 提前收尾")
	}
	if _, ok := e.autoTrack.Load(task.ID); ok {
		t.Fatal("Resume 后 autopilot 看门狗基线未清除，暂停时长会被误判为停滞")
	}
}

// TestMaybePendingSettleConsumesGoalMetWhenAllGoalsMet 补「全部 prove」正向对照：
// 全部目标 met 时 goal_met 收尾应当被消费并落 done——这是「目标达成后立即收尾」
// 链路的终点。
func TestMaybePendingSettleConsumesGoalMetWhenAllGoalsMet(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	task, err := m.CreateTask("settle all met", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	id, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "done"}, 0, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetNodeState(id, "met"); err != nil {
		t.Fatal(err)
	}

	task.requestGoalMetSettle("planner 判定目标达成")

	e := NewEngine(m)
	if !e.maybePendingSettle(context.Background(), task) {
		t.Fatal("全部目标已 met 却未执行收尾")
	}
	if got := task.lifecycleSnapshot().Status; got != "done" {
		t.Fatalf("终态=%q，期望 done", got)
	}
}
