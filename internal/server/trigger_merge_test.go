package server

import (
	"strings"
	"testing"
)

// A long task goal repeated per event was the dominant bloat. These tests pin the
// fix: the task-context header (description + goal) is rendered ONCE per task, no
// matter how many same-task fires are merged.

const longGoal = "拿到题目 f2-05 的受保护 flag 并通过 submit_flag 提交；本题密文已高度收敛，flag 只能由二进制内嵌数据派生……" // 代表那段几千字的继承事实

func sameTaskFires(n int) []triggeredRun {
	items := make([]triggeredRun, n)
	for i := range items {
		items[i] = triggeredRun{
			agentKey: "tec_benchmark", taskID: 72, taskDesc: "f2-05 逆向", taskGoal: longGoal,
			message: "【本次由工具调用触发】\n工具: submit_flag\n入参: {...}\n返回: {correct:false}", mergeable: true,
		}
	}
	return items
}

func TestMergeAllRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeAllRuns(sameTaskFires(39))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a merged-all run, got %d", got)
	}
	if strings.Count(out.message, "── 触发 ") < 1 || !strings.Contains(out.message, "触发 39") {
		t.Fatalf("all 39 event bodies should be present: %q", out.message)
	}
	// A merged run embeds its header inline, so finalTriggerMessage must not re-add it.
	if out.taskDesc != "" || out.taskGoal != "" {
		t.Fatalf("merged run must clear taskDesc/taskGoal to avoid a duplicate header")
	}
	if finalTriggerMessage(out) != out.message {
		t.Fatalf("finalTriggerMessage must not prepend another header for a merged run")
	}
}

func TestMergeAllRunsGroupsInterleavedTasks(t *testing.T) {
	// Fires from two tasks arriving interleaved (A,B,A,B) must still carry each
	// task's context exactly once — grouping, not per-event repetition.
	mk := func(id int64, goal string) triggeredRun {
		return triggeredRun{agentKey: "a", taskID: id, taskDesc: "d", taskGoal: goal, message: "body", mergeable: true}
	}
	out := mergeAllRuns([]triggeredRun{mk(1, "GOAL_A"), mk(2, "GOAL_B"), mk(1, "GOAL_A"), mk(2, "GOAL_B")})
	if got := strings.Count(out.message, "GOAL_A"); got != 1 {
		t.Fatalf("task #1 goal should appear once despite interleaving, got %d", got)
	}
	if got := strings.Count(out.message, "GOAL_B"); got != 1 {
		t.Fatalf("task #2 goal should appear once despite interleaving, got %d", got)
	}
	if !strings.Contains(out.message, "共 2 个任务") {
		t.Fatalf("header should report 2 tasks: %q", out.message)
	}
	if got := strings.Count(out.message, "── 触发 "); got != 4 {
		t.Fatalf("all 4 event bodies should be present, got %d", got)
	}
}

func TestMergeTriggeredRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeTriggeredRuns(sameTaskFires(5))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a by-task merge, got %d", got)
	}
}

func TestFinalTriggerMessageSingleFirePrependsHeaderOnce(t *testing.T) {
	item := sameTaskFires(1)[0]
	msg := finalTriggerMessage(item)
	if got := strings.Count(msg, longGoal); got != 1 {
		t.Fatalf("single fire should carry the task goal exactly once, got %d", got)
	}
	if !strings.HasPrefix(msg, "【任务 #72") {
		t.Fatalf("single fire should be prefixed with the task-context header: %q", msg)
	}
}

func TestTaskContextHeaderEmptyForIntervalFire(t *testing.T) {
	if h := taskContextHeader(0, "", ""); h != "" {
		t.Fatalf("interval/none trigger (no task) must produce no header, got %q", h)
	}
	// An interval fire's message must pass through untouched.
	item := triggeredRun{message: "定时触发正文"}
	if finalTriggerMessage(item) != "定时触发正文" {
		t.Fatalf("interval fire message must pass through unchanged")
	}
}

func TestTaskContextHeaderTruncatesLongGoal(t *testing.T) {
	huge := strings.Repeat("很", 5000)
	h := taskContextHeader(72, "d", huge)
	if len([]rune(h)) > 800 { // 200 desc + 500 goal + 截断标记/装饰，远小于 5000
		t.Fatalf("header should be bounded even for a huge goal, got %d runes", len([]rune(h)))
	}
}

// C1 历史整理 fire 带 transaction 预留的 conversationID。reporter 的兜底触发
// 策略是 serial+all（readTriggerBehavior 缺省 mergeMode="all"），队头是普通
// finding fire、整理 fire 排在后方时，nextTriggerRun 必须在第一条预创建会话处
// 截断合并——否则 conversationID 被折掉，预留的 conversation 与
// finding_case_review_runs 行永久停在 queued，任务被 ErrFindingCaseReviewBusy
// 卡死到重启。
func reviewFire(convID int64) triggeredRun {
	return triggeredRun{
		agentKey: "reporter", title: "漏洞整理 · task#7", message: "人工选择整理（只读原始记录）",
		taskID: 7, conversationID: convID,
	}
}

func findingFire() triggeredRun {
	return triggeredRun{
		agentKey: "reporter", taskID: 7, taskDesc: "d", taskGoal: "g",
		message: "【本次由任务发现 finding 触发】", mergeable: true,
	}
}

func nextRunFromQueue(t *testing.T, cfg triggerBehavior, items ...triggeredRun) (triggeredRun, []triggeredRun) {
	t.Helper()
	s := &Server{triggerQ: map[string][]triggeredRun{"reporter": items}}
	out := s.nextTriggerRun("reporter", cfg)
	return out, s.triggerQ["reporter"]
}

func TestNextTriggerRunTruncatesAllMergeAtReviewConversation(t *testing.T) {
	cfg := triggerBehavior{runMode: "serial", mergeMode: "all", maxParallel: 5}
	// 队头普通 fire + 整理 fire 排在后方：只合并截断点之前的部分，整理 fire 原样保留在队头。
	out, rest := nextRunFromQueue(t, cfg, findingFire(), findingFire(), reviewFire(55), findingFire())
	if out.conversationID != 0 {
		t.Fatalf("merged prefix must not carry a review conversation id: %+v", out)
	}
	if !strings.Contains(out.message, "── 触发 2") || strings.Contains(out.message, "人工选择整理") {
		t.Fatalf("merged run must contain exactly the two normal fires: %q", out.message)
	}
	if len(rest) != 2 || rest[0].conversationID != 55 || rest[1].conversationID != 0 {
		t.Fatalf("review fire must stay queued intact after the merged prefix: %+v", rest)
	}
	// 下一轮：整理 fire 单独弹出，conversationID 原样保留。
	out, rest = nextRunFromQueue(t, cfg, rest...)
	if out.conversationID != 55 || len(rest) != 1 || rest[0].conversationID != 0 {
		t.Fatalf("review fire must pop alone with its conversation id: out=%+v rest=%+v", out, rest)
	}
}

func TestNextTriggerRunPopsReviewConversationAtHeadUnmerged(t *testing.T) {
	cfg := triggerBehavior{runMode: "serial", mergeMode: "all", maxParallel: 5}
	out, rest := nextRunFromQueue(t, cfg, reviewFire(66), findingFire(), findingFire())
	if out.conversationID != 66 || len(rest) != 2 {
		t.Fatalf("review fire at head must pop alone: out=%+v rest=%+v", out, rest)
	}
	if strings.Contains(out.message, "── 触发") {
		t.Fatalf("review fire must not be merged: %q", out.message)
	}
}

func TestNextTriggerRunByTaskNeverFoldsReviewConversation(t *testing.T) {
	cfg := triggerBehavior{runMode: "serial", mergeMode: "by_task", maxParallel: 5}
	// by_task 只合并 mergeable 且同任务的项：两个普通 finding 并成组，整理 fire
	// （mergeable=false）原样留存在队列里。
	out, rest := nextRunFromQueue(t, cfg, findingFire(), reviewFire(77), findingFire())
	if out.conversationID != 0 || !strings.Contains(out.message, "── 触发 2") {
		t.Fatalf("by_task merge should fold only the same-task mergeable fires: %+v", out)
	}
	if len(rest) != 1 || rest[0].conversationID != 77 || rest[0].mergeable {
		t.Fatalf("review fire must survive by_task grouping untouched: %+v", rest)
	}
}

func TestNextTriggerRunParallelModePopsReviewConversationInOrder(t *testing.T) {
	cfg := triggerBehavior{runMode: "parallel", mergeMode: "none", maxParallel: 5}
	out, rest := nextRunFromQueue(t, cfg, findingFire(), reviewFire(88))
	if out.conversationID != 0 || len(rest) != 1 || rest[0].conversationID != 88 {
		t.Fatalf("parallel mode pops one at a time, review fire stays intact: out=%+v rest=%+v", out, rest)
	}
}
