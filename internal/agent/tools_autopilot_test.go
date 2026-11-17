package agent

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/intercept"
)

// intentRoundAddCap：无 resolver / 非 planner / 无探索图（种子目录空壳）时一律不限。
// 有阈值但查不了积压 → 放开（capN=-1），绝不因查库失败把派发卡死。
func TestIntentRoundAddCapUnlimited(t *testing.T) {
	ts := &ToolSet{worker: "planner"}
	if capN, _, _ := ts.intentRoundAddCap(); capN != -1 {
		t.Fatalf("无 resolver 时 capN=%d want -1", capN)
	}
	ts.SetIntentQueueLimit(func() (int, int) { return 8, 3 })
	if capN, _, _ := ts.intentRoundAddCap(); capN != -1 {
		t.Fatalf("无探索图时 capN=%d want -1", capN)
	}
	w := &ToolSet{worker: "work#1"}
	w.SetIntentQueueLimit(func() (int, int) { return 8, 3 })
	if capN, _, _ := w.intentRoundAddCap(); capN != -1 {
		t.Fatalf("worker 侧不受节流: capN=%d", capN)
	}
}

// maxIntentRetirePerRun 与上游保持一致（护栏：每轮 6 条）。
func TestMaxIntentRetirePerRun(t *testing.T) {
	if maxIntentRetirePerRun != 6 {
		t.Fatalf("maxIntentRetirePerRun=%d want 6", maxIntentRetirePerRun)
	}
}

// reasonClaimsPremiseInvalid / nodeRefIDs：退役理由护栏的纯函数判定。
func TestRetireReasonGuards(t *testing.T) {
	if !reasonClaimsPremiseInvalid("该方向前提已失效") {
		t.Fatal("「前提失效」应命中")
	}
	if !reasonClaimsPremiseInvalid("目标 #123 已被证伪") {
		t.Fatal("「证伪」应命中")
	}
	if reasonClaimsPremiseInvalid("该方向资源不足，暂缓") {
		t.Fatal("普通理由不应命中")
	}
	ids := nodeRefIDs("依据 #123 与 #456/7 否定")
	if len(ids) != 2 || ids[0] != 123 || ids[1] != 456 {
		t.Fatalf("nodeRefIDs=%v want [123 456]", ids)
	}
	if got := joinNodeRefs([]int64{3, 7}); got != "#3/#7" {
		t.Fatalf("joinNodeRefs=%q", got)
	}
}

// pacingPlannerGuidance：limit>0 时是硬约束口径并带阈值；limit=0 时是建议口径。
// 两档都必须交代 retire_intent 护栏。
func TestPacingPlannerGuidance(t *testing.T) {
	hard := pacingPlannerGuidance(8, 3, 10)
	if !strings.Contains(hard, "阈值 8") || !strings.Contains(hard, "10 条") {
		t.Fatalf("硬约束块缺少阈值/积压数：\n%s", hard)
	}
	soft := pacingPlannerGuidance(0, 3, 2)
	if strings.Contains(soft, "硬约束") {
		t.Fatalf("limit=0 应为建议口径：\n%s", soft)
	}
	for _, b := range []string{hard, soft} {
		if !strings.Contains(b, "retire_intent") || !strings.Contains(b, "superseded_by") || !strings.Contains(b, "6 条") {
			t.Fatalf("节奏块必须交代退役护栏：\n%s", b)
		}
	}
}

// autopilotTail：ctx 未注入 / 开关 false → 空串；注入且 true → 原文。
func TestAutopilotTail(t *testing.T) {
	ctx := t.Context()
	if got := autopilotTail(ctx, "X"); got != "" {
		t.Fatalf("未注入时应为空串，got %q", got)
	}
	off := intercept.WithAutopilot(ctx, func() bool { return false })
	if got := autopilotTail(off, "X"); got != "" {
		t.Fatalf("开关关闭时应为空串，got %q", got)
	}
	on := intercept.WithAutopilot(ctx, func() bool { return true })
	if got := autopilotTail(on, "X"); got != "X" {
		t.Fatalf("开关开启应返回原文，got %q", got)
	}
}

// worker 提示词必须带「前提核对」硬提醒（P4-4）：意图是快照，开跑前先核对。
func TestPremiseCheckHintPresent(t *testing.T) {
	if !strings.Contains(premiseCheckHint, "核对前提") || !strings.Contains(premiseCheckHint, "record_fact") {
		t.Fatalf("premiseCheckHint 缺关键内容：\n%s", premiseCheckHint)
	}
}

// renderBacklogHygiene：nil store 与空列表都返回空串（绝不能阻塞规划轮）。
func TestRenderBacklogHygieneNil(t *testing.T) {
	if got := renderBacklogHygiene(nil); got != "" {
		t.Fatalf("nil store 应返回空串，got %q", got)
	}
}
