package db

import (
	"slices"
	"testing"
)

// insertApprovalFixture 写一条审批行（可选决定行）用于过滤/分页测试：
// 触发器只拒 UPDATE/DELETE，测试夹具的 INSERT 走 SQL 直写以精确控制
// ask_source（含旧迁移值 unknown）与决定侧维度。
func insertApprovalFixture(t *testing.T, d *DB, scope string, ruleID int64, askSource, status, reason, decisionSource string) int64 {
	t.Helper()
	var ruleIDPtr any
	if ruleID > 0 {
		ruleIDPtr = ruleID
	}
	var id int64
	if err := d.QueryRow(`INSERT INTO intercept_pending
(rule_id, conversation_id, task_id, agent_name, tool_name, tool_input, reason, ask_source, kind)
VALUES ($1,NULL,$2,'test','Bash','{}'::jsonb,$3,$4,CASE WHEN $4 IN ('rule','judge') THEN $4 ELSE 'judge' END)
RETURNING id`, ruleIDPtr, scope, reason, askSource).Scan(&id); err != nil {
		t.Fatal(err)
	}
		if status != "pending" {
			action := "deny"
			if status == "allowed" {
				action = "allow"
			}
			if _, err := d.Exec(`INSERT INTO intercept_decisions
(pending_id, decision, action, decision_reason, decided_by, decision_source, decided_at)
VALUES ($1,$2,$3,'夹具',CASE WHEN $4='human' THEN 'admin' ELSE '' END,$4,now())`, id, status, action, decisionSource); err != nil {
				t.Fatal(err)
			}
		}
	return id
}

func TestInterceptApprovalFilters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "approval-filter-" + t.Name()
	other := scope + "-other"
	t.Cleanup(func() { rewindChainHeadToSurvivors(t, d) })
	t.Cleanup(func() { purgeInterceptRows(t, d, scope); purgeInterceptRows(t, d, other) })
	rule, err := d.CreateInterceptRule("filter fixture", "tool_name", "string", "Bash", "deny", "fixture", 1, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, rule.ID) })
	filter := InterceptApprovalFilter{Status: "denied", AskSource: "model"}
	_, baseline, err := d.ListAllInterceptsPage(1, 20, filter)
	if err != nil {
		t.Fatal(err)
	}
	// 三类 ask 来源 × 四类状态；决定侧维度 human/auto 按 source 奇偶分布。
	for _, task := range []string{scope, other} {
		copies := 3
		if task != scope {
			copies = 1
		}
		for _, status := range []string{"pending", "allowed", "denied", "timeout"} {
			for _, source := range []string{"model", "rule", "unknown"} {
				for i := 0; i < copies; i++ {
					var ruleID int64
					if source == "rule" {
						ruleID = rule.ID
					}
					reason := "legacy reason"
					if source == "model" {
						reason = "[模型] fixture"
					}
					decideSource := "human"
					if i%2 == 1 {
						decideSource = "auto"
					}
					insertApprovalFixture(t, d, task, ruleID, source, status, reason, decideSource)
				}
			}
		}
	}
	// 全量基线：id 升序即插入序，视图按 (created_at DESC, id DESC) 稳定排序，
	// 夹具在同一事务/微秒内可能并列 created_at，本地按同一规则推导期望页序。
	rows, _, err := d.ListTaskInterceptsPage(scope, 1, 100, InterceptApprovalFilter{})
	if err != nil || len(rows) != 36 {
		t.Fatalf("unfiltered count=%d err=%v", len(rows), err)
	}
	cases := []struct {
		name   string
		filter InterceptApprovalFilter
		want   int
	}{
		{"all", InterceptApprovalFilter{}, 36},
	}
	for _, s := range []string{"pending", "allowed", "denied", "timeout"} {
		cases = append(cases, struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{s, InterceptApprovalFilter{Status: s}, 9})
	}
	for _, s := range []string{"model", "rule", "unknown"} {
		cases = append(cases, struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{s, InterceptApprovalFilter{AskSource: s}, 12})
	}
	// 决定来源维度与 ask 来源正交：每组合 3 份夹具按 i 交替 human/auto/human
	//（非 pending 行 27 条 → human 18、auto 9）。
	cases = append(cases,
		struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{"decide-human", InterceptApprovalFilter{DecisionSource: "human"}, 18},
		struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{"decide-auto", InterceptApprovalFilter{DecisionSource: "auto"}, 9},
		struct {
			name   string
			filter InterceptApprovalFilter
			want   int
		}{"orthogonal", InterceptApprovalFilter{Status: "denied", AskSource: "model", DecisionSource: "auto"}, 1},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := d.ListTaskInterceptsPage(scope, 1, 100, tc.filter)
			if err != nil || total != tc.want || len(got) != tc.want {
				t.Fatalf("count=%d rows=%d err=%v", total, len(got), err)
			}
			for _, r := range got {
				if r.TaskID == nil || *r.TaskID != scope || tc.filter.Status != "" && r.Status != tc.filter.Status ||
					tc.filter.AskSource != "" && r.AskSource != tc.filter.AskSource ||
					tc.filter.DecisionSource != "" && r.DecisionSource != tc.filter.DecisionSource {
					t.Fatalf("nonmatching row: %+v", r.InterceptPending)
				}
			}
		})
	}
	// 组合过滤的分页稳定性：期望序列从全量行（已是 created_at DESC, id DESC 序）
	// 本地推导，翻页必须完整且不重复。
	expected := []int64{}
	for _, r := range rows {
		if r.Status == "denied" && r.AskSource == "model" {
			expected = append(expected, r.ID)
		}
	}
	if len(expected) != 3 {
		t.Fatalf("fixture count mismatch: %d", len(expected))
	}
	var seen []int64
	for page := 1; page <= 2; page++ {
		got, total, err := d.ListTaskInterceptsPage(scope, page, 2, filter)
		if err != nil || total != 3 {
			t.Fatalf("page %d total=%d err=%v", page, total, err)
		}
		for _, r := range got {
			seen = append(seen, r.ID)
		}
	}
	if !slices.Equal(seen, expected) {
		t.Fatalf("unstable combined-filter pagination: got %v want %v", seen, expected)
	}
	got, total, err := d.ListTaskInterceptsPage(scope, 3, 2, filter)
	if err != nil || len(got) != 0 || total != 3 {
		t.Fatalf("empty page count=%d total=%d err=%v", len(got), total, err)
	}
	_, total, err = d.ListAllInterceptsPage(1, 100, filter)
	if err != nil || total != baseline+4 {
		t.Fatalf("global filter count=%d want=%d err=%v", total, baseline+4, err)
	}
	// Values must remain SQL parameters even for direct store callers.
	got, total, err = d.ListTaskInterceptsPage(scope, 1, 20, InterceptApprovalFilter{Status: "denied' OR 1=1 --"})
	if err != nil || total != 0 || len(got) != 0 {
		t.Fatalf("invalid value escaped filter: %d %v", total, err)
	}
	// A rule's persisted source survives deletion of its associated rule.
	if err = d.DeleteInterceptRule(rule.ID); err != nil {
		t.Fatal(err)
	}
	got, total, err = d.ListTaskInterceptsPage(scope, 1, 100, InterceptApprovalFilter{AskSource: "rule"})
	if err != nil || total != 12 {
		t.Fatalf("deleted-rule source count=%d err=%v", total, err)
	}
	for _, r := range got {
		if r.RuleID != nil || r.AskSource != "rule" {
			t.Fatal("deleted rule lost its source")
		}
	}
}
