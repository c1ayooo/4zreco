package db

import "testing"

func findRuleByID(t *testing.T, d *DB, id int64) InterceptRule {
	t.Helper()
	rules, err := d.ListInterceptRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("规则 %d 不在列表里", id)
	return InterceptRule{}
}

// tool_scope 的读写往返：新建、替换、presence 保留、显式清空（上游 0.4.81 PR #26）。
func TestInterceptRuleToolScopeRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	mk := func(name string, scope []string, set bool) InterceptRuleInput {
		return InterceptRuleInput{
			Name: name, MatchTarget: "tool_input", MatchType: "string",
			Pattern: "example-dump", Action: "deny", Enabled: true,
			TimeoutEnabled: false, TimeoutSeconds: 60, TimeoutAction: "deny",
			ToolScope: scope, ToolScopeSet: set,
		}
	}

	r, err := d.CreateInterceptRule(mk("scope fixture empty", nil, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, r.ID) })
	if len(r.ToolScope) != 0 {
		t.Fatalf("新建空范围应读回空切片，实际 %v", r.ToolScope)
	}

	r2, err := d.UpdateInterceptRule(r.ID, mk("scope fixture set", []string{"Bash", "shell_open"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.ToolScope) != 2 || r2.ToolScope[0] != "Bash" {
		t.Fatalf("设置后应读回 [Bash shell_open]，实际 %v", r2.ToolScope)
	}

	// presence：ToolScopeSet=false 时保留库中值，旧客户端编辑不会清空范围。
	r3, err := d.UpdateInterceptRule(r.ID, mk("scope fixture keep", nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(r3.ToolScope) != 2 {
		t.Fatalf("未置位时应保留库中值，实际 %v", r3.ToolScope)
	}

	// 显式空切片 = 清空。
	r4, err := d.UpdateInterceptRule(r.ID, mk("scope fixture clear", []string{}, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(r4.ToolScope) != 0 {
		t.Fatalf("显式空切片应清空，实际 %v", r4.ToolScope)
	}
}

// 手工把列改成非数组时，读取应按「不限工具」处理——让这条规则继续可用，
// 好过整个规则集加载失败。
func TestInterceptRuleToolScopeMalformedReadsAsEmpty(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	r, err := d.CreateInterceptRule(InterceptRuleInput{
		Name: "scope fixture malformed", MatchTarget: "tool_input", MatchType: "string",
		Pattern: "example-dump", Action: "deny", Enabled: true,
		TimeoutEnabled: false, TimeoutSeconds: 60, TimeoutAction: "deny",
		ToolScope: []string{"Bash"}, ToolScopeSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, r.ID) })

	if _, err := d.Exec(`UPDATE intercept_rules SET tool_scope='"not-an-array"'::jsonb WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	got := findRuleByID(t, d, r.ID)
	if len(got.ToolScope) != 0 {
		t.Fatalf("非数组应降级为不限工具，实际 %v", got.ToolScope)
	}
}
