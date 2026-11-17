package intercept

import (
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// 规则级适用工具（上游 0.4.81 PR #26）：同一段文字出现在写文件工具的正文里是数据，
// 出现在 shell 工具的命令字段里才是命令。加这层范围之前，tool_input 对整段入参
// JSON 做匹配，两者无法区分——一条针对命令的规则会被报告正文触发。
func TestRuleMatchesToolScope(t *testing.T) {
	mk := func(scope []string) db.InterceptRule {
		return db.InterceptRule{
			ID: 1, Name: "导出类命令", Enabled: true, Priority: 100,
			MatchTarget: "tool_input", MatchType: "string",
			Pattern: "example-dump", Action: "deny",
			ToolScope: scope,
		}
	}
	cases := []struct {
		name     string
		scope    []string
		toolName string
		input    string
		want     bool
	}{
		{"限定 shell，shell 命中", []string{"Bash"}, "Bash", `{"command":"example-dump --all"}`, true},
		{"限定 shell，写文件不命中", []string{"Bash"}, "Write", `{"file_path":"r.md","content":"未使用 example-dump"}`, false},
		{"限定 shell，编辑不命中", []string{"Bash"}, "Edit", `{"file_path":"r.md","old_string":"example-dump"}`, false},
		{"空范围向后兼容：写文件仍命中", nil, "Write", `{"content":"example-dump"}`, true},
		{"空范围向后兼容：shell 也命中", []string{}, "Bash", `{"command":"example-dump"}`, true},
		{"多工具清单命中其一", []string{"Bash", "shell_open"}, "shell_open", `{"command":"example-dump"}`, true},
		{"多工具清单外的工具不命中", []string{"Bash", "shell_open"}, "Write", `{"content":"example-dump"}`, false},
		{"工具名大小写精确", []string{"Bash"}, "bash", `{"command":"example-dump"}`, false},
		{"未知工具名不 panic", []string{"Bash"}, "no-such-tool", `{}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ic := New(nil)
			ic.SetRulesInMemory([]db.InterceptRule{mk(c.scope)})
			if _, hit := ic.Match(c.toolName, []byte(c.input)); hit != c.want {
				t.Fatalf("命中=%v，期望 %v", hit, c.want)
			}
		})
	}
}

// 被工具范围排除的高优先级规则不能短路低优先级的同工具规则：
// 一条只针对 shell 的 allow 不该顺带豁免写文件工具。
func TestToolScopeDoesNotShortCircuitOtherRules(t *testing.T) {
	ic := New(nil)
	ic.SetRulesInMemory([]db.InterceptRule{
		{ID: 1, Name: "shell 专用放行", Enabled: true, Priority: 100,
			MatchTarget: "tool_input", MatchType: "string", Pattern: "example-dump",
			Action: "allow", ToolScope: []string{"Bash"}},
		{ID: 2, Name: "全局禁止", Enabled: true, Priority: 10,
			MatchTarget: "tool_input", MatchType: "string", Pattern: "example-dump",
			Action: "deny"},
	})
	d, hit := ic.Match("Write", []byte(`{"content":"example-dump"}`))
	if !hit || d.Action != "deny" {
		t.Fatalf("写文件应落到全局禁止规则，实际 hit=%v action=%q", hit, d.Action)
	}
	// shell 命中高优先级那条 allow，语义不变。
	d2, hit2 := ic.Match("Bash", []byte(`{"command":"example-dump"}`))
	if !hit2 || d2.Action != "allow" {
		t.Fatalf("shell 应命中高优先级 allow，实际 hit=%v action=%q", hit2, d2.Action)
	}
}

// tool_name 目标同样受工具范围约束（引擎不因 match_target 而区别对待）。
func TestToolScopeAppliesToToolNameTarget(t *testing.T) {
	ic := New(nil)
	ic.SetRulesInMemory([]db.InterceptRule{{
		ID: 1, Name: "仅 shell", Enabled: true, Priority: 10,
		MatchTarget: "tool_name", MatchType: "string", Pattern: "Bash",
		Action: "deny", ToolScope: []string{"Bash"},
	}})
	if _, hit := ic.Match("Bash", []byte(`{}`)); !hit {
		t.Fatal("Bash 应命中")
	}
	// 即便 toolName 是 "Bash"，只要不在范围里就不命中——本用例验证过滤先于匹配。
	ic2 := New(nil)
	ic2.SetRulesInMemory([]db.InterceptRule{{
		ID: 1, Name: "仅 shell", Enabled: true, Priority: 10,
		MatchTarget: "tool_name", MatchType: "string", Pattern: "Bash",
		Action: "deny", ToolScope: []string{"shell_open"},
	}})
	if _, hit := ic2.Match("Bash", []byte(`{}`)); hit {
		t.Fatal("不在 tool_scope 里的工具不应命中")
	}
}
