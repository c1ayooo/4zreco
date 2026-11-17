package server

import (
	"strings"
	"testing"
)

// tool_scope 的归一化：去空白、去重保序、拒绝空项与超限。
// 静默丢弃非法项会让作者以为规则限定了工具，因此一律报错（上游 0.4.81 PR #26）。
func TestNormalizeInterceptToolScope(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"空列表", []string{}, []string{}, false},
		{"单工具", []string{"Bash"}, []string{"Bash"}, false},
		{"去空白", []string{"  Bash\t"}, []string{"Bash"}, false},
		{"去重保序", []string{"Bash", "shell_open", "Bash"}, []string{"Bash", "shell_open"}, false},
		{"空项报错", []string{"Bash", "   "}, nil, true},
		{"单项超长报错", []string{strings.Repeat("x", maxInterceptToolScopeLen+1)}, nil, true},
		{"超数量上限报错", make([]string, maxInterceptToolScopeItems+1), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeInterceptToolScope(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("未期望报错：%v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("长度 %d，期望 %d", len(got), len(c.want))
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("第 %d 项 %q，期望 %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// buildInterceptRuleInput 的 presence 语义：没传 ≠ 传空数组。
// 前者保留库中值（ToolScopeSet=false），后者明确清空。
func TestBuildInterceptRuleInputToolScopePresence(t *testing.T) {
	base := interceptRuleReq{
		Name: "r", MatchTarget: "tool_input", MatchType: "string",
		Pattern: "example-dump", Action: "deny",
	}

	// 未传 → 不修改。
	in, err := buildInterceptRuleInput(base)
	if err != nil {
		t.Fatalf("未传 tool_scope 不应报错：%v", err)
	}
	if in.ToolScopeSet {
		t.Fatal("未传时不应置位 ToolScopeSet")
	}

	// 显式空数组 → 清空（Set=true，scope 为空）。
	empty := []string{}
	req := base
	req.ToolScope = &empty
	in, err = buildInterceptRuleInput(req)
	if err != nil {
		t.Fatalf("空数组不应报错：%v", err)
	}
	if !in.ToolScopeSet || len(in.ToolScope) != 0 {
		t.Fatalf("空数组应置位并清空，实际 set=%v scope=%v", in.ToolScopeSet, in.ToolScope)
	}

	// 合法列表 → 置位并归一化。
	list := []string{" Bash ", "Bash"}
	req = base
	req.ToolScope = &list
	in, err = buildInterceptRuleInput(req)
	if err != nil {
		t.Fatalf("合法列表不应报错：%v", err)
	}
	if !in.ToolScopeSet || len(in.ToolScope) != 1 || in.ToolScope[0] != "Bash" {
		t.Fatalf("列表应归一化为 [Bash]，实际 %v", in.ToolScope)
	}
}

// match_target=tool_name 的规则按工具名匹配，再限定工具列表会让「作用于谁」出现
// 两个真相，必须拒绝。
func TestBuildInterceptRuleInputRejectsScopeOnToolNameTarget(t *testing.T) {
	scope := []string{"Bash"}
	req := interceptRuleReq{
		Name: "r", MatchTarget: "tool_name", MatchType: "string",
		Pattern: "Bash", Action: "deny", ToolScope: &scope,
	}
	if _, err := buildInterceptRuleInput(req); err == nil {
		t.Fatal("tool_name 目标携带非空 tool_scope 应报错")
	}

	// 空数组是允许的（等价于不限），避免把「清空范围」也拒掉。
	empty := []string{}
	req.ToolScope = &empty
	if _, err := buildInterceptRuleInput(req); err != nil {
		t.Fatalf("tool_name 目标携带空 tool_scope 应允许：%v", err)
	}
}
