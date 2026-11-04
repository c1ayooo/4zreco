package server

import "testing"

// 规则的 timeout_action 必须校验为 allow|deny。
//
// 2026-10-22 起，规则的 timeout_enabled/seconds/action **真的生效**了（规则
// 自己的声明优先于全局 judge 配置）。这让 timeout_action 从「一个存进库里的
// 字符串」变成「决定超时后放行还是拒绝的实际开关」——
// `dec.TimeoutAction == "allow"` 这个判定把任何非 "allow" 的值都当成拒绝，
// 而界面显示的却是那个乱写的字符串。用户看到「超时后 → 瞎写的值」，实际
// 行为是「拒绝」，对不上。
func TestValidateInterceptRuleReqTimeoutAction(t *testing.T) {
	base := interceptRuleReq{
		Name:           "测试规则",
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        "abc",
		Action:         "judge",
		Message:        "x",
		TimeoutEnabled: true,
		TimeoutSeconds: 90,
	}

	cases := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{"allow 合法", "allow", false},
		{"deny 合法", "deny", false},
		{"空串非法", "", true},
		{"乱写非法", "maybe", true},
		{"大小写不同非法", "ALLOW", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := base
			req.TimeoutAction = c.action
			err := validateInterceptRuleReq(req)
			if c.wantErr && err == nil {
				t.Errorf("timeout_action=%q 应报错，实际通过了", c.action)
			}
			if !c.wantErr && err != nil {
				t.Errorf("timeout_action=%q 不该报错: %v", c.action, err)
			}
		})
	}
}

// 启用超时时 timeout_seconds 必须为正数——0 会让 HandleAsk 走「60s 默认值」
// 的隐式路径，界面显示 0 而实际是 60，对不上。
func TestValidateInterceptRuleReqTimeoutSeconds(t *testing.T) {
	req := interceptRuleReq{
		Name:           "测试规则",
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        "abc",
		Action:         "judge",
		Message:        "x",
		TimeoutEnabled: true,
		TimeoutSeconds: 0,
		TimeoutAction:  "allow",
	}
	if err := validateInterceptRuleReq(req); err == nil {
		t.Error("启用超时时 timeout_seconds=0 应报错")
	}

	// 未启用超时时 seconds 为 0 是允许的（那时不生效）。
	req.TimeoutEnabled = false
	if err := validateInterceptRuleReq(req); err != nil {
		t.Errorf("未启用超时时不应因 seconds=0 报错: %v", err)
	}
}
