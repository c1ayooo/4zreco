package db

import (
	"testing"
)

// 真库验证：seed + 迁移之后，内置规则在**库里**的实际状态。
//
// 这条测试是「全新安装后规则长什么样」的直接证据——上面的分类测试断言的是
// 代码里的定义表，这条断言的是**落库后的结果**。两者不一致就说明 seed 或
// 迁移出了问题（比如参数错位把 pattern 写成了空串）。
//
// 需要真 PG（无库时随其它 db 测试一起 skip）。
func TestSeededBuiltinRulesLandInDatabase(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	rules, err := d.ListInterceptRules()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]InterceptRule{}
	for _, r := range rules {
		byName[r.Name] = r
	}

	// 每条内置规则都必须落库，且动作/超时与定义表一致。
	for _, def := range builtinInterceptRules {
		got, ok := byName[def.name]
		if !ok {
			t.Errorf("内置规则 %q 未落库", def.name)
			continue
		}
		if got.Action != def.action {
			t.Errorf("规则 %q 落库 action=%q，应为 %q", def.name, got.Action, def.action)
		}
		if got.TimeoutEnabled != def.timeoutEnabled {
			t.Errorf("规则 %q 落库 timeout_enabled=%v，应为 %v",
				def.name, got.TimeoutEnabled, def.timeoutEnabled)
		}
		if got.TimeoutSeconds != def.timeoutSeconds {
			t.Errorf("规则 %q 落库 timeout_seconds=%d，应为 %d",
				def.name, got.TimeoutSeconds, def.timeoutSeconds)
		}
		if got.TimeoutAction != def.timeoutAction {
			t.Errorf("规则 %q 落库 timeout_action=%q，应为 %q",
				def.name, got.TimeoutAction, def.timeoutAction)
		}
		// pattern 也不能是空串——参数错位那类 bug 正是把它写成空串的。
		if got.Pattern == "" {
			t.Errorf("规则 %q 落库后 pattern 为空", def.name)
		}
	}

	// 明令禁止 / 研判 / 人工确认三类在库里都要有实际条目（v0.3.87 起 ask 恢复）。
	counts := map[string]int{}
	for _, r := range rules {
		for _, def := range builtinInterceptRules {
			if def.name == r.Name {
				counts[def.class]++
				break
			}
		}
	}
	for _, class := range []string{classHardDeny, classJudge, classAsk} {
		if counts[class] == 0 {
			t.Errorf("库里没有分类 %q 的内置规则", class)
		}
	}
	t.Logf("落库的内置规则分类统计: 明令禁止=%d 研判=%d 人工确认=%d",
		counts[classHardDeny], counts[classJudge], counts[classAsk])
}


// 升级路径回归：v0.3.86 全新装（v4 flag 已置、规则已从目录移除）→ v0.3.87
// 升级——V4 seed 必须把「启停回连接收器」规则按名补种回来（Kali 实测缺陷）。
// 这里模拟该序列：置 flag → 删规则行 → 跑 V4 seed → 断言规则回来。
func TestListenerRuleRepairedOnUpgrade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	flag := "intercept_default_rules_v4_listener"
	if err := d.SetSetting(flag, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM intercept_rules WHERE name=$1`, "[内置] 启停回连接收器"); err != nil {
		t.Fatal(err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		t.Fatal(err)
	}
	var action string
	err = d.QueryRow(`SELECT action FROM intercept_rules WHERE name=$1`, "[内置] 启停回连接收器").Scan(&action)
	if err != nil {
		t.Fatalf("升级后 listener 规则应被补种: %v", err)
	}
	if action != "ask" {
		t.Fatalf("listener 规则 action=%q，应为 ask", action)
	}
}
