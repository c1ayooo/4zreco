package db

import (
	"encoding/json"
	"testing"
)

// v6 seed（强动作扫描器 zombie_weakpass / proton_secrets 的 ask 审批边界，
// AGENTS.md §5.5 P3）的三条升级路径回归——V4/V5 的缺陷教训（flag 早退吞掉
// 新规则、enabled 工具集不合并）在这批不能重演。

// 分类哨兵：v6 两条必须是 ask（强动作类转人工，不允许被顺手改成 judge/deny）。
func TestV6RulesAreAskClass(t *testing.T) {
	want := map[string]string{
		"[内置] 弱口令检测 zombie_weakpass": "ask",
		"[内置] 敏感信息扫描 proton_secrets": "ask",
	}
	seen := map[string]string{}
	for _, r := range builtinInterceptRules {
		if _, ok := want[r.name]; ok {
			seen[r.name] = r.action
			if r.seedBatch != "v6" {
				t.Errorf("规则 %q seedBatch=%q，应为 v6", r.name, r.seedBatch)
			}
			if r.target != "tool_name" {
				t.Errorf("规则 %q target=%q，应为 tool_name（按工具名整单拦，不看参数内容）", r.name, r.target)
			}
		}
	}
	for name, action := range want {
		if seen[name] != action {
			t.Errorf("规则 %q action=%q（缺条目也算失败），应为 %q", name, seen[name], action)
		}
	}
}

// 全新安装路径：batch seed 把 v6 两条落库。
func TestV6RulesLandOnFreshInstall(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if err := d.seedDefaultInterceptRulesV6(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"[内置] 弱口令检测 zombie_weakpass", "[内置] 敏感信息扫描 proton_secrets"} {
		var action string
		if err := d.QueryRow(`SELECT action FROM intercept_rules WHERE name=$1`, name).Scan(&action); err != nil {
			t.Errorf("v6 规则 %q 未落库: %v", name, err)
			continue
		}
		if action != "ask" {
			t.Errorf("v6 规则 %q action=%q，应为 ask", name, action)
		}
	}
}

// 升级路径回归（V4 教训复刻）：flag 已置 done 但规则行被删——按名补种必须把
// 规则补回来，且 enabled 工具集合并要把两个新工具名补进已保存的清单。
func TestV6RulesRepairedOnUpgrade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	const flag = "intercept_default_rules_v6_scanners"
	if err := d.SetSetting(flag, "done"); err != nil {
		t.Fatal(err)
	}
	names := []string{"[内置] 弱口令检测 zombie_weakpass", "[内置] 敏感信息扫描 proton_secrets"}
	for _, name := range names {
		if _, err := d.Exec(`DELETE FROM intercept_rules WHERE name=$1`, name); err != nil {
			t.Fatal(err)
		}
	}
	// 模拟「已保存过 enabled 工具集」的老实例：预置一份不含新工具名的清单。
	const enabledKey = "intercept_enabled_tools"
	if _, ok, _ := d.GetSetting(enabledKey); ok {
		t.Skip("实例已持久化 intercept_enabled_tools——不能在本库模拟预置值，跳过合并断言（规则补种断言不受影响）")
	}
	if err := d.SetSetting(enabledKey, `["Bash","listener_start"]`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// 测试库复用：清掉本测试写的设置，避免污染其它用例对「未保存」状态的假设。
		if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, enabledKey); err != nil {
			t.Fatalf("cleanup settings: %v", err)
		}
	}()

	if err := d.seedDefaultInterceptRulesV6(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		var action string
		if err := d.QueryRow(`SELECT action FROM intercept_rules WHERE name=$1`, name).Scan(&action); err != nil {
			t.Fatalf("flag 早退场景下 v6 规则 %q 应被按名补种: %v", name, err)
		}
		if action != "ask" {
			t.Fatalf("v6 规则 %q action=%q，应为 ask", name, action)
		}
	}
	raw, _, err := d.GetSetting(enabledKey)
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	if err := json.Unmarshal([]byte(raw), &tools); err != nil {
		t.Fatalf("enabled 工具集不是合法 JSON: %v", err)
	}
	got := map[string]bool{}
	for _, n := range tools {
		got[n] = true
	}
	for _, want := range []string{"zombie_weakpass", "proton_secrets", "Bash", "listener_start"} {
		if !got[want] {
			t.Errorf("enabled 工具集合并后缺 %q（原清单项不得丢失、新工具必须补进）: %s", want, raw)
		}
	}
}
