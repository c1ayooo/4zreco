package db

import (
	"strings"
	"testing"
)

// U4（上游 v0.4.60）：内置任务 Playbook 种子——4 个模板入库、幂等、可检索。
func TestSeedBuiltinTaskPlaybooks(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	// 干净批次：清掉本测试的历史种子标记与同名模板（共享测试库）。
	_, _ = d.Exec(`DELETE FROM task_templates WHERE name LIKE 'Playbook：%'`)
	_, _ = d.Exec(`DELETE FROM settings WHERE key='task_playbooks_v1'`)

	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	list, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, tpl := range list {
		if strings.HasPrefix(tpl.Name, "Playbook：") {
			count++
			if !strings.Contains(tpl.Goal, "【内部工作流") && !strings.Contains(tpl.Goal, "【工作流") && !strings.Contains(tpl.Goal, "【产出】") {
				t.Errorf("playbook %q 缺少结构化工作流段", tpl.Name)
			}
		}
	}
	if count != len(builtinTaskPlaybooks) {
		t.Fatalf("playbook 数=%d want %d", count, len(builtinTaskPlaybooks))
	}
	// 幂等：再跑一次不新增、不报错（flag 已 done）。
	before := len(list)
	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	after, _ := d.ListTaskTemplates()
	if len(after) != before {
		t.Fatalf("重复种子不应新增：before=%d after=%d", before, len(after))
	}
}
