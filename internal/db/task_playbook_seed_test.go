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
	// 共享库纪律：**不删**同名模板（种子语义就是「用户删除/修改不复活」，测试
	// 不能反过来清掉用户数据）。只清本测试自己的批次标记重放种子行为，随后
	// 校验「每个内置名都存在」而非「恰好 N 条」。
	_, _ = d.Exec(`DELETE FROM settings WHERE key='task_playbooks_v1'`)

	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	list, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*TaskTemplate{}
	for _, tpl := range list {
		if strings.HasPrefix(tpl.Name, "Playbook：") {
			byName[tpl.Name] = tpl
		}
	}
	for _, pb := range builtinTaskPlaybooks {
		tpl, ok := byName[pb.name]
		if !ok {
			t.Errorf("playbook %q 未入库", pb.name)
			continue
		}
		if !strings.Contains(tpl.Goal, "【内部工作流") && !strings.Contains(tpl.Goal, "【工作流") && !strings.Contains(tpl.Goal, "【产出】") {
			t.Errorf("playbook %q 缺少结构化工作流段", tpl.Name)
		}
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
