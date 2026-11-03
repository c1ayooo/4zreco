package agent

import (
	"encoding/json"
	"reflect"
	"testing"
)

// CWE→方法论 skill 联动（M1 闭环）：relatedSkillsFor 按命中 CWE 去重返回
// skill 名单；未注入索引或无命中时返回 nil——工具输出里不出现 related_skills，
// 联动是纯增量，不能让既有形状变化。
func TestRelatedSkillsFor(t *testing.T) {
	// 未注入索引：恒为 nil。
	if got := relatedSkillsFor([]string{"CWE-89"}); got != nil {
		t.Fatalf("未注入索引时应返回 nil，got=%v", got)
	}

	SetCweSkillIndex(map[string][]string{
		"CWE-89":  {"inj-skill"},
		"CWE-862": {"authz-skill"},
		"CWE-639": {"authz-skill"},
	})
	t.Cleanup(func() { SetCweSkillIndex(nil) })

	// 单 CWE 命中。
	if got := relatedSkillsFor([]string{"CWE-89"}); !reflect.DeepEqual(got, []string{"inj-skill"}) {
		t.Fatalf("CWE-89 → %v", got)
	}
	// 多 CWE 去重：两个 CWE 指向同一 skill 时只出现一次；大小写不敏感。
	got := relatedSkillsFor([]string{"CWE-862", "cwe-639"})
	if !reflect.DeepEqual(got, []string{"authz-skill"}) {
		t.Fatalf("CWE-862+cwe-639 → %v，应为去重后的 [authz-skill]", got)
	}
	// 无命中返回 nil。
	if got := relatedSkillsFor([]string{"CWE-999"}); got != nil {
		t.Fatalf("无命中应返回 nil，got=%v", got)
	}
}

// 联动字段必须是「无则缺失」：不带 related_skills 的 get_vuln 输出形状与
// 既有调用方（提示词里写的字段名）保持一致。
func TestVulnDetailWithSkillsOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(vulnDetailWithSkills{VulnDetail: nil})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["related_skills"]; ok {
		t.Fatal("无联动时 related_skills 不应出现在输出里")
	}
}
