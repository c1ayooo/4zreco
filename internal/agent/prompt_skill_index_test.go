package agent

import (
	"strings"
	"testing"

)

// U4（上游 v0.4.60）：SkillIndexBlock 挂点——非空时追加进渲染后的 system
// prompt；nil/空串行为与从前一致（不追加）。无 DB 依赖。
func TestRenderSystemAppendsSkillIndexBlock(t *testing.T) {
	const def = "worker body {{.DataDir}}"
	out := renderSystem("worker", def, WorkerVars{DataDir: "/d"})
	if !strings.HasPrefix(out, "worker body /d") {
		t.Fatalf("基础渲染被破坏: %q", out)
	}
	SkillIndexBlock = func(string) string { return "【技能速查】vuln-hunting" }
	defer func() { SkillIndexBlock = nil }()
	out = renderSystem("worker", def, WorkerVars{DataDir: "/d"})
	if !strings.Contains(out, "worker body /d") || !strings.Contains(out, "【技能速查】vuln-hunting") {
		t.Fatalf("速查块未追加进 system prompt: %q", out)
	}
	// 返回空串 = 不加块。
	SkillIndexBlock = func(string) string { return "" }
	out = renderSystem("worker", def, WorkerVars{DataDir: "/d"})
	if strings.Contains(out, "【技能速查") {
		t.Fatalf("空块不应追加: %q", out)
	}
}

// planner 提示词含独立复现规则（critical/high 必配 machine oracle）。
func TestPlannerPromptHasReproductionRule(t *testing.T) {
	for _, want := range []string{"独立复现", "只做复现、不扩大", "降级"} {
		if !strings.Contains(plannerDefaultTmpl, want) {
			t.Errorf("planner 提示词缺独立复现规则关键段 %q", want)
		}
	}
}
