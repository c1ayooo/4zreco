package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

func callAssess(t *testing.T, body string) (string, bool) {
	t.Helper()
	res, err := (&ToolSet{}).assessNucleiHit().Call(context.Background(), json.RawMessage(body), nil)
	if err != nil {
		t.Fatalf("工具返回 Go error: %v", err)
	}
	return res.Flatten(), res.IsError
}

// 强证据：模板 word 匹配 + 响应正文 + 提取到证据 → confirmed。
func TestAssessNucleiHitConfirmedViaTemplatePath(t *testing.T) {
	setupPocTree(t) // 复用 tools_pocparse_test.go 的临时模板树
	out, isErr := callAssess(t, `{"path":"http/cves/spring.yaml","type":"http","status_code":200,`+
		`"response":"<html>JNDI lookup triggered</html>","extracted":"/tmp/x"}`)
	if isErr {
		t.Fatalf("不应失败: %s", out)
	}
	// 模板名含 "RCE" → 上游类目表按 cmdi 命中（deserialization 只认 log4j/jndi 等词）
	for _, want := range []string{`"verdict":"confirmed"`, `"class":"cmdi"`, `"needs_manual_review":false`, `"template_id":"CVE-2022-22965-spring4shell"`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺 %s：%s", want, out)
		}
	}
}

// 弱证据：只给 template_id+name，无模板画像、无响应 → needs_review。
func TestAssessNucleiHitNeedsReviewWithoutEvidence(t *testing.T) {
	SetNucleiTemplatesDir("")
	out, isErr := callAssess(t, `{"template_id":"CVE-2024-9999","name":"SQL injection probe","type":"http","status_code":200}`)
	if isErr {
		t.Fatalf("不应失败: %s", out)
	}
	if !strings.Contains(out, `"verdict":"needs_review"`) || !strings.Contains(out, "响应正文") {
		t.Errorf("缺正文应判 needs_review 并说明原因：%s", out)
	}
}

func TestAssessNucleiHit5xxAndStatusOnly(t *testing.T) {
	SetNucleiTemplatesDir("")
	// 5xx
	out, _ := callAssess(t, `{"template_id":"x","name":"Some check","status_code":500,"response":"error","extracted":"a"}`)
	if !strings.Contains(out, "5xx") {
		t.Errorf("5xx 应给出服务端错误原因：%s", out)
	}
	// 仅状态码匹配的模板：走 content 给 matcher 画像
	statusOnly := "id: status-only-check\ninfo:\n  name: Status only probe\n  severity: info\nmatchers:\n  - type: status\n    status: [200]\n"
	out, _ = callAssess(t, `{"content":`+jsonQuote(statusOnly)+`,"status_code":200,"response":"ok body here"}`)
	if !strings.Contains(out, `"status_only":true`) || !strings.Contains(out, "状态码") {
		t.Errorf("仅状态码模板应被判弱证据：%s", out)
	}
}

func TestAssessNucleiHitRequiresTemplateOrID(t *testing.T) {
	SetNucleiTemplatesDir("")
	out, isErr := callAssess(t, `{"status_code":200}`)
	if !isErr || !strings.Contains(out, "至少给") {
		t.Errorf("空输入应报错，得到 isErr=%v out=%s", isErr, out)
	}
}

func TestAssessNucleiHitRegistered(t *testing.T) {
	const key = "assess_nuclei_hit"
	ts := NewToolSet(nil, "")
	has := func(tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == key {
				return true
			}
		}
		return false
	}
	if !has(ts.PlannerTools()) || !has(ts.WorkerTools()) || !has(ts.MainAgentTools()) {
		t.Error("assess_nuclei_hit 未进入三张工具清单")
	}
	bound := map[string]bool{}
	for _, s := range BuiltinToolSeeds() {
		if s.Key == key {
			for _, a := range s.Agents {
				bound[a] = true
			}
		}
	}
	for _, want := range []string{"planner", "worker", "mainagent"} {
		if !bound[want] {
			t.Errorf("内置工具目录未绑定到 %s", want)
		}
	}
}
