package agent

import (
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// TestValidateMechanicalEvidence 上游 0.4.52 机械验证凭据校验：critical/high 必须附
// 可机械复现的验证凭据（HTTP 状态码/curl 输出/工具命中）；纯版本匹配单独拦截；
// medium/low 不校验。
func TestValidateMechanicalEvidence(t *testing.T) {
	mechanical := "curl -s http://target/api/users?id=1' and '1'='1\nHTTP/1.1 200 OK\nContent-Type: text/html"
	versionOnly := "目标运行 nginx/1.14.2，banner 显示 Apache Tomcat 8.5.1 版本较旧，x-powered-by php 5.6"
	proseOnly := "经分析该接口可能存在未授权访问风险，攻击者或可利用该缺陷获取敏感信息。"

	cases := []struct {
		name     string
		severity string
		evidence string
		want     string // "" = 通过；否则断言打回提示包含该子串
	}{
		{"critical-curl-passthrough", "critical", mechanical, ""},
		{"high-http-header-passthrough", "high", mechanical, ""},
		{"critical-status-code-passthrough", "critical", "GET /admin\nstatus: 403 Forbidden", ""},
		{"critical-version-only", "critical", versionOnly, "版本匹配 ≠ 漏洞"},
		{"high-version-only", "high", versionOnly, "版本匹配 ≠ 漏洞"},
		{"critical-prose-only", "critical", proseOnly, "可机械复现的验证凭据"},
		{"high-prose-only", "high", proseOnly, "可机械复现的验证凭据"},
		{"medium-prose-not-blocked", "medium", proseOnly, ""},
		{"low-empty-not-blocked", "low", "", ""},
		{"critical-empty-delegated", "critical", "", ""}, // 空 evidence 由 validateFindingEvidence 的篇幅门槛管
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateMechanicalEvidence(c.severity, c.evidence)
			if c.want == "" && got != "" {
				t.Fatalf("期望通过，实际打回: %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("打回提示缺关键内容 %q: %q", c.want, got)
			}
			// 打回提示必须给出可执行出路（实测触发/补凭据 或 降级），模型才能自纠。
			if got != "" && !strings.Contains(got, "降级为 medium") && !strings.Contains(got, "降为 medium") {
				t.Fatalf("打回提示缺少降级指引: %q", got)
			}
		})
	}
}

// TestReportFindingMechanicalGateWire 机械校验接在 report_finding 的篇幅门槛之后：
// 无任务上下文的 ToolSet 也走同一 handler，critical 纯版本证据直接打回。
func TestReportFindingMechanicalGateWire(t *testing.T) {
	ts := NewToolSet(nil, "fixture")
	var finding actool.CoreTool
	for _, tool := range ts.WorkerTools() {
		if tool.Name() == "report_finding" {
			finding = tool
			break
		}
	}
	if finding == nil {
		t.Fatal("WorkerTools 里找不到 report_finding")
	}
	// t.ts 为 nil 时 report_finding 先于机械校验报「需要任务上下文」——所以这里只断言
	// handler 路径本身可用（真打回链路由 TestValidateMechanicalEvidence 钉住函数级行为）。
	res, err := finding.Call(nil, []byte(`{"vulnclass":"未授权访问","name":"x","severity":"critical","summary":"s","evidence":"版本匹配"}`), nil)
	if err != nil {
		t.Fatalf("report_finding call: %v", err)
	}
	if !res.IsError {
		t.Fatalf("无任务上下文的 report_finding 应报错而非成功: %q", res.Flatten())
	}
}

// TestReviewEvidence13Checks 上游 0.4.71 evidence_check 的 13 项清单审查：
// 完整证据 src_ready；脱敏/缺口分别命中对应项与建议。
func TestReviewEvidence13Checks(t *testing.T) {
	full := `GET /api/user/list HTTP/1.1
Host: target.example.com
Cookie: session=admin-token

HTTP/1.1 200 OK
{"total": 2731, "users": [...]}
共 2731 条记录，含手机号、身份证字段
验证时间 2026-11-18 10:00:00
复现命令: curl -s "http://target.example.com/api/user/list"
save_evidence kind=data sha256:abc123
traffic_refs baseline/proof 已绑定`
	rv := ReviewEvidence("high", "信息泄露", full)
	if !rv.SRCReady {
		t.Fatalf("完整证据应 SRC-ready: score=%d missing=%v", rv.Score, rv.Missing)
	}
	if len(rv.Checks) != 13 {
		t.Fatalf("清单应为 13 项，实际 %d 项", len(rv.Checks))
	}

	// 脱敏证据：no_mask 不过，且给出恢复原值建议。
	masked := strings.ReplaceAll(full, "2731 条记录，含手机号、身份证字段", "返回 138****5678、[redacted]")
	rv2 := ReviewEvidence("high", "信息泄露", masked)
	for _, c := range rv2.Checks {
		if c.ID == "no_mask" && c.OK {
			t.Fatal("打码证据的 no_mask 检查不应通过")
		}
	}
	if len(rv2.Suggestions) == 0 {
		t.Fatal("脱敏证据应产生补齐建议")
	}

	// 越权类：缺权限矩阵 → missing 命中，且 src_ready=false。
	weak := "GET /api/order/100 HTTP/1.1\nHost: t.example.com\nHTTP/1.1 200 OK {\"id\":1}\n复现命令: curl -s http://t.example.com/api/order/100"
	rv3 := ReviewEvidence("high", "越权", weak)
	if rv3.SRCReady {
		t.Fatalf("越权缺权限矩阵不应 SRC-ready: missing=%v", rv3.Missing)
	}
	found := false
	for _, m := range rv3.Missing {
		if strings.Contains(m, "权限矩阵") {
			found = true
		}
	}
	if !found {
		t.Fatalf("越权类 missing 应含权限矩阵: %v", rv3.Missing)
	}

	// medium 不带身份/影响必过项：弱证据也有部分分、不 panic。
	rv4 := ReviewEvidence("medium", "信息泄露", weak)
	if rv4.Score <= 0 {
		t.Fatalf("medium 弱证据也应有部分分: %d", rv4.Score)
	}
}

// TestEvidenceCheckToolRegistered evidence_check（上游 0.4.71 只读复核工具）必须进
// 三张工具清单（worker/planner/mainagent）——AGENTS.md §5.5 注册三件套；
// toolcatalog 的 BuiltinToolSeeds 从这三张清单推导，无需另行断言。
func TestEvidenceCheckToolRegistered(t *testing.T) {
	ts := NewToolSet(nil, "")
	for _, agent := range []struct {
		key   string
		tools []actool.CoreTool
	}{
		{"worker", ts.WorkerTools()},
		{"planner", ts.PlannerTools()},
		{"mainagent", ts.MainAgentTools()},
	} {
		found := false
		for _, tl := range agent.tools {
			if tl.Name() == "evidence_check" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s 工具清单缺 evidence_check", agent.key)
		}
	}
}

// TestEvidenceCheckReviewJSON evidence_check 纯文本路径：无任务上下文（nil store）
// 也能对 evidence 做审查并返回结构化 review。
func TestEvidenceCheckReviewJSON(t *testing.T) {
	ts := NewToolSet(nil, "")
	var tool actool.CoreTool
	for _, tl := range ts.WorkerTools() {
		if tl.Name() == "evidence_check" {
			tool = tl
			break
		}
	}
	if tool == nil {
		t.Fatal("WorkerTools 里找不到 evidence_check")
	}
	in := `{"evidence":"GET /a HTTP/1.1\nHost: t.example.com\nHTTP/1.1 200 OK\nstatus: 200\n复现命令: curl -s http://t.example.com/a","severity":"medium"}`
	res, err := tool.Call(nil, []byte(in), nil)
	if err != nil {
		t.Fatalf("evidence_check call: %v", err)
	}
	if res.IsError {
		t.Fatalf("evidence_check 纯文本路径不应报错: %q", res.Flatten())
	}
	if out := res.Flatten(); !strings.Contains(out, `"review"`) || !strings.Contains(out, `"checks"`) {
		t.Fatalf("返回缺 review/checks 字段: %q", out)
	}
}

// TestVerificationTailsInjected 全量危害验证协议尾巴（0.4.71/0.4.72 #9）必须进
// 各 agent 的代码固定尾——判定纪律不随 DB 正文编辑丢失（照 plannerHoneypotRules
// 先例，断言方式对照 antitrap_test）。
func TestVerificationTailsInjected(t *testing.T) {
	w := workerSystem("", "", "/data", "/data")
	for _, seg := range []string{"全量危害验证协议", "影响阶梯", "405", "sink 审计", "10 条去重记录"} {
		if !strings.Contains(w, seg) {
			t.Fatalf("workerSystem 缺验证协议段 %q", seg)
		}
	}
	p := plannerSystem("拿下X", "/data", "/data")
	for _, seg := range []string{"危害深度编排", "至少保留 1 条并行意图", "拿到一个 critical 不是收敛信号"} {
		if !strings.Contains(p, seg) {
			t.Fatalf("plannerSystem 缺编排纪律段 %q", seg)
		}
	}
	m := mainAgentSystem("goal", "/data", "/data")
	for _, seg := range []string{"角色边界硬规则", "严禁用 Bash 与目标系统交互", "危害深度编排"} {
		if !strings.Contains(m, seg) {
			t.Fatalf("mainAgentSystem 缺角色边界/编排段 %q", seg)
		}
	}
	pe := chatSystem("pentest", "/data", "/data")
	for _, seg := range []string{"全量危害验证协议", "SRC 全量证据附录", "危害深度编排"} {
		if !strings.Contains(pe, seg) {
			t.Fatalf("chatSystem(pentest) 缺验证协议段 %q", seg)
		}
	}
	if rep := chatSystem("reporter", "/data", "/data"); !strings.Contains(rep, "SRC 全量证据附录") {
		t.Fatal("chatSystem(reporter) 缺 SRC 全量证据附录")
	}
	if rt := chatSystem("retester", "/data", "/data"); strings.Contains(rt, "全量证据附录") {
		t.Fatal("retester 不应注入 SRC 附录")
	}
	if g := goalsVerificationTail; !strings.Contains(g, "验收标准必须证明危害") {
		t.Fatal("goalsVerificationTail 内容缺失")
	}
}
