package agent

// 全量验证证据审查（移植自 Pojun agent/tools_evidence.go，v0.4.71 全量危害验证
// 协议批次）。
//
// 目标不是「有没有写证据」，而是「证据能不能支撑危害结论、能不能通过 SRC 验收」。
// 这里用纯文本规则做一次可解释的清单审查（13 项检查 + 分数 + src_ready + missing
// 补齐建议）：上报时可通过 evidence_check 主动复核，也可传 finding_node_id 读已
// 登记漏洞节点的证据。
//
// 规则只做提示与评分，不阻断入库——阻断会把真实漏洞挡在门外；但对 high/critical
// 缺少核心证据的，会明确列出缺口，供自动续跳意图带着缺口去定向补齐。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// EvidenceCheck 是单项证据检查结果。
type EvidenceCheck struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	OK       bool   `json:"ok"`
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

// EvidenceReview 是一次证据审查的汇总（分数 + 各项 + 缺口 + 建议）。
type EvidenceReview struct {
	Score       int             `json:"score"`
	SRCReady    bool            `json:"src_ready"`
	Checks      []EvidenceCheck `json:"checks"`
	Missing     []string        `json:"missing,omitempty"`
	Suggestions []string        `json:"suggestions,omitempty"`
}

var (
	evRawRequestRE = regexp.MustCompile(`(?mi)^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+`)
	evResponseRE   = regexp.MustCompile(`(?i)(HTTP/\d(?:\.\d)?|Status:\s*\d{3}|状态码\s*[:：]?\s*\d{3}|"status"\s*:\s*\d{2,3})`)
	evURLRE        = regexp.MustCompile(`https?://[^\s"'<>]+`)
	evIPRE         = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	evTimeRE       = regexp.MustCompile(`(20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}:\d{2}:\d{2})`)
	evMaskRE       = regexp.MustCompile(`(\*{3,}|\[redacted\]|已脱敏|打码|masked|x{4,})`)
	evCountRE      = regexp.MustCompile(`(?i)(?:共|总计|合计|total|count|rows?|records?)?\s*(\d{2,})\s*(?:条|行|个|records?|rows?|users?|orders?|items?)`)
	evCmdExecRE    = regexp.MustCompile(`(?i)(uid=\d+|whoami|hostname|/etc/passwd|nt authority\\system|root@|administrator|命令执行回显|id\s*[:=]\s*\d+)`)
)

func evHasAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func evCountSignal(s string) (int, bool) {
	m := evCountRE.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ReviewEvidence 对一段漏洞证据做 SRC 完整性审查（纯函数，evidence_check 工具与
// report_finding 回执共用）。severity 不区分大小写；vulnclass 用于判断该类别必须
// 证明什么（数据读取 / 写操作 / 权限 / 命令执行）。
func ReviewEvidence(severity, vulnclass, evidence string) EvidenceReview {
	sev := strings.ToLower(strings.TrimSpace(severity))
	vc := strings.ToLower(strings.TrimSpace(vulnclass))
	text := strings.TrimSpace(evidence)
	lower := strings.ToLower(text)

	rawReq := evRawRequestRE.MatchString(text) || strings.Contains(lower, "curl ")
	resp := evResponseRE.MatchString(text)
	identity := evHasAny(lower, "cookie:", "authorization:", "token", "session", "账号", "用户名", "uid=", "role", "身份", "登录态")
	repro := evHasAny(lower, "curl ", "sqlmap", "nuclei", "python ", "python3 ", "复现步骤", "复现命令")
	if !repro {
		repro = regexp.MustCompile(`(?m)^\s*\d+[.)、]\s*`).MatchString(text)
	}
	target := evURLRE.MatchString(text) || evIPRE.MatchString(text) || evHasAny(lower, "目标", "host", "域名")
	stamp := evTimeRE.MatchString(text)
	noMask := !evMaskRE.MatchString(text)
	artifact := regexp.MustCompile(`artifact:\d+|save_evidence|sha256`).MatchString(lower)
	traffic := evHasAny(lower, "traffic_refs", "traffic_id", "baseline", "proof", "流量 #", "流量#")

	num, hasCount := evCountSignal(lower)
	fullExport := evHasAny(lower, "全量", "完整导出", "分页取全", "所有记录", "总数", "total", "导出接口")
	dataVolume := (hasCount && num >= 10) || fullExport
	sensitive := evHasAny(lower, "身份证", "手机号", "手机", "邮箱", "地址", "订单", "余额", "密码", "token", "密钥", "银行卡", "email", "phone", "id_card", "password", "secret", "user_id", "用户数据")
	impactRead := dataVolume && sensitive
	writeTest := evHasAny(lower, "写测试", "写入", "新增", "创建", "修改", "更新", "删除", "回读", "before", "after", "测试对象", "测试订单", "create", "update", "delete", "insert")
	writeReadback := evHasAny(lower, "回读", "再次查询", "readback", "read back", "对比一致", "一致", "before", "after")
	permission := evHasAny(lower, "越权", "水平", "垂直", "未授权", "匿名", "普通用户", "低权", "管理员", "admin", "idor", "权限矩阵", "身份矩阵", "两个账号", "两个身份", "不同用户")
	cmdExec := evCmdExecRE.MatchString(lower)
	impact := impactRead || (writeTest && writeReadback) || permission || cmdExec

	mk := func(id, label string, ok bool, required bool, detail string) EvidenceCheck {
		return EvidenceCheck{ID: id, Label: label, OK: ok, Required: required, Detail: detail}
	}
	// 13 项清单：required 与 vulnclass 挂钩——越权类必查权限矩阵、注入/泄露类必查
	// 数据量、上传/逻辑类必查写测试；critical/high 另有身份、影响证明两个必过项。
	checks := []EvidenceCheck{
		mk("raw_request", "原始请求/命令（方法/路径/头或实际命令）", rawReq || cmdExec, true, "贴出实际请求行与关键请求头，或实际执行的命令；没有原文无法复核"),
		mk("response", "原始响应/命令输出", resp || cmdExec, true, "贴出实际响应状态码与关键正文，或命令回显；不能只写“返回成功”"),
		mk("identity", "身份与权限上下文", identity, sev == "critical" || sev == "high", "写明使用哪个账号/角色/Cookie/token，越权类必须有两个身份"),
		mk("reproduction", "可复现命令或分步步骤", repro, true, "给出 curl/sqlmap/nuclei 命令或编号步骤，别人能照着复现"),
		mk("target", "目标地址/主机", target, true, "写明完整 URL、Host 或 IP"),
		mk("timestamp", "验证时间", stamp, false, "记录验证时间，便于复测与证据时效判断"),
		mk("no_mask", "数据未脱敏（保留原值）", noMask, true, "证据中不得出现 ***、[redacted]、已脱敏、打码；第一方 SRC 递交需原值"),
		mk("impact", "实际危害证明（读/写/权限/命令）", impact, sev == "critical" || sev == "high", "至少证明一种真实影响：读到数据、写测试回读、权限差异或命令回显"),
		mk("data_volume", "数据量与敏感字段", impactRead, strings.Contains(vc, "泄露") || strings.Contains(vc, "越权") || strings.Contains(vc, "注入") || strings.Contains(vc, "数据") || strings.Contains(vc, "idor"), "至少 10 条去重记录或全量/总数，并列出敏感字段；只取 1 条不算证明"),
		mk("write_test", "写操作测试（自建对象+回读+清理）", writeTest && writeReadback, strings.Contains(vc, "上传") || strings.Contains(vc, "写入") || strings.Contains(vc, "逻辑") || strings.Contains(vc, "支付") || strings.Contains(vc, "篡改"), "写测试只能改自建测试对象，记录修改前后值并回读；不得改生产业务数据"),
		mk("permission", "权限矩阵/越权对照", permission, strings.Contains(vc, "越权") || strings.Contains(vc, "未授权") || strings.Contains(vc, "权限") || strings.Contains(vc, "idor"), "列出匿名/普通用户/管理员等身份对同一接口的响应差异"),
		mk("artifact", "证据附件/哈希", artifact, false, "大数据集/截图用 save_evidence 登记，记录 sha256 与 artifact:<id>"),
		mk("traffic", "流量证据绑定（baseline/proof）", traffic, false, "HTTP 漏洞建议用 traffic_refs 绑定 baseline 与 proof 两条真实流量"),
	}

	requiredCount, passedRequired := 0, 0
	missing := make([]string, 0, 4)
	suggestions := make([]string, 0, 4)
	for _, c := range checks {
		if c.Required {
			requiredCount++
			if c.OK {
				passedRequired++
			} else {
				missing = append(missing, c.Label)
			}
		}
	}
	score := 0
	if len(checks) > 0 {
		passed := 0
		for _, c := range checks {
			if c.OK {
				passed++
			}
		}
		score = passed * 100 / len(checks)
	}
	// 必过项全过且总分不低于 55 才算 SRC-ready。低危也要有原始请求/响应、
	// 复现步骤与目标地址；high/critical 另有身份、影响证明等必过项。
	srcReady := requiredCount > 0 && passedRequired == requiredCount && score >= 55
	if !noMask {
		suggestions = append(suggestions, "把打码/脱敏字段恢复为原值；第一方 SRC 递交需要完整证据，脱敏会被判定为证据不足。")
	}
	if !impactRead && !cmdExec && !permission && !(writeTest && writeReadback) {
		suggestions = append(suggestions, "补一次真实影响验证：读取 ≥10 条或全量数据、写测试回读、两个身份权限对照，或命令执行回显。")
	}
	if !artifact && (impactRead || writeTest) {
		suggestions = append(suggestions, "把完整数据集/样本落盘并 save_evidence 登记（kind=data，note 写记录数与字段），报告中引用 artifact:<id>。")
	}
	if !traffic && (rawReq || resp) {
		suggestions = append(suggestions, "用 traffic_refs 绑定 baseline（正常请求）与 proof（利用请求），便于复核。")
	}
	return EvidenceReview{Score: score, SRCReady: srcReady, Checks: checks, Missing: missing, Suggestions: suggestions}
}

// evidenceCheck 是给 agent 主动复核用的只读工具：可直接审查一段证据文本，
// 也可传 finding_node_id 读取已登记漏洞节点的 payload（summary/evidence.poc）。
// 无任务上下文的 ToolSet（工具目录构造期/无图会话）仍可传 evidence 纯文本使用。
func (t *ToolSet) evidenceCheck() actool.CoreTool {
	return readTool("evidence_check",
		"审查漏洞证据是否能支撑危害结论并通过 SRC 验收（原始请求/响应、复现命令、身份、数据量/敏感字段、权限或写测试、是否脱敏、附件/流量绑定）。上报前先跑一次，按 missing 补齐；high/critical 不建议在缺核心项时结束。",
		obj(map[string]any{
			"evidence":        str("待审查的证据文本（可选；与 finding_node_id 二选一或同时给，同时给时以 evidence 为准）"),
			"finding_node_id": idp("可选：已登记漏洞的探索节点 ID；读取其 payload 里的 summary/evidence.poc/vulnclass/severity"),
			"severity":        str("critical|high|medium|low（可选，默认从节点读取或 medium）"),
			"vulnclass":       str("漏洞类别（可选，用于判断该类必须补哪几项）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Evidence      string `json:"evidence"`
				FindingNodeID int64  `json:"finding_node_id"`
				Severity      string `json:"severity"`
				VulnClass     string `json:"vulnclass"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			source := "input"
			if strings.TrimSpace(a.Evidence) == "" && a.FindingNodeID > 0 {
				if t.ts == nil {
					return actool.Errorf("当前 agent 没有任务探索图上下文；请直接把证据文本传给 evidence 参数"), nil
				}
				n, err := t.ts.GetNode(a.FindingNodeID)
				if err != nil || n == nil {
					return actool.Errorf("finding_node_id 不存在或不可读"), nil
				}
				// finding 节点 payload 形状（db.RecordFinding 同源）：
				// {vulnclass, name, severity, summary, evidence:{by, poc}}。
				var p struct {
					VulnClass string `json:"vulnclass"`
					Name      string `json:"name"`
					Severity  string `json:"severity"`
					Summary   string `json:"summary"`
					Evidence  struct {
						PoC string `json:"poc"`
					} `json:"evidence"`
				}
				_ = json.Unmarshal(n.Payload, &p)
				if a.VulnClass == "" {
					a.VulnClass = p.VulnClass
				}
				if a.Severity == "" {
					a.Severity = p.Severity
				}
				if strings.TrimSpace(a.Evidence) == "" {
					a.Evidence = strings.TrimSpace(p.Summary + "\n" + p.Evidence.PoC)
				}
				source = fmt.Sprintf("finding_node:%d", a.FindingNodeID)
			}
			if strings.TrimSpace(a.Evidence) == "" {
				return actool.Errorf("需要 evidence 文本或 finding_node_id"), nil
			}
			if a.Severity == "" {
				a.Severity = "medium"
			}
			review := ReviewEvidence(a.Severity, a.VulnClass, a.Evidence)
			return jsonResult(map[string]any{"source": source, "review": review})
		})
}
