package agent

import (
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/c1ayooo/4zreco/db"
)

const findingIDGuidance = "\n\n**漏洞编号约定**：finding_id 是独立漏洞记录 ID；finding_node_id 是探索节点 ID。list_findings / list_task_findings / node_detail / get_task_node_detail 的 id 保留为探索节点 ID，应从同一返回的 finding_id 读取独立编号。get_finding_traffic / bind_finding_traffic 用独立 finding_id。旧 update_finding_report 的 finding_id 参数仍传 finding_node_id。不要把 report_finding 第一行的数字用于证据工具，也不要遇到编号错误后猜测其他数字。"

// evidenceDisciplineGuidance 证据分级与上报门槛（借鉴 Shannon 的 L1–L4 证据
// 阶梯与"安全机制 vs 外部约束"判定问句，v0.4.5）。放在 tool guidance 里而不是
// DB prompt：升级即生效，且不覆盖用户自己编辑过的 agent prompt。
const evidenceDisciplineGuidance = `

**证据分级与上报门槛（report_finding 之前先自查）**：
- 证据分四级：L1 接口有响应、参数被后端处理；L2 证明输入真实影响了后端逻辑（引号闭合、条件差异、报错差异）；L3 真实影响达成（数据外带、越权读到他人数据、命令执行回显、登录绕过）；L4 关键影响（全量数据、系统接管）。
- **只有达到 L3 才允许报 critical / high**；L2 最多报 medium，并在 evidence 写明利用条件；L1 不报漏洞，记进 TodoWrite 存疑项。
- 被挡住时先问一句：**挡住你的是"安全机制"（输入校验、权限判定、框架/ORM 防护、参数化查询），还是"外部运维约束"（网关、WAF、IP 白名单、组件未部署、网络隔离）？** 安全机制挡住 = 不是漏洞（顶多写加固建议），不要上报；外部约束挡住 = 可以上报，但 evidence 必须写明该前置条件，severity 按"绕过该约束后实际能拿到什么"评估并注明。
- 观察 ≠ 推断：evidence 只写你**亲眼看到的**请求/响应原文与命令输出；从响应里"推断出"的结论写进 summary 或分析，不能当作证据。
- severity 自查：给 critical / high 之前自问"最终谁受损、攻击者拿到了什么本不该拿的东西？"如果理由里出现"需要管理员配合 / 影响有限 / 本来就能看到"，那就不该评高危——**你的理由不能反驳你的定级**。critical 只留给：无权限或零前置，直接拿到敏感数据或执行命令。`

// reporterEvidenceAnnex 报告结构补充（只在 reporter 上注入，v0.4.5 起）。
const reporterEvidenceAnnex = `

**报告结构补充**：
- 在「复现步骤」之后加 ` + "`## 前置条件`" + `：复现所需账号/权限/网络位置/特殊配置；确实没有写“无”。
- 加 ` + "`## 影响证明`" + `：用编号逐条列出“已实际达成的可验证影响”（例：读出 2731 条用户数据含身份证号、接管 admin 会话），每条对应证据出处；这是严重度的依据，不写推测。
- ` + "`## 证据`" + ` 只放亲眼看到的原文（请求/响应/命令输出）；推断写进 ` + "`## 根因分析`" + `，不得混入证据。
- 小节标题只写“缺陷是什么、在哪”，**不写后果**，不用“可能存在 / 疑似 / 理论上”等措辞。
- 某些验证因环境限制未执行（无内网、无账号、组件不可达）时，在报告末尾加 ` + "`## 未验证范围`" + ` 如实说明；无法验证的部分不得写成已确认。
- 登记的 severity 与你的判断不一致时，在「影响与危害」中写“建议复核为 X 级”并说明理由，**不得擅自改写登记值**。
- 现场截图：先用 ` + "`list_artifacts`" + ` 查本任务证据附件（reporter 没有任务上下文，调用时**必须带上当前 finding_id**，例如 ` + "`list_artifacts {\"finding_id\": 123}`" + `，工具会反查所属任务）；把与本漏洞相关（finding_id 匹配）的图片用 ` + "`![具体说明](artifact:<id>)`" + ` 插进「证据」小节。图注写清“什么系统的什么页面、证明了什么”；不要引用无关图片，也不要在没有图片时编造。
- **存储桶 / 文件读取 / 上传类漏洞必须有图**：如果附件里有从 bucket/接口下载的文件样本（尤其照片），「证据」小节必须嵌入（拼图或单图）；图注写明 bucket/路径、样本数量与文件名（拼图以水印为准）。只有文字描述、没有样本图片时，在「未验证范围」里如实说明“未留存文件样本证据”，不得把“能读/能访问”写成“已获取数据”。
- **SQL 注入必须有「复测命令」小节**：给出本次 worker 实测跑通的完整 sqlmap 命令（代码块，含 --batch --flush-session、真实 URL/参数/--data/--cookie），注明预期输出（Parameter/Type/DBMS）。命令只能取自证据或执行记录，不得编造；worker 未跑 sqlmap 时，如实写“未取得 sqlmap 复测命令”，不得虚构命令。`

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		// 证据纪律与流量绑定开关无关：关闭自动绑定时上报者照样要过证据门槛。
		return out, evidenceGuidanceFor(agentKey, out)
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\n默认由报告 Agent 在编写报告前核对并绑定流量。上报者在 evidence 中保留验证命令、关键输出、已有的真实流量 ID 及其用途，供报告 Agent 对照执行记录核实；无需为绑定额外查包。兼容显式即时绑定：traffic_refs 或 evidence_hint_id 可提交已核实的引用，后者读取本任务指定 hint 的结构化引用。引用里的流量 ID 若不存在，本次上报仍会成功（漏洞不会丢），未生效的 ID 会在返回值 skipped_traffic_refs 里列出，请用 traffic_get 核实真实 ID 后用 bind_finding_traffic 补绑。TCP/无包不需要这些可选参数。返回 finding_id 与 finding_node_id 分别表示独立记录和探索节点。"
		case "add_hint", "add_task_hint":
			note = "\n交接已确认漏洞时，在对应提示的 traffic_refs 中保留已核实流量的 ID、用途、说明和顺序（单条放顶层，批量放对应 hints 元素），并在 text 中说明它证明的具体漏洞。调用方不能只交接文字而丢弃已有流量引用。未核实的候选不能作为证据传递。"
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**流量证据交接（可选）**：自动绑定默认由报告 Agent 在漏洞入库后、编写报告前完成。上报者应在 evidence 保留验证命令、关键输出、已有真实流量 ID 及其用途，任务中带 intent_id，便于报告 Agent 追溯；不必为了绑定额外查包。Auto / Planner 代为上报时不要丢弃执行者已有的引用。add_hint / add_task_hint 可用 traffic_refs 交接；显式即时绑定仍兼容 report_finding 的 traffic_refs / evidence_hint_id。TCP 或无包时正常登记，不能猜测 ID，也不能仅为补包重复探测。"
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\n平台对话没有任务上下文时，不直接调用 report_finding；通过 add_task_hint 向已有对应任务交接，由任务 Agent 登记，并用 list_task_findings 核对结果。"
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\n判定目标完成前，先完成本次已有证据的上报/交接。不要在证据交接尚未完成时仅因文字漏洞已登记就结束任务、取消 Worker；无包不要求等待或强行抓包。"
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**报告前自动关联流量（已开启）**：你负责为本次触发的漏洞核对并绑定流量，再撰写报告。先从 report_finding 返回 JSON 或 get_task_node_detail / list_task_findings 取得明确的 finding_id 与 finding_node_id。读取漏洞详情、对应意图的执行记录及已有证据清单，优先使用上报者交接的真实 ID。若本次验证为 HTTP 且流量工具可用，用 traffic_search 筛选候选，再用 traffic_get 逐条核实请求/响应确实支持该漏洞；域名和时间只用于筛选，不证明归属。将确认的证据按复现顺序用 bind_finding_traffic(finding_id, traffic_refs) 关联，选择 baseline / proof / verification / supporting 并说明用途。只能操作本次漏洞，不重复创建漏洞或重新探测目标。绑定成功后重新调用 get_finding_traffic 获取最新 version，读取所需正文，再将实际读取的 version 作为 evidence_version 传给 update_finding_report（其 finding_id 参数仍用 finding_node_id）。已有绑定不必重复追加。TCP、未采集、工具不可用或没有确切匹配时，跳过自动绑定，依据文字/命令证据正常写报告并说明原因，不得为凑齐流量而猜测。绑定失败不宣称成功；保留已有证据并在报告说明未绑定原因。"
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance + evidenceGuidanceFor(agentKey, out)
}

// evidenceGuidanceFor 按 agent 实际可见的工具集拼证据纪律（上报者）与报告结构
// 补充（reporter）。独立成函数是为了让"关闭自动流量绑定"的分支也带上纪律段。
func evidenceGuidanceFor(agentKey string, tools []actool.CoreTool) string {
	has := map[string]bool{}
	for _, t := range tools {
		has[t.Name()] = true
	}
	var g string
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		g += evidenceDisciplineGuidance
	}
	// reporter 的报告结构补充只在它真的有写报告工具时注入：没有
	// update_finding_report 的装配（如自动绑定关闭的测试场景）不注入，
	// 保持"无报告工具 → 无报告指导"的契约。
	if agentKey == "reporter" && has["update_finding_report"] {
		g += reporterEvidenceAnnex
	}
	return g
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "可选：已核实且对应本提示中具体漏洞的流量引用，保留顺序；交接后 report_finding 可传 evidence_hint_id 携带这些引用。", "items": obj(map[string]any{"traffic_id": str("真实流量 ID"), "role": str("baseline / proof / verification / supporting"), "note": str("该流量支持什么结论")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d 必须是本任务的提示节点（继承提示不可直接用于绑定）", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
