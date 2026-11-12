package agent

// C1 漏洞归并 agent 工具（移植自 ARTEX 0.3.29，工具本体从 server 层 actool 形态
// 移到 internal/agent，进三张执行 agent 清单 + toolcatalog 播种；reporter 经
// tools 表按名绑定）。判定逻辑全是普通 Go 函数 + SQL，不感知内核（红线 R4）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// FindingCaseDB 由 server 在启动时注入（wireTools）：归并工具不需要任务上下文，
// reporter 等会话级 agent 的 ToolSet 没有探索图 store，db 访问统一走这个入口。
// nil = 归并功能未装配，工具调用返回明确错误而不是 panic。
var FindingCaseDB func() *db.DB

func findingCaseDB() (*db.DB, error) {
	if FindingCaseDB == nil {
		return nil, errors.New("漏洞归并功能未启用（数据库未装配）")
	}
	pg := FindingCaseDB()
	if pg == nil {
		return nil, errors.New("漏洞归并功能未启用（数据库未装配）")
	}
	return pg, nil
}

// findingReviewKey marks a historical consolidation session (人工批量整理).
type findingReviewKey struct{}

// WithFindingCaseReview narrows a reporter session to the consolidation toolset.
func WithFindingCaseReview(ctx context.Context) context.Context {
	return context.WithValue(ctx, findingReviewKey{}, true)
}

func isFindingCaseReview(ctx context.Context) bool {
	v, _ := ctx.Value(findingReviewKey{}).(bool)
	return v
}

// historicalFindingCaseTools 是历史整理会话的工具白名单：只读 + 归并工具，
// 禁原始报告改写/流量绑定/上报/命令执行/重新探测。
func historicalFindingCaseTools(tools []actool.CoreTool) []actool.CoreTool {
	allowed := map[string]bool{}
	for _, name := range []string{"search_finding_duplicates", "get_finding_record", "merge_finding_records", "suggest_finding_merge", "get_finding_case", "update_finding_case_report", "complete_finding_case_review", "get_finding_traffic", "traffic_search", "traffic_get", "traffic_blob", "get_task_node_detail", "list_task_findings", "get_task_graph", "list_task_worker_traces", "search_task_worker_traces", "get_task_worker_trace", "Read"} {
		allowed[name] = true
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		if allowed[tool.Name()] {
			out = append(out, tool)
		}
	}
	return out
}

// findingCaseWorkflow 给 reporter 追加「同一漏洞的多次上报整理」指引。挂依赖
// 工具存在检查：工具被关闭/解绑时不注入，避免提示词悬空。历史整理模式的
// 覆盖指引在 assembly 里经 historicalFindingReviewGuidance 追加。
func findingCaseWorkflow(key string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if key != "reporter" {
		return tools, ""
	}
	has := map[string]bool{}
	for _, t := range tools {
		has[t.Name()] = true
	}
	if !has["search_finding_duplicates"] || !has["merge_finding_records"] || !has["get_finding_case"] || !has["update_finding_case_report"] {
		return tools, ""
	}
	return tools, `

【同一漏洞的多次上报整理】保留本次独立报告，不覆盖其他原报告。默认报告完成即停止的旧指引在此扩展：先保存本次报告，然后 search_finding_duplicates(finding_id=独立记录ID) 分页读取同任务候选摘要（按 score 排序；strong=同漏洞类型且资产重叠，优先核对；weak=未同时具备同漏洞类型和资产重叠，结合 hit_reasons 核对，仅作参考），按需 get_finding_record 查看证据。仅凭漏洞类型、标题、令牌、登录入口相似或高中低等级不能归并；须核对目标、接口、参数、权限边界、根因及实际验证证据。只能处理同一任务，尊重人工否决和 finding_case_blocks。
【判断准则】若证据表明端点/路由、处理器或后端组件、易受影响参数，或缺失检查属于不同代码路径，可以据此判定 independent；必须说明各自证据。仅凭路径、接口、登录入口、令牌、标题或漏洞类型相同/不同，都不能单独证明同一根因或不同根因。只有根因明确相同才直接调用 merge_finding_records(task_id,finding_ids,title,reason)。只有存在具体共同点（两条记录都证据化地指向同一端点、参数、组件或缺失检查），但缺少确认共同根因的关键证据时，才调用 suggest_finding_merge；一次提交覆盖2..20条同任务记录的一个分组，不要拆成两两建议。仅共享漏洞类型或资产没有具体共同点，不得提交建议；没有具体共同点时保持 independent，不要因为不确定就 suggest。不得重复上报、删除记录或重新探测目标。人工选择整理时只能判断所选记录，不能加入未选记录（既有组成员可作为报告上下文）。
归并成功或已有case_id时，get_finding_case 记录实际version，分页读取全部成员，按需 get_finding_record、get_finding_traffic 读取原报告、PoC及已保存流量。根因明确时归并不被统一报告阻塞，应随后尽力用 update_finding_case_report 保存统一报告；如果本次无法完成，文件夹显示“统一报告待更新”，由后续 reporter 运行或人工补齐。统一报告在保存时仍须包含有内容的概述、影响、前置条件、复现步骤、证据、PoC、根因分析、修复建议章节，不得半篇截断；评级及 severity_reason 必须基于已验证影响，不能直接取成员最高等级。集中给出前置条件、完整执行顺序、输入输出如何衔接、可运行的完整脚本及命令，不把必要步骤分散到原报告；缺失条件、未验证步骤如实标明。版本冲突重新读取材料并生成，不能仅换version重试。各成员仍有独立报告、评级和证据。工具被关闭时不绕过配置。`
}

const historicalFindingReviewGuidance = `

【历史整理模式，优先于旧报告撰写及自动绑流量指引】本次只整理已经存在的上报。原始报告即使为空或待更新，也只记录缺失情况，绝不调用 update_finding_report、report_finding、bind_finding_traffic，不修改原始标题、评级、状态、证据或报告，不执行 Bash、写文件或重新探测目标。
先逐条 get_finding_record 读取所选记录，已有原报告直接作为判断材料复用，不重复撰写。只在所选范围内检查同一实际缺陷，可按需读取已存在的证据。结构化证据显示不同端点/路由、处理器或后端组件、参数或缺失检查属于不同代码路径时，可判 independent；仅类型、资产、标题、令牌或登录入口相似不够。只有具体共同点明确且关键根因证据缺失时才保存一个覆盖2..20条记录的疑似分组，没有具体共同点就保持 independent。历史整理只能处理 selected scope，必须遵守同一任务限制和人工否决。
历史模式禁止调用 update_finding_report、report_finding、bind_finding_traffic，不修改原始标题、评级、状态、证据或报告，不执行 Bash、写文件或重新探测目标。已有或新建文件夹应读取全部成员并尽力用 update_finding_case_report 写入完整、最新的统一报告；归并不因报告暂缺而阻塞，未完成时文件夹显示“统一报告待更新”，可由后续运行或人工补齐。统一报告是单独的材料，不覆盖原报告。最后必须调用 complete_finding_case_review，为每条所选 finding_id 提交 verdict（independent/merged/suggested）、reason 和 root_cause_evidence，并提供总结。根因证据应说明具体相同/不同的检查及证据来源；疑似建议明确待补证据。服务端验收通过后才可宣布完成。人工整理只能判断 selected scope，不能加入未选记录。工具不可用或验收失败时如实报告，不能只用自然语言声称完成。`

// FindingCaseRequest 是 7 个归并工具的公共入参（数字或数字字符串均可）。
type FindingCaseRequest struct {
	TaskID         json.RawMessage   `json:"task_id"`
	FindingID      json.RawMessage   `json:"finding_id"`
	IDs            []json.RawMessage `json:"finding_ids"`
	CaseID         json.RawMessage   `json:"case_id"`
	Version        int64             `json:"version"`
	Title          string            `json:"title"`
	Reason         string            `json:"reason"`
	Report         string            `json:"report"`
	Severity       string            `json:"severity"`
	SeverityReason string            `json:"severity_reason"`
	Page           int               `json:"page"`
}

// IDList 解析 finding_ids 列表（丢弃非法项）。名为 IDList 以免与 IDs 字段撞名。
func (a FindingCaseRequest) IDList() []int64 { return pidList(a.IDs) }

func caseI64(v int64) string { return strconv.FormatInt(v, 10) }

// findingCaseJSON renders a DBFinding as the compact JSON object the model sees.
// 不内联 db.DBFinding（无 json tag，序列化成 Go 字段名会误导模型）。
func findingCaseJSON(f *db.DBFinding) map[string]any {
	if f == nil {
		return nil
	}
	assets := f.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	v := map[string]any{
		"finding_id":    caseI64(f.ID),
		"vulnclass":     f.VulnClass,
		"name":          f.Name,
		"severity":      f.Severity,
		"summary":       f.Summary,
		"evidence":      f.Evidence,
		"report":        f.Report,
		"worker":        f.Worker,
		"status":        f.Status,
		"asset_ids":     assets,
		"created_at":    f.CreatedAt,
		"case_id":       "",
		"task_id":       "",
		"traffic_count": f.TrafficCount,
		"evidence_ver":  f.EvidenceVersion,
		"report_ver":    f.ReportEvidenceVersion,
		"node_id":       0,
	}
	if f.NodeID != nil {
		v["node_id"] = *f.NodeID
	}
	if f.TaskID != nil {
		v["task_id"] = caseI64(*f.TaskID)
	}
	return v
}

// PerformFindingCaseTool is the shared handler behind the 7 finding-case tools.
// Exported so the server can drive the same code paths in tests and HTTP guards.
func PerformFindingCaseTool(ctx context.Context, name string, a FindingCaseRequest) (any, error) {
	pg, err := findingCaseDB()
	if err != nil {
		return nil, err
	}
	if err := CheckCaseReviewScope(ctx, name, a); err != nil {
		return nil, err
	}
	fid := pid(a.FindingID)
	cid := pid(a.CaseID)
	page := a.Page
	if page < 1 {
		page = 1
	}
	switch name {
	case "search_finding_duplicates":
		scope, err := pg.FindingCaseReviewSelection(intercept.ConvIDFromContext(ctx))
		if err != nil {
			return nil, err
		}
		var scopes [][]int64
		if scope != nil {
			scopes = append(scopes, scope)
		}
		items, total, strongTotal, err := pg.FindingCaseCandidates(fid, page, 20, scopes...)
		return map[string]any{"items": items, "total": total, "strong_total": strongTotal, "page": page, "page_size": 20,
			"note": "按分数排序；weak 表示未同时具备同漏洞类型和资产重叠，请结合 hit_reasons 核对，仅作参考，通常不应据此建议归并"}, err
	case "get_finding_record":
		f, err := pg.GetFinding(fid)
		if err != nil {
			return nil, err
		}
		if f == nil {
			return nil, errors.New("漏洞不存在")
		}
		group, err := pg.FindingCaseID(f.ID)
		if err != nil {
			return nil, err
		}
		if conv := intercept.ConvIDFromContext(ctx); conv > 0 {
			if _, err := pg.Exec(`UPDATE finding_case_review_runs SET reviewed_ids=CASE WHEN reviewed_ids @> jsonb_build_array($2::bigint) THEN reviewed_ids ELSE reviewed_ids || jsonb_build_array($2::bigint) END WHERE conversation_id=$1 AND finding_ids @> jsonb_build_array($2::bigint)`, conv, f.ID); err != nil {
				return nil, err
			}
		}
		dto := findingCaseJSON(f)
		if group > 0 {
			dto["case_id"] = caseI64(group)
		}
		nodeID := int64(0)
		if f.NodeID != nil {
			nodeID = *f.NodeID
		}
		return map[string]any{"finding": dto, "finding_node_id": nodeID}, nil
	case "merge_finding_records":
		id, err := pg.MergeFindingCase(ctx, pid(a.TaskID), a.IDList(), a.Title, a.Reason, "reporter")
		return map[string]string{"case_id": caseI64(id)}, err
	case "suggest_finding_merge":
		ids := a.IDList()
		if len(ids) < 2 || len(ids) > 20 {
			return nil, errors.New("疑似重复分组需要2至20条记录")
		}
		id, err := pg.SuggestFindingCase(ctx, pid(a.TaskID), ids, a.Title, a.Reason)
		return map[string]any{"suggestion_id": caseI64(id), "finding_ids": ids}, err
	case "get_finding_case":
		c, err := pg.GetFindingCase(cid)
		if err != nil {
			return nil, err
		}
		if c == nil {
			return nil, errors.New("漏洞组不存在")
		}
		fs, total, err := pg.FindingCaseMembers(cid, page, 20)
		if err != nil {
			return nil, err
		}
		members := []map[string]any{}
		for _, f := range fs {
			members = append(members, findingCaseJSON(f))
		}
		return map[string]any{"case": c, "members": members, "total": total, "page": page, "page_size": 20}, nil
	case "update_finding_case_report":
		if err := ValidateUnifiedFindingReport(a.Report); err != nil {
			return nil, err
		}
		err := pg.UpdateFindingCaseReport(ctx, cid, a.Version, a.Title, a.Report, a.Severity, a.SeverityReason)
		return map[string]bool{"ok": err == nil}, err
	}
	return nil, errors.New("未知归并工具")
}

// findingCaseToolProps 是 7 个工具共享的参数说明。
func findingCaseToolProps() map[string]any {
	return map[string]any{
		"finding_id":      idp("独立 findings 记录 ID，不是探索节点 ID"),
		"finding_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "独立漏洞记录 ID 列表"},
		"task_id":         idp("同一来源任务 ID"),
		"case_id":         idp("归并组 ID"),
		"version":         idp("get_finding_case 实际读取的 version"),
		"page":            idp("分页，从1开始，每页20条"),
		"title":           str("同一实际缺陷的名称"),
		"reason":          str("具体证据与归并理由，不能仅类型相同"),
		"report":          str("全部成员证据的完整统一 Markdown 报告"),
		"severity":        str("critical|high|medium|low"),
		"severity_reason": str("基于已验证影响的评级依据，不直接取最高等级"),
	}
}

// FindingCaseTools builds the 7 finding-case tools. They are store-free (the
// consolidated state lives in its own tables), so a nil-store ToolSet — the
// catalog's seed-only shell — constructs them safely.
func (t *ToolSet) FindingCaseTools() []actool.CoreTool {
	props := findingCaseToolProps()
	call := func(ctx context.Context, in json.RawMessage, name string) (actool.Result, error) {
		var a FindingCaseRequest
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		v, err := PerformFindingCaseTool(ctx, name, a)
		return findingCaseResult(v, err)
	}
	ro := []actool.CoreTool{}
	ro = append(ro, readTool("search_finding_duplicates", "只读检索同任务候选摘要与资产，按分数排序并返回 score、tier、hit_reasons：strong=同漏洞类型且资产重叠，weak=未同时具备同漏洞类型和资产重叠，请结合 hit_reasons 核对，仅作参考。等级不同也可能重复。支持分页，按需读取详情。",
		obj(map[string]any{"finding_id": props["finding_id"], "page": props["page"]}, "finding_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "search_finding_duplicates")
		}))
	ro = append(ro, readTool("get_finding_record", "读取独立漏洞完整原始证据和报告，返回探索节点编号以便追溯执行记录。",
		obj(map[string]any{"finding_id": props["finding_id"]}, "finding_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "get_finding_record")
		}))
	ro = append(ro, readTool("get_finding_case", "读取归并组和成员分页。先记录version，再读取成员的原报告、证据及流量；版本变化必须重新读取。",
		obj(map[string]any{"case_id": props["case_id"], "page": props["page"]}, "case_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "get_finding_case")
		}))
	wr := []actool.CoreTool{}
	wr = append(wr, writeTool("merge_finding_records", "证据明确证明同一缺陷时归并；保留所有原始记录。不跨任务、不改变原评级，不可绕过人工否决。",
		obj(map[string]any{"task_id": props["task_id"], "finding_ids": props["finding_ids"], "title": props["title"], "reason": props["reason"]}, "task_id", "finding_ids", "title", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "merge_finding_records")
		}))
	wr = append(wr, writeTool("suggest_finding_merge", "证据存在具体共同点但缺少关键证据时，提交一个疑似重复分组（2..20 条同任务记录，一次覆盖全部疑似成员，不要拆成两两建议），待人工确认；不是自动合并。仅类型/资产相同不应提交。",
		obj(map[string]any{"task_id": props["task_id"], "finding_ids": props["finding_ids"], "title": props["title"], "reason": props["reason"]}, "task_id", "finding_ids", "title", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "suggest_finding_merge")
		}))
	wr = append(wr, writeTool("update_finding_case_report", "保存统一报告及评级理由，version必须来自实际读取。保留各条原报告，不新建漏洞。",
		obj(map[string]any{"case_id": props["case_id"], "version": props["version"], "title": props["title"], "report": props["report"], "severity": props["severity"], "severity_reason": props["severity_reason"]}, "case_id", "version", "title", "report", "severity", "severity_reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return call(ctx, in, "update_finding_case_report")
		}))
	out := append(ro, wr...)
	out = append(out, t.completeFindingCaseReviewTool())
	return out
}

func findingCaseResult(v any, err error) (actool.Result, error) {
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	raw, _ := json.Marshal(v)
	return actool.Text(string(raw)), nil
}

// completeFindingCaseReviewTool 收口历史整理会话：逐条根因判断 + 服务端验收。
func (t *ToolSet) completeFindingCaseReviewTool() actool.CoreTool {
	decision := obj(map[string]any{
		"finding_id":          idp("所选独立漏洞记录 ID"),
		"verdict":             map[string]any{"type": "string", "enum": []string{"independent", "merged", "suggested"}},
		"reason":              str("判断理由，引用已证据化的共同点或不同代码路径；仅类型、标题或资产相同不足以证明共同根因"),
		"root_cause_evidence": str("原始报告/证据中支持实际共同或不同根因的具体材料；suggested 须说明具体共同点、缺失的关键证据及已保存分组；没有具体共同点应判 independent")}, "finding_id", "verdict", "reason", "root_cause_evidence")
	return writeTool("complete_finding_case_review", "历史整理结束前提交每条所选记录的根因判断并验收：必须已读取全部记录，疑似必须已有待确认分组建议；归并只需已在活动文件夹中，统一报告可稍后补齐。验收失败不能宣布完成。", obj(map[string]any{"summary": str("整理结果总结"), "decisions": map[string]any{"type": "array", "items": decision}}, "summary", "decisions"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var a FindingReviewConclusion
		if err := json.Unmarshal(raw, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		conv := intercept.ConvIDFromContext(ctx)
		if err := SaveFindingReviewConclusion(ctx, conv, a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text("历史整理验收通过；原始记录和报告保留，逐条根因判断已保存。"), nil
	})
}

// FindingReviewDecision 是一条记录的根因判断。
type FindingReviewDecision struct {
	FindingID         int64  `json:"finding_id"`
	Verdict           string `json:"verdict"`
	Reason            string `json:"reason"`
	RootCauseEvidence string `json:"root_cause_evidence"`
}

// FindingReviewConclusion 是 complete_finding_case_review 的提交内容。
type FindingReviewConclusion struct {
	Summary   string                  `json:"summary"`
	Decisions []FindingReviewDecision `json:"decisions"`
}

// SaveFindingReviewConclusion 校验并落盘整理验收（会话行 FOR UPDATE、必须已读取、
// verdict 与实际归并/建议状态一致）。验收通过后服务端仍会在会话收尾重校验
// （证据变化会推翻完成态）。
func SaveFindingReviewConclusion(ctx context.Context, conv int64, a FindingReviewConclusion) error {
	if conv <= 0 {
		return errors.New("仅用于有上下文的历史整理会话")
	}
	pg, err := findingCaseDB()
	if err != nil {
		return err
	}
	return pg.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var idsRaw, readsRaw json.RawMessage
		var state string
		if err := tx.QueryRow(`SELECT finding_ids,reviewed_ids,state FROM finding_case_review_runs WHERE conversation_id=$1 FOR UPDATE`, conv).Scan(&idsRaw, &readsRaw, &state); err != nil {
			return err
		}
		if state != "running" {
			return errors.New("整理会话未运行，不能提交验收")
		}
		var ids, reads []int64
		if err := json.Unmarshal(idsRaw, &ids); err != nil {
			return err
		}
		if err := json.Unmarshal(readsRaw, &reads); err != nil {
			return err
		}
		read := map[int64]bool{}
		for _, id := range reads {
			read[id] = true
		}
		decisions := map[int64]FindingReviewDecision{}
		for _, d := range a.Decisions {
			if _, ok := decisions[d.FindingID]; ok {
				return errors.New("重复的判断编号")
			}
			decisions[d.FindingID] = d
		}
		if strings.TrimSpace(a.Summary) == "" || len(ids) != len(decisions) {
			return errors.New("须提供总结和覆盖全部所选记录的逐条判断")
		}
		for _, id := range ids {
			d, ok := decisions[id]
			if !ok || !read[id] {
				return fmt.Errorf("请先 get_finding_record 读取并判断所选记录 #%d", id)
			}
			if strings.TrimSpace(d.Reason) == "" || strings.TrimSpace(d.RootCauseEvidence) == "" {
				return fmt.Errorf("记录 #%d 缺少判断理由或根因证据", id)
			}
			var cid sql.NullInt64
			if err := tx.QueryRow(`SELECT m.case_id FROM findings f LEFT JOIN finding_case_members m ON m.finding_id=f.id WHERE f.id=$1`, id).Scan(&cid); err != nil {
				return err
			}
			switch d.Verdict {
			case "merged":
				if !cid.Valid {
					return fmt.Errorf("记录 #%d 尚未归并", id)
				}
			case "suggested":
				var pending bool
				if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_case_suggestions s
                    JOIN finding_case_suggestion_members sm ON sm.suggestion_id=s.id
                    WHERE s.state='pending' AND sm.finding_id=$1)`, id).Scan(&pending); err != nil {
					return err
				}
				if !pending {
					return fmt.Errorf("记录 #%d 须先保存待确认建议", id)
				}
			case "independent":
				if cid.Valid {
					return fmt.Errorf("记录 #%d 已在文件夹中，不能声明为独立", id)
				}
			default:
				return errors.New("无效判断类型")
			}
			if cid.Valid {
				var active bool
				if err := tx.QueryRow(`SELECT active FROM finding_cases WHERE id=$1 FOR SHARE`, cid.Int64).Scan(&active); err != nil {
					return err
				}
				if !active {
					return fmt.Errorf("文件夹 #%d 已关闭", cid.Int64)
				}
			}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE finding_case_review_runs SET conclusion=$2 WHERE conversation_id=$1`, conv, string(raw))
		return err
	})
}

// ValidateUnifiedFindingReport 要求统一报告具备有内容八大章节且代码块闭合。
// 校验的是报告完整性，不是模型根因声明的真实性。
func ValidateUnifiedFindingReport(report string) error {
	aliases := [][]string{{"概述", "overview", "summary"}, {"影响", "impact"}, {"前置", "prerequisite", "precondition"}, {"复现", "reproduction", "reproduce"}, {"证据", "evidence"}, {"poc", "完整脚本", "验证脚本", "proof of concept"}, {"根因", "root cause"}, {"修复", "remediation", "recommendation", "fix"}}
	names := []string{"概述", "影响", "前置条件", "复现步骤", "证据", "PoC", "根因分析", "修复建议"}
	found := make([]bool, len(aliases))
	current := -1
	hasContent := false
	fence := ""
	finish := func() {
		if current >= 0 && hasContent {
			found[current] = true
		}
	}
	for _, line := range strings.Split(report, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			marker := t[:3]
			if fence == "" {
				fence = marker
			} else if fence == marker {
				fence = ""
			}
			continue
		}
		if fence != "" {
			if t != "" {
				hasContent = true
			}
			continue
		}
		if strings.HasPrefix(t, "#") {
			heading := strings.TrimLeft(t, "#")
			if len(heading) == len(t) || !strings.HasPrefix(heading, " ") {
				continue
			}
			// Subheadings belong to the current section unless they start another required section.
			next := -1
			lower := strings.ToLower(heading)
			for i, words := range aliases {
				for _, word := range words {
					if strings.Contains(lower, word) {
						next = i
						break
					}
				}
				if next >= 0 {
					break
				}
			}
			if next >= 0 {
				finish()
				current = next
				hasContent = false
			}
			continue
		}
		if t != "" && t != "---" && t != "***" && t != ">" {
			hasContent = true
		}
	}
	finish()
	if fence != "" {
		return errors.New("统一报告代码块未闭合，可能截断；请补全后再保存")
	}
	missing := []string{}
	for i, ok := range found {
		if !ok {
			missing = append(missing, names[i])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("统一报告缺少有内容的章节：%s；请补全后保存", strings.Join(missing, "、"))
	}
	return nil
}

// CheckCaseReviewScope 是历史整理会话的操作范围闸：人工批量整理只能判断所选
// 记录；验收提交后不能再改；原始报告/上报/流量绑定被整体禁止。非整理会话
// （无 conv 或无 review run 行）一律放行。
func CheckCaseReviewScope(ctx context.Context, name string, a FindingCaseRequest) error {
	conv := intercept.ConvIDFromContext(ctx)
	if conv == 0 {
		return nil
	}
	pg, err := findingCaseDB()
	if err != nil {
		return err
	}
	var raw, conclusion json.RawMessage
	err = pg.QueryRow(`SELECT finding_ids,conclusion FROM finding_case_review_runs WHERE conversation_id=$1`, conv).Scan(&raw, &conclusion)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	var ids []int64
	if err := json.Unmarshal(raw, &ids); err != nil {
		return err
	}
	if string(conclusion) != "{}" && (name == "merge_finding_records" || name == "suggest_finding_merge" || name == "update_finding_case_report") {
		return errors.New("整理判断已提交，不能在验收后继续修改")
	}
	allowed := map[int64]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	switch name {
	case "search_finding_duplicates":
		if !allowed[pid(a.FindingID)] {
			return errors.New("历史整理只能检索所选记录的候选")
		}
	case "update_finding_report", "bind_finding_traffic", "report_finding":
		return errors.New("历史整理禁止修改原始报告、上报或证据；只能写归并关系及统一报告")
	case "merge_finding_records", "suggest_finding_merge":
		for _, id := range a.IDList() {
			if !allowed[id] {
				return errors.New("人工整理只能归并所选记录")
			}
		}
	case "update_finding_case_report":
		fs, _, err := pg.FindingCaseMembers(pid(a.CaseID), 1, 100000)
		if err != nil {
			return err
		}
		found := false
		for _, f := range fs {
			if allowed[f.ID] {
				found = true
			}
		}
		if !found {
			return errors.New("该漏洞组不属于人工所选范围")
		}
	}
	return nil
}
