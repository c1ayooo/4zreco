package server

// C1 漏洞归并 HTTP 面 + reporter 工具绑定 seed（移植自 ARTEX 0.3.29
// server/finding_cases.go，工具本体在 internal/agent，此处只保留 HTTP 面与会话编排）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

func caseHTTPError(w http.ResponseWriter, err error) {
	code := 400
	if errors.Is(err, db.ErrFindingCaseConflict) || errors.Is(err, db.ErrFindingCaseReviewBusy) {
		code = 409
	}
	writeErr(w, code, err.Error())
}
func decodeCaseRequest(w http.ResponseWriter, r *http.Request, a any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(a); err != nil {
		writeErr(w, 400, "无效请求正文")
		return false
	}
	return true
}
func (s *Server) caseFindingDTO(f *db.DBFinding) FindingDTO {
	return findingFromDB(f, s.resolveAssetIDs(f.AssetIDs))
}

// listFindingCases 是「文件夹优先」的漏洞列表：case 折叠成一行（COUNT DISTINCT
// 'c:'/'f:' 口径），未归并的原始行保持独立。响应内嵌 stats 与 matching_reports。
func (s *Server) listFindingCases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := findingPaginationParam(q.Get("page"), 1, 0)
	size := findingPaginationParam(q.Get("limit"), 20, 100)
	rows, total, err := s.m.pg.ListFindingCases(findingFilterFromQuery(q), page, size)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	caseIDs := []int64{}
	for _, row := range rows {
		if row.Case != nil {
			caseIDs = append(caseIDs, row.Case.ID)
		}
	}
	contexts, err := s.m.pg.FindingCaseListContexts(caseIDs)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	assetIDs := []int64{}
	for _, c := range contexts {
		assetIDs = append(assetIDs, c.AssetIDs...)
	}
	assets := s.resolveAssetIDs(assetIDs)
	items := []map[string]any{}
	for _, row := range rows {
		v := map[string]any{"case": row.Case, "matched_ids": row.MatchedIDs}
		if row.Case != nil {
			c := contexts[row.Case.ID]
			v["task_name"], v["task_description"], v["last_found_at"], v["asset_count"] = c.TaskName, c.TaskDescription, c.LastFoundAt, c.AssetCount
			v["assets"] = append([]FindingAssetDTO{}, findingFromDB(&db.DBFinding{AssetIDs: c.AssetIDs}, assets).Assets...)
		}
		if row.FindingID > 0 {
			f, err := s.m.pg.FindingCaseSummary(row.FindingID, q.Get("original_rows") == "1")
			if err != nil {
				caseHTTPError(w, err)
				return
			}
			if f == nil {
				continue
			}
			f.Report = ""
			v["finding"] = s.caseFindingDTO(f)
		}
		items = append(items, v)
	}
	stats, err := s.m.pg.DistinctFindingStats(q.Get("task_id"))
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	matchingReports, err := s.m.pg.MatchingFindingReportCount(findingFilterFromQuery(q))
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "matching_reports": matchingReports, "page": page, "page_size": size, "stats": stats})
}
func (s *Server) findingCaseAccess(w http.ResponseWriter, r *http.Request, mutation bool) (*db.FindingCase, bool) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	c, err := s.m.pg.GetFindingCase(id)
	if err != nil {
		caseHTTPError(w, err)
		return nil, false
	}
	if c == nil {
		writeErr(w, 404, "漏洞组不存在")
		return nil, false
	}
	if ctx := r.URL.Query().Get("context_task"); ctx != "" {
		t := s.m.ResolveTask(ctx)
		_, inherited, allowed := findingProvenanceInTask(t, c.TaskID)
		if !allowed {
			writeErr(w, 404, "任务中没有该漏洞组")
			return nil, false
		}
		if mutation && inherited {
			writeErr(w, 403, "继承漏洞组只读")
			return nil, false
		}
	}
	return c, true
}
func (s *Server) getFindingCase(w http.ResponseWriter, r *http.Request) {
	c, ok := s.findingCaseAccess(w, r, false)
	if !ok {
		return
	}
	events, err := s.m.pg.FindingCaseEvents(c.ID)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"case": c, "events": events})
}
func (s *Server) getFindingCaseMembers(w http.ResponseWriter, r *http.Request) {
	c, ok := s.findingCaseAccess(w, r, false)
	if !ok {
		return
	}
	page := findingPaginationParam(r.URL.Query().Get("page"), 1, 0)
	size := findingPaginationParam(r.URL.Query().Get("limit"), 20, 100)
	fs, total, err := s.m.pg.FindingCaseMembers(c.ID, page, size)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	assets := s.resolveFindingAssets(fs)
	items := []FindingDTO{}
	for _, f := range fs {
		dto := findingFromDB(f, assets)
		if ctx := r.URL.Query().Get("context_task"); ctx != "" {
			dto.SourceTaskID, dto.Inherited, _ = findingProvenanceInTask(s.m.ResolveTask(ctx), f.TaskID)
		}
		items = append(items, dto)
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}
func (s *Server) removeFindingCaseMember(w http.ResponseWriter, r *http.Request) {
	c, ok := s.findingCaseAccess(w, r, true)
	if !ok {
		return
	}
	fid := int64(atoiDefault(r.PathValue("fid"), 0))
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeCaseRequest(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		body.Reason = "人工移出归并组"
	}
	if err := s.m.pg.RemoveFindingCaseMember(r.Context(), c.ID, fid, body.Reason); err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) caseSuggestions(w http.ResponseWriter, r *http.Request) {
	items, err := s.m.pg.FindingCaseSuggestions(int64(atoiDefault(r.URL.Query().Get("task_id"), 0)))
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) resolveCaseSuggestion(w http.ResponseWriter, r *http.Request) {
	var a struct {
		Accept     bool     `json:"accept"`
		ExcludeIDs []string `json:"exclude_ids"`
	}
	if !decodeCaseRequest(w, r, &a) {
		return
	}
	exclude := make([]int64, 0, len(a.ExcludeIDs))
	for _, raw := range a.ExcludeIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			caseHTTPError(w, errors.New("无效的排除记录编号"))
			return
		}
		exclude = append(exclude, id)
	}
	id, err := s.m.pg.ResolveFindingCaseSuggestion(r.Context(), int64(atoiDefault(r.PathValue("id"), 0)), a.Accept, exclude)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"case_id": i64s(id)})
}
func (s *Server) mergeFindingCase(w http.ResponseWriter, r *http.Request) {
	var a agent.FindingCaseRequest
	if !decodeCaseRequest(w, r, &a) {
		return
	}
	id, err := s.m.pg.MergeFindingCase(r.Context(), parseProfileID(a.TaskID), a.IDList(), a.Title, a.Reason, "human")
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"case_id": i64s(id)})
}
func (s *Server) updateCaseReport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.findingCaseAccess(w, r, true)
	if !ok {
		return
	}
	var a agent.FindingCaseRequest
	if !decodeCaseRequest(w, r, &a) {
		return
	}
	if err := agent.ValidateUnifiedFindingReport(a.Report); err != nil {
		caseHTTPError(w, err)
		return
	}
	if err := s.m.pg.UpdateFindingCaseReport(r.Context(), c.ID, a.Version, a.Title, a.Report, a.Severity, a.SeverityReason); err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// pidOf 是 agent.FindingCaseRequest 的数字字段解析（数字或数字字符串）。
func pidOf(raw json.RawMessage) int64 { return parseProfileID(raw) }

// seedFindingCaseTools 启动时：置 failed 重启打断的整理会话 + 给 reporter 绑定
// 7 个归并工具（工具本体经 toolcatalog 播种进 tools 表；reporter 是会话级 agent，
// 不在 builtinToolsByAgent 三清单里，按名补绑）。一次性 flag 守卫，用户解绑后
// 不回绑（与 seedReporterAgent 的补齐语义不同——这里刻意不 repair，避免覆盖
// 人工裁剪）。
func (s *Server) seedFindingCaseTools() {
	if _, err := s.m.pg.Exec(`UPDATE finding_case_review_runs SET state='failed',error='服务重启中断，请重新提交整理' WHERE state IN ('queued','running')`); err != nil {
		log.Printf("[finding-cases] 清理中断整理会话失败: %v", err)
	}
	const flag = "finding_case_tools_reporter_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	names := []string{}
	for _, t := range agent.NewToolSet(nil, "").FindingCaseTools() {
		names = append(names, t.Name())
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[finding-cases] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	if err := s.m.pg.AddAgentToToolBinding("reporter", names); err != nil {
		log.Printf("[finding-cases] reporter 绑定归并工具失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

const findingCaseReviewTaskMessage = "人工选择整理（只读原始记录）：本任务所选 finding_ids=%s。逐条读取已有报告，仅判断同一实际根因；根因明确相同则直接归并。只有证据指向相同端点、处理器/后端组件、参数或缺失检查等具体共同点，但缺少确认共同根因的关键证据时，才提交一个覆盖2..20条同任务疑似成员的分组，不要拆成两两建议；仅类型或资产相同不足以建议，没有具体共同点时保持 independent，不要因为不确定就提交建议。证据表明属于不同代码路径时可判 independent。已有或新建组应尽力更新统一报告；统一报告暂缺或待更新不阻塞 complete_finding_case_review，可由后续运行或人工补齐。禁止生成或覆盖原始报告、改评级状态、补绑证据，不归并未选记录，不探测目标，遵守人工否决。结束前调用 complete_finding_case_review 提交逐条判断并通过验收。"

// reviewFindingCases 启动历史批量整理：按来源任务分批、事务性预留会话与运行行，
// 逐任务排队一个 reporter 触发会话（带预创建 conversation 与整理消息）。
func (s *Server) reviewFindingCases(w http.ResponseWriter, r *http.Request) {
	var a agent.FindingCaseRequest
	if !decodeCaseRequest(w, r, &a) {
		return
	}
	ids := a.IDList()
	if cid := pidOf(a.CaseID); cid > 0 {
		c, err := s.m.pg.GetFindingCase(cid)
		if err != nil || c == nil || !c.Active {
			writeErr(w, 400, "漏洞组不可用")
			return
		}
		if ctx := r.URL.Query().Get("context_task"); ctx != "" && (c.TaskID == nil || ctx != i64s(*c.TaskID)) {
			writeErr(w, 403, "继承漏洞组只读")
			return
		}
		fs, _, err := s.m.pg.FindingCaseMembers(cid, 1, 100000)
		if err != nil {
			caseHTTPError(w, err)
			return
		}
		ids = nil
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 || (len(a.CaseID) == 0 && len(ids) > 200) {
		writeErr(w, 400, "请选择1至200条原始上报")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil || !reporter.Enabled || s.chatAgentRef() == nil {
		writeErr(w, 409, "报告 Agent 未启用或模型不可用")
		return
	}
	batches := map[int64][]int64{}
	for _, fid := range ids {
		f, err := s.m.pg.FindingCaseSummary(fid)
		if err != nil || f == nil || f.TaskID == nil {
			writeErr(w, 400, "所选漏洞来源任务不可用")
			return
		}
		batches[*f.TaskID] = append(batches[*f.TaskID], fid)
	}
	// Validate and snapshot every source before starting any batch.
	taskContexts := map[int64]triggeredRun{}
	for taskID := range batches {
		t, ok := s.m.Task(i64s(taskID))
		if !ok {
			writeErr(w, 409, "任务不可用")
			return
		}
		taskContexts[taskID] = triggeredRun{taskDesc: t.Description, taskGoal: t.Goal}
	}
	reservations, err := s.m.pg.CreateFindingCaseReviews(r.Context(), batches)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	runs := []map[string]any{}
	for _, reservation := range reservations {
		taskID, fids := reservation.TaskID, reservation.FindingIDs
		taskContext := taskContexts[taskID]
		raw, _ := json.Marshal(fids)
		msg := fmt.Sprintf(findingCaseReviewTaskMessage, raw)
		item := triggeredRun{agentKey: "reporter", title: "漏洞整理 · task#" + i64s(taskID), message: msg, taskID: taskID, taskDesc: taskContext.taskDesc, taskGoal: taskContext.taskGoal, conversationID: reservation.ConversationID}
		s.startTriggeredRunItem(item)
		runs = append(runs, map[string]any{"conversation_id": reservation.ConversationID, "task_id": i64s(taskID)})
	}
	writeJSON(w, 202, map[string]any{"runs": runs})
}
func (s *Server) caseReviewRuns(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.Query(`SELECT conversation_id,task_id,state,error FROM finding_case_review_runs ORDER BY conversation_id DESC LIMIT 50`)
	if err != nil {
		caseHTTPError(w, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var conv int64
		var taskID sql.NullInt64
		var state, msg string
		if err := rows.Scan(&conv, &taskID, &state, &msg); err != nil {
			caseHTTPError(w, err)
			return
		}
		items = append(items, map[string]any{"conversation_id": conv, "task_id": i64s(taskID.Int64), "state": state, "error": msg})
	}
	if err := rows.Err(); err != nil {
		caseHTTPError(w, err)
		return
	}
	writeJSON(w, 200, items)
}

// isHistoricalFindingReview reports whether a conversation is a reserved
// consolidation session.
func (s *Server) isHistoricalFindingReview(conv int64) (bool, error) {
	return s.m.pg.IsFindingCaseReviewConversation(conv)
}

// validateFindingReviewCompletion re-runs the acceptance after the last model
// turn; concurrent evidence changes invalidate completion.
func (s *Server) validateFindingReviewCompletion(conv int64) error {
	var raw json.RawMessage
	if err := s.m.pg.QueryRow(`SELECT conclusion FROM finding_case_review_runs WHERE conversation_id=$1`, conv).Scan(&raw); err != nil {
		return err
	}
	var a agent.FindingReviewConclusion
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	if len(a.Decisions) == 0 {
		return errors.New("整理未通过验收：未提交 complete_finding_case_review 逐条根因判断；请查看执行记录")
	}
	return agent.SaveFindingReviewConclusion(context.Background(), conv, a)
}

// findingMergeCandidates 弱键「可能重复」提示（多键去重，finding_keys.go 移植）：
// 返回与目标漏洞共享 name/asset_class/endpoint/param 弱键的同任务候选。
// 只提示不自动合并——endpoint/param 描述「在哪儿」而非「是什么漏洞」，
// 自动合并会把同一位置上的不同漏洞误并；人工确认走归并文件夹。
func (s *Server) findingMergeCandidates(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	list, err := s.m.pg.FindingMergeCandidates(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []*db.DBFinding{}
	}
	writeJSON(w, 200, map[string]any{"candidates": list})
}
