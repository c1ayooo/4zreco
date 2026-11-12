package server

// C1 漏洞归并 server 回归（移植自 ARTEX 0.3.29 server/finding_cases_test.go）。
// 工具本体在 internal/agent，performFindingCaseTool → agent.PerformFindingCaseTool；
// db 入口 agent.FindingCaseDB 由用例装配（生产由 wireTools 注入）。

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

func testCaseServer(t *testing.T) (*Server, int64, []int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	pg := m.pg
	task, err := pg.CreateTask("case server", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := []int64{}
	for _, sev := range []string{"high", "medium", "low"} {
		id, err := pg.AddFinding(task.ID, 0, "IDOR", "orders", sev, "same endpoint", "proof "+sev, "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID); _ = pg.DeleteTask(task.ID) })
	oldDB := agent.FindingCaseDB
	agent.FindingCaseDB = func() *db.DB { return pg }
	t.Cleanup(func() { agent.FindingCaseDB = oldDB })
	return &Server{m: m}, task.ID, ids
}

// performFindingCaseTool drives the agent-side consolidated-tool handler.
func performFindingCaseTool(ctx context.Context, name string, a agent.FindingCaseRequest) (any, error) {
	return agent.PerformFindingCaseTool(ctx, name, a)
}

func TestFindingCaseToolMigrationPreservesBindings(t *testing.T) {
	s, _, _ := testCaseServer(t)
	pg := s.m.pg
	const flag = "finding_case_tools_reporter_v1"
	value, exists, err := pg.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if exists {
			if err := pg.SetSetting(flag, value); err != nil {
				t.Error(err)
			}
		} else if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
			t.Error(err)
		}
	})
	tools := agent.NewToolSet(nil, "").FindingCaseTools()
	if len(tools) != 7 {
		t.Fatalf("expected 7 finding-case tools, got %d", len(tools))
	}
	toolRows := map[string]*db.Tool{}
	for _, tool := range tools {
		old, err := pg.GetTool(tool.Name())
		if err != nil {
			t.Fatal(err)
		}
		toolRows[tool.Name()] = old
		key := tool.Name()
		t.Cleanup(func() {
			if toolRows[key] == nil {
				if _, err := pg.Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
					t.Error(err)
				}
				return
			}
			old := toolRows[key]
			bindings, _ := json.Marshal(old.Agents)
			if err := pg.UpdateTool(key, old.Description, old.Schema, bindings, old.Enabled); err != nil {
				t.Error(err)
			}
		})
	}
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	s.seedFindingCaseTools()
	for _, tool := range tools {
		row, err := pg.GetTool(tool.Name())
		if err != nil || row == nil {
			t.Fatal("missing tool", tool.Name(), err)
		}
		if !contains(row.Agents, "reporter") {
			t.Fatalf("reporter not bound: %+v", row)
		}
		if row.Description != tool.Description() || len(row.Schema) <= 2 {
			t.Fatalf("description/schema not refreshed: %+v", row)
		}
	}
	// 一次性 flag 语义：首次播种后，操作者手工解绑不会被开机重放覆盖。
	for _, tool := range tools {
		if err := pg.RemoveAgentFromTool("reporter", tool.Name()); err != nil {
			t.Fatal(err)
		}
	}
	s.seedFindingCaseTools()
	for _, tool := range tools {
		row, err := pg.GetTool(tool.Name())
		if err != nil || row == nil || contains(row.Agents, "reporter") {
			t.Fatal("reseed restored an operator-removed binding", row, err)
		}
	}
}

func TestFindingCaseAPIPaginationAndTools(t *testing.T) {
	s, task, ids := testCaseServer(t)
	ctx := context.Background()
	a := agent.FindingCaseRequest{TaskID: json.RawMessage(fmt.Sprint(task)), Title: "订单越权", Reason: "same check"}
	for _, id := range ids {
		a.IDs = append(a.IDs, json.RawMessage(fmt.Sprint(id)))
	}
	result, err := performFindingCaseTool(ctx, "merge_finding_records", a)
	if err != nil {
		t.Fatal(err)
	}
	cid := result.(map[string]string)["case_id"]
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/exploration/finding-cases?task_id=%d&severity=low&page=1&limit=1", task), nil)
	w := httptest.NewRecorder()
	s.listFindingCases(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var page struct {
		Total int `json:"total"`
		Items []struct {
			Case    db.FindingCase `json:"case"`
			Matched []int64        `json:"matched_ids"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Case.Count != 3 || page.Items[0].Case.Report != "" || len(page.Items[0].Matched) != 1 {
		t.Fatalf("page %+v", page)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.SetPathValue("id", cid)
	w = httptest.NewRecorder()
	s.getFindingCaseMembers(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "proof high") {
		t.Fatal(w.Code, w.Body)
	}
	a.CaseID = json.RawMessage(cid)
	result, err = performFindingCaseTool(ctx, "get_finding_case", a)
	if err != nil {
		t.Fatal(err)
	}
	c := result.(map[string]any)["case"].(*db.FindingCase)
	a.Version = c.Version
	a.Report = completeFindingReviewReport
	a.Severity = "high"
	a.SeverityReason = "verified data disclosure"
	if _, err := performFindingCaseTool(ctx, "update_finding_case_report", a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence='new data' WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := performFindingCaseTool(ctx, "update_finding_case_report", a); err != db.ErrFindingCaseConflict {
		t.Fatalf("stale report accepted %v", err)
	}
}
func TestFindingCaseConsolidatedExportPreservesScope(t *testing.T) {
	s, task, ids := testCaseServer(t)
	ctx := context.Background()
	cid, err := s.m.pg.MergeFindingCase(ctx, task, ids, "订单越权", "same", "reporter")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.m.pg.GetFindingCase(cid)
	if err := s.m.pg.UpdateFindingCaseReport(ctx, cid, c.Version, "订单越权", "complete report", "high", "verified"); err != nil {
		t.Fatal(err)
	}
	fs, err := s.m.pg.ListFindingsForExport(db.FindingFilter{}, ids[:1])
	if err != nil {
		t.Fatal(err)
	}
	expanded, plan, err := s.prepareFindingCaseExport(fs)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != 3 {
		t.Fatal("selected one child did not include complete group")
	}
	out, err := s.consolidateFindingCaseExport(expanded, plan, false)
	if err != nil || len(out) != 1 || out[0].Report != "complete report" || !strings.Contains(out[0].Summary, fmt.Sprint(ids[2])) {
		t.Fatalf("unified %+v %v", out, err)
	}
	out, err = s.consolidateFindingCaseExport(expanded, plan, true)
	if err != nil || len(out) != 4 {
		t.Fatalf("originals lost %d %v", len(out), err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET severity='critical' WHERE id=$1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	out, err = s.consolidateFindingCaseExport(expanded, plan, false)
	if err != nil || !strings.Contains(out[0].Report, "已过期") || !strings.Contains(out[0].Evidence, "proof low") {
		t.Fatalf("pending export omitted evidence %+v %v", out, err)
	}
}
func TestFindingCaseManualSelectionScope(t *testing.T) {
	s, task, ids := testCaseServer(t)
	conv, err := s.m.pg.CreateConversation("reporter", "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
	raw, _ := json.Marshal(ids[:2])
	if _, err := s.m.pg.Exec(`INSERT INTO finding_case_review_runs(conversation_id,task_id,finding_ids) VALUES($1,$2,$3)`, conv.ID, task, string(raw)); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithConvID(context.Background(), conv.ID)
	a := agent.FindingCaseRequest{IDs: []json.RawMessage{json.RawMessage(fmt.Sprint(ids[0])), json.RawMessage(fmt.Sprint(ids[2]))}}
	if err := agent.CheckCaseReviewScope(ctx, "merge_finding_records", a); err == nil {
		t.Fatal("unselected mutation allowed")
	}
	a.IDs[1] = json.RawMessage(fmt.Sprint(ids[1]))
	if err := agent.CheckCaseReviewScope(ctx, "merge_finding_records", a); err != nil {
		t.Fatal(err)
	}
}

func TestFindingCaseReviewStatusSurvivesTaskDeletion(t *testing.T) {
	s, task, ids := testCaseServer(t)
	conv, err := s.m.pg.CreateConversation("reporter", "review", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
	if _, err := s.m.pg.Exec(`INSERT INTO finding_case_review_runs(conversation_id,task_id,finding_ids) VALUES($1,$2,$3)`, conv.ID, task, fmt.Sprintf("[%d]", ids[0])); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.DeleteTask(task); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, id := range ids {
			_, _ = s.m.pg.DeleteFinding(id)
		}
	}()
	w := httptest.NewRecorder()
	s.caseReviewRuns(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"task_id":"0"`) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestFindingCaseSelectedReviewCannotRewriteOtherOriginal(t *testing.T) {
	s, task, ids := testCaseServer(t)
	conv, err := s.m.pg.CreateConversation("reporter", "review", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
	raw, _ := json.Marshal(ids[:1])
	if _, err := s.m.pg.Exec(`INSERT INTO finding_case_review_runs(conversation_id,task_id,finding_ids) VALUES($1,$2,$3)`, conv.ID, task, string(raw)); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithConvID(context.Background(), conv.ID)
	if err := agent.CheckCaseReviewScope(ctx, "update_finding_report", agent.FindingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(ids[1]))}); err == nil {
		t.Fatal("unselected original allowed")
	}
	if err := agent.CheckCaseReviewScope(ctx, "update_finding_report", agent.FindingCaseRequest{FindingID: json.RawMessage(fmt.Sprint(ids[0]))}); err == nil {
		t.Fatal("selected original was allowed to be overwritten")
	}
}

func TestFindingCaseGroupedTrafficExportAndInheritedAccess(t *testing.T) {
	s, recorded, req := trafficEvidenceServer(t)
	ctx := t.Context()
	f, err := s.m.pg.GetFinding(recorded.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.GetTask(*f.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("verified original response")
	seedServerEvidenceFlow(t, s, "case-proof", body)
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/traffic", f.ID), `{"traffic_refs":[{"traffic_id":"case-proof","role":"proof"}]}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	other, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "same permission boundary", Severity: "low"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{f.ID, other.FindingID} {
		if _, err := s.m.pg.Exec(`UPDATE findings SET report=$2 WHERE id=$1`, id, fmt.Sprintf("original script #%d", id)); err != nil {
			t.Fatal(err)
		}
	}
	cid, err := s.m.pg.MergeFindingCase(ctx, task.ID, []int64{f.ID, other.FindingID}, "orders", "same permission check", "reporter")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.m.pg.GetFindingCase(cid)
	if err := s.m.pg.UpdateFindingCaseReport(ctx, cid, c.Version, "orders", "unified complete script", "high", "verified impact"); err != nil {
		t.Fatal(err)
	}
	// A binding note is evidence too: changing it makes the aggregate report stale.
	list, err := s.m.pg.GetFindingTraffic(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	w := req("PATCH", fmt.Sprintf("/api/exploration/findings/%d/traffic/%d", f.ID, list.Bindings[0].ID), fmt.Sprintf(`{"version":%d,"note":"additional verified condition"}`, list.Version))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	c, _ = s.m.pg.GetFindingCase(cid)
	if c.Version == c.ReportVersion {
		t.Fatal("binding evidence did not invalidate unified report")
	}
	url := fmt.Sprintf("/api/exploration/findings/export?mode=consolidated&include_originals=true&scope=selected&ids=%d&format=md-zip", f.ID)
	w = req("GET", url, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	mdCount, caseCount := 0, 0
	seen := map[string]bool{}
	recovered := false
	for _, file := range z.File {
		if seen[file.Name] {
			t.Fatalf("duplicate ZIP entry %s", file.Name)
		}
		seen[file.Name] = true
		reader, e := file.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(reader)
		reader.Close()
		if e != nil {
			t.Fatal(e)
		}
		if strings.HasSuffix(file.Name, ".md") {
			mdCount++
			if strings.HasPrefix(file.Name, "case_") {
				caseCount++
				if !strings.Contains(string(data), fmt.Sprintf("original script #%d", other.FindingID)) {
					t.Fatal("stale export lost an original report")
				}
			}
		}
		if strings.HasSuffix(file.Name, "response.bin") && bytes.Equal(data, body) {
			recovered = true
		}
	}
	if mdCount != 3 || caseCount != 1 || !recovered {
		t.Fatalf("ZIP reports=%d folders=%d evidence=%v", mdCount, caseCount, recovered)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/export?mode=consolidated&scope=selected&ids=%d&format=json", f.ID), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id": "case:`) || !strings.Contains(w.Body.String(), `"member_ids"`) {
		t.Fatal(w.Code, w.Body)
	}
	child, err := s.m.CreateTaskWithOptions("inherited folders", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{task.ID}})
	if err != nil {
		t.Fatal(err)
	}
	childID, _ := strconv.ParseInt(child.ID, 10, 64)
	defer s.m.pg.DeleteTask(childID)
	base := fmt.Sprintf("/api/exploration/finding-cases/%d", cid)
	suffix := "?context_task=" + child.ID
	if w = req("GET", base+suffix, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("GET", base+"/members"+suffix, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"inherited":true`) {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("DELETE", fmt.Sprintf("%s/members/%d%s", base, f.ID, suffix), `{}`); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("PUT", base+"/report"+suffix, `{}`); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("POST", "/api/exploration/finding-case-review"+suffix, fmt.Sprintf(`{"case_id":%d}`, cid)); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestFindingCaseListIncludesContextAndFilteredCounts(t *testing.T) {
	s, task, ids := testCaseServer(t)
	cid, err := s.m.pg.MergeFindingCase(t.Context(), task, ids[:3], "same defect", "verified root cause", "human")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/exploration/finding-cases?task_id=%d&severity=medium", task), nil)
	w := httptest.NewRecorder()
	s.listFindingCases(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	var page struct {
		Total           int `json:"total"`
		MatchingReports int `json:"matching_reports"`
		Items           []struct {
			Case            *db.FindingCase   `json:"case"`
			TaskDescription string            `json:"task_description"`
			Assets          []FindingAssetDTO `json:"assets"`
			AssetCount      int               `json:"asset_count"`
			LastFoundAt     string            `json:"last_found_at"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.MatchingReports != 1 || len(page.Items) != 1 || page.Items[0].Case.ID != cid || page.Items[0].Case.Count != 3 || page.Items[0].Case.Report != "" || page.Items[0].TaskDescription == "" || page.Items[0].LastFoundAt == "" || page.Items[0].Assets == nil {
		t.Fatalf("list payload %s", w.Body.String())
	}
}

func TestOriginalFindingRowsKeepEvidenceAndOmitReportBody(t *testing.T) {
	s, task, ids := testCaseServer(t)
	if _, err := s.m.pg.Exec(`UPDATE findings SET report=$2 WHERE id=$1`, ids[0], "large original report"); err != nil {
		t.Fatal(err)
	}
	for _, original := range []bool{false, true} {
		suffix := ""
		if original {
			suffix = "&original_rows=1"
		}
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/exploration/finding-cases?task_id=%d%s", task, suffix), nil)
		w := httptest.NewRecorder()
		s.listFindingCases(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d %s", w.Code, w.Body)
		}
		var page struct {
			Items []struct {
				Finding FindingDTO `json:"finding"`
			} `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 3 {
			t.Fatalf("lost original rows %s", w.Body)
		}
		for _, row := range page.Items {
			if row.Finding.Report != "" {
				t.Fatal("list loaded report body")
			}
			if original && !strings.HasPrefix(row.Finding.Evidence, "proof ") {
				t.Fatal("original table evidence missing")
			}
			if !original && row.Finding.Evidence != "" {
				t.Fatal("compact list should omit evidence")
			}
		}
	}
}
