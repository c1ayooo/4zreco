package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// TestIntelligenceHTTPSettingsAndScope：settings 开关默认关、可持久化；列表/详情
// 直出原文；跨任务访问 404；task_relations 继承可见但不可改；关闭开关不隐藏已保存
// 记录（enabled=false 只是停止采集）。
func TestIntelligenceHTTPSettingsAndScope(t *testing.T) {
	s, initial, request := trafficEvidenceServer(t)
	f, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := *f.TaskID
	if s.settingsPayload()[db.SettingTaskIntelligence] != false {
		t.Fatal("default must be off")
	}
	if r := request("PUT", "/api/settings", `{"task_intelligence_enabled":true}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	defer s.m.pg.SetBool(db.SettingTaskIntelligence, false)
	if !s.m.pg.GetBool(db.SettingTaskIntelligence, false) {
		t.Fatal("setting not persisted")
	}
	in := db.IntelligenceInput{Kind: "credential", Title: "test credential", Content: "local-api-fixture-secret", Evidence: "local fixture evidence", Confidence: "observed"}
	item, err := s.m.pg.RecordIntelligence(t.Context(), taskID, 0, "qa", in)
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/api/tasks/%d/intelligence", taskID)
	r := request("GET", base, "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), in.Content) || !strings.Contains(r.Body.String(), in.Evidence) {
		t.Fatalf("list omitted content or evidence: %d %s", r.Code, r.Body)
	}
	r = request("GET", fmt.Sprintf("%s/%d", base, item.ID), "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), in.Content) {
		t.Fatal("detail content missing", r.Code, r.Body)
	}
	if r = request("PATCH", fmt.Sprintf("%s/%d", base, item.ID), `{"status":"verified"}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	other, err := s.m.pg.CreateTask("unrelated intel API", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.DeleteTask(other.ID)
	for _, method := range []string{"GET", "PATCH"} {
		r = request(method, fmt.Sprintf("/api/tasks/%d/intelligence/%d", other.ID, item.ID), `{"status":"invalid"}`)
		if r.Code != 404 {
			t.Fatal("cross task access", method, r.Code, r.Body)
		}
	}
	if _, err = s.m.pg.Exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, other.ID, taskID); err != nil {
		t.Fatal(err)
	}
	r = request("GET", fmt.Sprintf("/api/tasks/%d/intelligence/%d", other.ID, item.ID), "")
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	var got db.Intelligence
	if err = json.Unmarshal(r.Body.Bytes(), &got); err != nil || !got.Inherited {
		t.Fatal("missing inherited marker")
	}
	if r = request("PATCH", fmt.Sprintf("/api/tasks/%d/intelligence/%d", other.ID, item.ID), `{"status":"invalid"}`); r.Code != 404 {
		t.Fatal("inherited mutation accepted")
	}
	// 资产维度镜像路由：按 asset_ids 命中可见。
	assetID, err := s.m.pg.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: fmt.Sprintf("https://intel-api-%d.example.invalid", taskID), TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	if _, err = s.m.pg.Exec(`UPDATE task_intelligence SET asset_ids=$2::jsonb WHERE id=$1`, item.ID, fmt.Sprintf("[%d]", assetID)); err != nil {
		t.Fatal(err)
	}
	r = request("GET", fmt.Sprintf("/api/assets/%d/intelligence", assetID), "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), in.Content) {
		t.Fatalf("asset mirror list: %d %s", r.Code, r.Body)
	}
	r = request("GET", fmt.Sprintf("/api/assets/%d/intelligence/%d", assetID, item.ID), "")
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if r = request("GET", "/api/assets/999999999/intelligence", ""); r.Code != 404 {
		t.Fatal("missing asset scope", r.Code, r.Body)
	}
	if r = request("PUT", "/api/settings", `{"task_intelligence_enabled":false}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if r = request("GET", base, ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"total":1`) {
		t.Fatal("disable hid saved records")
	}
}
