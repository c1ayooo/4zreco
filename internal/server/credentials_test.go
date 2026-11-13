package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/llmrec"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

// credentialDSNOrSkip 让本文件的 PG 门控用例在无数据库配置时 skip（而非夹具里的
// t.Fatal）——AGENTS.md 测试惯例：无 DSN 的本地快速循环必须全绿。
func credentialDSNOrSkip(t *testing.T) {
	t.Helper()
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
}

type credentialServerProvider struct {
	calls   int
	invalid bool
}

func (p *credentialServerProvider) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	if p.invalid {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("invalid fixture JSON")}}, "end_turn", llm.Usage{}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(`{"accounts":[{"username":"qa-user","password":"qa-pass-321"}]}`)}}, "end_turn", llm.Usage{InputTokens: 88, OutputTokens: 22}, nil
}
func (*credentialServerProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) { panic("unexpected stream") }
}

// TestCredentialProcessingFlowBindingAndScopes（移植自 ARTEX 0.3.29）：三开关经
// settings API 的依赖校验、结构化 JSON 零模型整理、流量绑定只命中同主机且含凭据
// 原文的已抓取流量、范围授权（跨任务 404 / task_relations 继承读不可写 / 资产镜像）、
// 原始流量删除后绑定片段仍在、重试不丢既有绑定、散文凭据恰一次模型调用且用量归账
// 到凭据整理专用通道、关闭开关清空绑定并隐藏派生展示。
func TestCredentialProcessingFlowBindingAndScopes(t *testing.T) {
	credentialDSNOrSkip(t)
	s, initial, request := trafficEvidenceServer(t)
	f, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := *f.TaskID
	oldRecording := s.m.pg.GetBool(db.SettingTaskIntelligence, false)
	oldOn, oldBind := s.m.pg.GetBool(db.SettingCredentialAgent, false), s.m.pg.GetBool(db.SettingCredentialTraffic, false)
	defer func() {
		_ = s.m.pg.SetBool(db.SettingTaskIntelligence, oldRecording)
		_ = s.m.pg.SetCredentialAgentSettings(t.Context(), &oldOn, nil)
		if oldOn {
			_ = s.m.pg.SetCredentialAgentSettings(t.Context(), nil, &oldBind)
		}
	}()
	_ = s.m.pg.SetBool(db.SettingCredentialAgent, false)
	_ = s.m.pg.SetBool(db.SettingCredentialTraffic, false)
	if r := request("PUT", "/api/settings", `{"credential_traffic_binding":true}`); r.Code != 400 {
		t.Fatal("ungated binding", r.Code, r.Body)
	}
	if r := request("PUT", "/api/settings", `{"credential_agent_enabled":true}`); r.Code != 400 {
		t.Fatal("agent enabled without recording", r.Code)
	}
	if r := request("PUT", "/api/settings", `{"task_intelligence_enabled":true}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if r := request("PUT", "/api/settings", `{"credential_agent_enabled":true}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if s.settingsPayload()[db.SettingCredentialTraffic] != false {
		t.Fatal("binding default must be off")
	}
	assetID, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "http://evidence.local", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	in := db.IntelligenceInput{Kind: "credential", Title: "structured fixture", Content: `{"username":"qa-user","password":"qa-pass-321"}`, Evidence: "http://evidence.local local fixture", Confidence: "observed", AssetIDs: []int64{assetID}}
	item, err := s.m.pg.RecordIntelligence(t.Context(), taskID, 0, "fixture", in)
	if err != nil {
		t.Fatal(err)
	}
	mock := &credentialServerProvider{}
	s.llmOn = true
	s.llmProv = llmrec.Wrap(mock, s.m.pg, "fixture", "fixture", "", "", func() bool { return false })
	s.llmCfg.Model = "fixture"
	first, err := s.m.pg.ClaimCredentialJob(t.Context(), false, taskID)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	s.processCredentialJob(t.Context(), first)
	got, err := s.m.pg.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.Credentials.State != "ready" || len(got.Credentials.Accounts) != 1 || mock.calls != 0 || got.Credentials.TrafficState != "off" {
		t.Fatalf("rules: %+v %v calls=%d", got.Credentials, err, mock.calls)
	}
	seedServerEvidenceFlow(t, s, "credential-proof", []byte(`{"username":"qa-user","password":"qa-pass-321"}`))
	seedServerEvidenceFlow(t, s, "credential-wrong", []byte(`{"username":"other-user","password":"qa-pass-321"}`))
	seedServerEvidenceFlow(t, s, "credential-other-host", []byte(`{"username":"qa-user","password":"qa-pass-321"}`))
	// 直接插测试数据绕过采集写入侧的全文索引。
	for _, id := range []string{"credential-proof", "credential-wrong", "credential-other-host"} {
		if _, err = s.m.traffic.DB().Exec(`INSERT INTO ex_fts(rowid,content) SELECT rowid,? FROM exchanges WHERE id=?`, `{"username":"qa-user","password":"qa-pass-321"}`, id); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.m.traffic.DB().Exec(`UPDATE exchanges SET host='other.local',url='http://other.local/' WHERE id='credential-other-host'`)
	if err != nil {
		t.Fatal(err)
	}
	if r := request("PUT", "/api/settings", `{"credential_traffic_binding":true}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	second, err := s.m.pg.ClaimCredentialJob(t.Context(), true, taskID)
	if err != nil || second == nil {
		t.Fatal("no late binding job", err)
	}
	s.processCredentialJob(t.Context(), second)
	got, _ = s.m.pg.GetIntelligence(t.Context(), item.ID)
	if got.Credentials.TrafficState != "ready" || len(got.Credentials.Traffic) != 1 || got.Credentials.Traffic[0].ID != "credential-proof" || mock.calls != 0 || got.Status != "unverified" {
		t.Fatalf("binding: %+v calls=%d", got.Credentials, mock.calls)
	}
	base := fmt.Sprintf("/api/tasks/%d/intelligence/%d/traffic/credential-proof", taskID, item.ID)
	r := request("GET", base, "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "qa-pass-321") {
		t.Fatal("flow detail", r.Code, r.Body)
	}
	other, err := s.m.pg.CreateTask("credential scope", "local", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.DeleteTask(other.ID)
	if r = request("GET", fmt.Sprintf("/api/tasks/%d/intelligence/%d/traffic/credential-proof", other.ID, item.ID), ""); r.Code != 404 {
		t.Fatal("unrelated task reads flow", r.Code)
	}
	if _, err = s.m.pg.Exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, other.ID, taskID); err != nil {
		t.Fatal(err)
	}
	if r = request("GET", fmt.Sprintf("/api/tasks/%d/intelligence/%d/traffic/credential-proof", other.ID, item.ID), ""); r.Code != 200 {
		t.Fatal("inherited read failed", r.Code)
	}
	if r = request("POST", fmt.Sprintf("/api/tasks/%d/intelligence/%d/credentials/retry", other.ID, item.ID), ""); r.Code != 404 {
		t.Fatal("inherited write accepted", r.Code)
	}
	if r = request("GET", fmt.Sprintf("/api/assets/%d/intelligence/%d/traffic/credential-proof", assetID, item.ID), ""); r.Code != 200 {
		t.Fatal("asset read failed", r.Code, r.Body)
	}
	_, _ = s.m.traffic.DB().Exec(`DELETE FROM exchange_bodies WHERE id='credential-proof'`)
	_, _ = s.m.traffic.DB().Exec(`DELETE FROM exchanges WHERE id='credential-proof'`)
	if r = request("GET", base, ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"unavailable":true`) || !strings.Contains(r.Body.String(), "qa-pass-321") {
		t.Fatal("saved excerpt lost", r.Code, r.Body)
	}
	// 重新整理必须保留既有绑定与片段（原始流量已删）。
	if r = request("POST", fmt.Sprintf("/api/tasks/%d/intelligence/%d/credentials/retry", taskID, item.ID), ""); r.Code != 202 {
		t.Fatal(r.Code, r.Body)
	}
	repeat, err := s.m.pg.ClaimCredentialJob(t.Context(), true, taskID)
	if err != nil || repeat == nil {
		t.Fatal(err)
	}
	s.processCredentialJob(t.Context(), repeat)
	preserved, _ := s.m.pg.GetIntelligence(t.Context(), item.ID)
	if len(preserved.Credentials.Traffic) != 1 || preserved.Credentials.Traffic[0].ID != "credential-proof" {
		t.Fatal("retry lost saved evidence")
	}
	// 散文凭据走隔离模型通道恰好一次，用量归账到专用 lane——即使正文录制关闭。
	in.Title = "prose fixture"
	in.Content = "qa-user 的密码为 qa-pass-321"
	prose, err := s.m.pg.RecordIntelligence(t.Context(), taskID, 0, "fixture", in)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.m.pg.ClaimCredentialJob(t.Context(), true, taskID)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	s.processCredentialJob(t.Context(), job)
	got, _ = s.m.pg.GetIntelligence(t.Context(), prose.ID)
	if got.Credentials.Method != "agent" || mock.calls != 1 || got.Credentials.InputTokens != 88 {
		t.Fatalf("model: %+v calls=%d", got.Credentials, mock.calls)
	}
	var count int
	err = s.m.pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1 AND worker=$2 AND input_tokens=88`, fmt.Sprint(taskID), db.CredentialAgentKey).Scan(&count)
	if err != nil || count != 1 {
		t.Fatal("usage not attributed", count, err)
	}
	if r = request("PUT", "/api/settings", `{"credential_agent_enabled":false}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if s.m.pg.GetBool(db.SettingCredentialTraffic, true) {
		t.Fatal("dependent switch not cleared")
	}
	if r = request("POST", fmt.Sprintf("/api/tasks/%d/intelligence/%d/credentials/retry", taskID, item.ID), ""); r.Code != 409 {
		t.Fatal("off retry accepted", r.Code)
	}
	list := request("GET", fmt.Sprintf("/api/tasks/%d/intelligence", taskID), "")
	var page db.IntelligencePage
	if err = json.Unmarshal(list.Body.Bytes(), &page); err != nil || len(page.Items) != 2 || page.CredentialAgentEnabled || page.Items[0].Credentials == nil {
		t.Fatal("off hid derived credentials", err)
	}
}

type blockingCredentialProvider struct{ entered chan struct{} }

func (p *blockingCredentialProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	close(p.entered)
	<-ctx.Done()
	return llm.Message{}, "", llm.Usage{}, errors.New("cancelled fixture")
}
func (*blockingCredentialProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) { panic("unexpected streaming") }
}

// TestCredentialDisableCancelsInFlightModel（移植自 ARTEX）：关闭开关取消进行中的
// 模型调用；完成退回队列、原文不受影响；关闭期间不认领新运行。
func TestCredentialDisableCancelsInFlightModel(t *testing.T) {
	credentialDSNOrSkip(t)
	s, f, request := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := *finding.TaskID
	oldRecording := s.m.pg.GetBool(db.SettingTaskIntelligence, false)
	oldOn, oldBinding := s.m.pg.GetBool(db.SettingCredentialAgent, false), s.m.pg.GetBool(db.SettingCredentialTraffic, false)
	defer func() {
		_ = s.m.pg.SetBool(db.SettingTaskIntelligence, oldRecording)
		_ = s.m.pg.SetCredentialAgentSettings(t.Context(), &oldOn, nil)
		if oldOn {
			_ = s.m.pg.SetCredentialAgentSettings(t.Context(), nil, &oldBinding)
		}
	}()
	on := true
	_ = s.m.pg.SetIntelligenceSettings(t.Context(), &on, &on, nil)
	item, err := s.m.pg.RecordIntelligence(t.Context(), taskID, 0, "fixture", db.IntelligenceInput{Kind: "credential", Title: "cancel fixture", Content: "qa-user 的密码为 qa-pass-321", Evidence: "local fixture", Confidence: "observed"})
	if err != nil {
		t.Fatal(err)
	}
	mock := &blockingCredentialProvider{entered: make(chan struct{})}
	s.llmOn = true
	s.llmProv = mock
	job, err := s.m.pg.ClaimCredentialJob(t.Context(), false, taskID)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s.processCredentialJob(t.Context(), job); close(done) }()
	select {
	case <-mock.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("model never started")
	}
	if r := request("PUT", "/api/settings", `{"credential_agent_enabled":false}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("switch did not cancel model")
	}
	got, err := s.m.pg.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.Credentials.State != "queued" || len(got.Credentials.Accounts) != 0 || got.Content != item.Content {
		t.Fatal("off published result or lost raw input", err)
	}
	if next, err := s.m.pg.ClaimCredentialJob(t.Context(), false, taskID); err != nil || next != nil {
		t.Fatal("off admitted a new run")
	}
}

// TestCredentialTokenMatchesWithoutUsername（移植自 ARTEX）：Token/Cookie 可不带
// 用户名独立命中；密码路径要求原文同时含密码与用户名。
func TestCredentialTokenMatchesWithoutUsername(t *testing.T) {
	a := db.CredentialAccount{Username: "qa-user", Password: "qa-pass-321", Token: "qa-token-123456"}
	if !credentialMatches(`{"token":"qa-token-123456"}`, a) {
		t.Fatal("token-only response not matched")
	}
	if !credentialMatches(`{"username":"qa-user","password":"qa-pass-321"}`, a) {
		t.Fatal("password request not matched when a token is also known")
	}
	if credentialMatches(`{"username":"other","password":"qa-pass-321"}`, a) {
		t.Fatal("other account incorrectly matched")
	}
}

// TestCredentialFailedModelCanRetry（移植自 ARTEX）：模型失败落 error 不自动重试；
// 显式重排队后恰好再调一次模型并成功。
func TestCredentialFailedModelCanRetry(t *testing.T) {
	credentialDSNOrSkip(t)
	s, f, request := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := *finding.TaskID
	oldRecord, oldAgent, oldBind := s.m.pg.GetBool(db.SettingTaskIntelligence, false), s.m.pg.GetBool(db.SettingCredentialAgent, false), s.m.pg.GetBool(db.SettingCredentialTraffic, false)
	defer s.m.pg.SetIntelligenceSettings(t.Context(), &oldRecord, &oldAgent, &oldBind)
	on, off := true, false
	_ = s.m.pg.SetIntelligenceSettings(t.Context(), &on, &on, &off)
	item, err := s.m.pg.RecordIntelligence(t.Context(), taskID, 0, "fixture", db.IntelligenceInput{Kind: "credential", Title: "retry fixture", Content: "qa-user 的密码为 qa-pass-321", Evidence: "local fixture", Confidence: "observed"})
	if err != nil {
		t.Fatal(err)
	}
	mock := &credentialServerProvider{invalid: true}
	s.llmOn = true
	s.llmProv = mock
	job, err := s.m.pg.ClaimCredentialJob(t.Context(), false, taskID)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	s.processCredentialJob(t.Context(), job)
	got, _ := s.m.pg.GetIntelligence(t.Context(), item.ID)
	if got.Credentials.State != "error" || mock.calls != 1 {
		t.Fatal("failure not recorded")
	}
	if again, err := s.m.pg.ClaimCredentialJob(t.Context(), false, taskID); err != nil || again != nil {
		t.Fatal("failed model automatically retried")
	}
	mock.invalid = false
	if r := request("POST", fmt.Sprintf("/api/tasks/%d/intelligence/%d/credentials/retry", taskID, item.ID), ""); r.Code != 202 {
		t.Fatal(r.Code, r.Body)
	}
	job, err = s.m.pg.ClaimCredentialJob(t.Context(), false, taskID)
	if err != nil || job == nil {
		t.Fatal(err)
	}
	s.processCredentialJob(t.Context(), job)
	got, _ = s.m.pg.GetIntelligence(t.Context(), item.ID)
	if got.Credentials.State != "ready" || len(got.Credentials.Accounts) != 1 || mock.calls != 2 {
		t.Fatal("explicit retry did not call model again")
	}
}
