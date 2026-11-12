package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/config"
	"github.com/c1ayooo/4zreco/internal/db"
)

func TestTaskMetadataPatchReturnsRenameAndPin(t *testing.T) {
	m, err := NewManager(testDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("metadata patch", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()
	s := New(context.Background(), m, config.Paths{Skills: testDir(t), Data: testDir(t), Base: testDir(t)})
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"name": "  renamed task  ", "pinned": true})
	req := httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Name     string `json:"name"`
		Pinned   bool   `json:"pinned"`
		PinnedAt string `json:"pinned_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed task" || !updated.Pinned || updated.PinnedAt == "" {
		t.Fatalf("unexpected task patch response: %+v", updated)
	}

	body, _ = json.Marshal(map[string]any{"name": strings.Repeat("任", maxTaskNameRunes+1)})
	req = httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong task name status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTaskMetadataPatchRemark(t *testing.T) {
	m, err := NewManager(testDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("metadata remark patch", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()
	s := New(context.Background(), m, config.Paths{Skills: testDir(t), Data: testDir(t), Base: testDir(t)})
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}

	// remark-only patch：只带 remark 也能通过校验并回写。
	body, _ := json.Marshal(map[string]any{"remark": "  外网入口，弱口令已确认  "})
	req := httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remark patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Remark string `json:"remark"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Remark != "外网入口，弱口令已确认" {
		t.Fatalf("remark not trimmed/persisted: %q", updated.Remark)
	}

	// 超 2000 rune 拒绝（HTTP 层与 db 层同一上限）。
	body, _ = json.Marshal(map[string]any{"remark": strings.Repeat("界", db.MaxTaskRemarkRunes+1)})
	req = httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong remark status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 空补丁拒绝。
	body, _ = json.Marshal(map[string]any{})
	req = httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty patch status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 边界值 2000 rune 通过，且 DB 落盘值与响应一致。
	body, _ = json.Marshal(map[string]any{"remark": strings.Repeat("界", db.MaxTaskRemarkRunes)})
	req = httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("boundary remark status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("界", db.MaxTaskRemarkRunes)
	if updated.Remark != want {
		t.Fatalf("boundary remark not echoed (len=%d)", len([]rune(updated.Remark)))
	}
	persisted, err := m.pg.GetTask(taskID)
	if err != nil || persisted == nil || persisted.Remark != want {
		t.Fatalf("boundary remark not persisted: %+v, %v", persisted, err)
	}
}

func TestConversationBatchDeleteReportsMissing(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, config.Paths{Skills: t.TempDir(), Data: t.TempDir(), Base: t.TempDir()})
	first, err := m.pg.CreateConversation("mainagent", "batch-http-first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.pg.CreateConversation("mainagent", "batch-http-second", nil)
	if err != nil {
		_ = m.pg.DeleteConversation(first.ID)
		t.Fatal(err)
	}
	defer func() {
		_ = m.pg.DeleteConversation(first.ID)
		_ = m.pg.DeleteConversation(second.ID)
	}()
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	missing := int64(1<<62 - 1)
	body, _ := json.Marshal(map[string]any{"ids": []int64{first.ID, missing, second.ID}})
	req := httptest.NewRequest(http.MethodPost, "/api/conversations/delete/batch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []conversationDeleteItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 3 || !response.Items[0].OK || response.Items[1].OK || !response.Items[2].OK {
		t.Fatalf("batch delete response=%+v", response.Items)
	}
	for _, id := range []int64{first.ID, second.ID} {
		if conversation, err := m.pg.GetConversation(id); err != nil || conversation != nil {
			t.Fatalf("conversation %d still exists: %+v err=%v", id, conversation, err)
		}
	}
	if response.Items[1].Error == "" {
		t.Fatalf("missing conversation %s must include an error", fmt.Sprint(missing))
	}
}
