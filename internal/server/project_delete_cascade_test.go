package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/config"
)

// DELETE /api/projects/{id} 随项目一并删除挂载的任务与对话（2026-11-19 语义修订，
// 原「解除挂载」口径）。未挂项目的任务必须存活；归档冷任务不在级联范围
// （ProjectLiveTaskIDs 已排除，此处不覆盖归档机）。
func TestDeleteProjectDeletesAttachedTasksAndConversations(t *testing.T) {
	m, err := NewManager(testDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, config.Paths{Skills: testDir(t), Data: testDir(t), Base: testDir(t)})
	h := s.Handler()
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, body any) (int, map[string]any) {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	// doRetry retries on 5xx (transient DB conflicts from parallel test packages).
	doRetry := func(method, path string, body any) (int, map[string]any) {
		var code int
		var out map[string]any
		for i := 0; i < 5; i++ {
			code, out = do(method, path, body)
			if code < 500 {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		return code, out
	}

	code, out := doRetry("POST", "/api/projects", map[string]string{"name": "级联删除测试项目"})
	if code != http.StatusCreated {
		t.Fatalf("create project: %d (%v)", code, out)
	}
	projectID := int64(out["id"].(float64))

	code, out = doRetry("POST", "/api/tasks", map[string]any{"description": "挂项目任务", "goal": "g", "project_id": projectID})
	if code != http.StatusCreated {
		t.Fatalf("create attached task: %d (%v)", code, out)
	}
	idAttached, _ := out["id"].(string)
	code, out = doRetry("POST", "/api/tasks", map[string]string{"description": "不挂项目任务", "goal": "g"})
	if code != http.StatusCreated {
		t.Fatalf("create bare task: %d (%v)", code, out)
	}
	idBare, _ := out["id"].(string)
	// 兜底清理：项目删除失败时任务仍在，别把测试库留脏。
	defer func() {
		for _, id := range []string{idAttached, idBare} {
			if n, err := strconv.ParseInt(id, 10, 64); err == nil {
				_ = m.pg.DeleteTask(n)
			}
		}
		_ = m.pg.Projects().DeleteProject(projectID)
	}()

	code, out = doRetry("POST", "/api/conversations", map[string]string{"agent_key": "auto", "title": "挂项目对话"})
	if code != http.StatusOK {
		t.Fatalf("create conversation: %d (%v)", code, out)
	}
	convID := int64(out["id"].(float64))
	code, out = doRetry("PATCH", "/api/conversations/"+strconv.FormatInt(convID, 10), map[string]any{"project_id": projectID})
	if code != http.StatusOK {
		t.Fatalf("attach conversation: %d (%v)", code, out)
	}

	code, out = doRetry("DELETE", "/api/projects/"+strconv.FormatInt(projectID, 10), nil)
	if code != http.StatusOK {
		t.Fatalf("delete project: %d (%v)", code, out)
	}
	if n := out["tasks_deleted"].(float64); n != 1 {
		t.Fatalf("tasks_deleted=%v, want 1", out["tasks_deleted"])
	}
	if n := out["conversations_deleted"].(float64); n != 1 {
		t.Fatalf("conversations_deleted=%v, want 1", out["conversations_deleted"])
	}

	code, out = doRetry("GET", "/api/tasks", nil)
	if code != http.StatusOK {
		t.Fatalf("list tasks after delete: %d (%v)", code, out)
	}
	ids := map[string]bool{}
	tasks, _ := out["tasks"].([]any)
	for _, raw := range tasks {
		task, _ := raw.(map[string]any)
		id, _ := task["id"].(string)
		ids[id] = true
	}
	if ids[idAttached] {
		t.Fatalf("attached task %s survived project deletion", idAttached)
	}
	if !ids[idBare] {
		t.Fatalf("bare task %s must survive project deletion", idBare)
	}

	// 空列表序列化为 null（Go nil 切片），断言用逗号形式吞掉 nil。
	code, out = doRetry("GET", "/api/conversations", nil)
	if code != http.StatusOK {
		t.Fatalf("list conversations after delete: %d (%v)", code, out)
	}
	convs, _ := out["conversations"].([]any)
	for _, raw := range convs {
		conv, _ := raw.(map[string]any)
		if id := conv["id"].(float64); int64(id) == convID {
			t.Fatalf("attached conversation %d survived project deletion", convID)
		}
	}

	code, out = doRetry("GET", "/api/projects", nil)
	if code != http.StatusOK {
		t.Fatalf("list projects after delete: %d (%v)", code, out)
	}
	projects, _ := out["projects"].([]any)
	for _, raw := range projects {
		p, _ := raw.(map[string]any)
		if id := p["id"].(float64); int64(id) == projectID {
			t.Fatalf("project %d survived deletion", projectID)
		}
	}
}
