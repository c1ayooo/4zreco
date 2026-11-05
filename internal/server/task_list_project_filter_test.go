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

// GET /api/tasks?project_id=N 只返回挂该项目的任务（项目主轴第二批：服务端过滤）。
// 挂项目走 POST /api/tasks 的 project_id（创建时定）；不挂项目的任务必须被过滤掉。
func TestListTasksFiltersByProject(t *testing.T) {
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
	taskIDs := func(body map[string]any) map[string]float64 {
		ids := map[string]float64{}
		rows, _ := body["tasks"].([]any)
		for _, raw := range rows {
			task, _ := raw.(map[string]any)
			id, _ := task["id"].(string)
			pid, _ := task["project_id"].(float64)
			ids[id] = pid
		}
		return ids
	}

	code, out := doRetry("POST", "/api/projects", map[string]string{"name": "过滤测试项目"})
	if code != http.StatusCreated {
		t.Fatalf("create project: %d (%v)", code, out)
	}
	projectID := int64(out["id"].(float64))
	defer func() { _ = m.pg.Projects().DeleteProject(projectID) }()

	code, out = doRetry("POST", "/api/tasks", map[string]any{"description": "挂项目", "goal": "g", "project_id": projectID})
	if code != http.StatusCreated {
		t.Fatalf("create attached task: %d (%v)", code, out)
	}
	idAttached, _ := out["id"].(string)
	code, out = doRetry("POST", "/api/tasks", map[string]string{"description": "不挂项目", "goal": "g"})
	if code != http.StatusCreated {
		t.Fatalf("create bare task: %d (%v)", code, out)
	}
	idBare, _ := out["id"].(string)
	defer func() {
		for _, id := range []string{idAttached, idBare} {
			if n, err := strconv.ParseInt(id, 10, 64); err == nil {
				_ = m.pg.DeleteTask(n)
			}
		}
	}()

	code, out = doRetry("GET", "/api/tasks?project_id="+strconv.FormatInt(projectID, 10), nil)
	if code != http.StatusOK {
		t.Fatalf("list filtered: %d (%v)", code, out)
	}
	filtered := taskIDs(out)
	if len(filtered) != 1 {
		t.Fatalf("expected exactly the attached task, got %v (project=%d)", filtered, projectID)
	}
	if _, ok := filtered[idAttached]; !ok {
		t.Fatalf("attached task %s missing from filtered list: %v", idAttached, filtered)
	}
	if _, ok := filtered[idBare]; ok {
		t.Fatalf("bare task %s leaked into filtered list: %v", idBare, filtered)
	}
	if pid := filtered[idAttached]; pid != float64(projectID) {
		t.Fatalf("attached task project_id=%v, want %d", pid, projectID)
	}

	code, out = doRetry("GET", "/api/tasks", nil)
	if code != http.StatusOK {
		t.Fatalf("list unfiltered: %d (%v)", code, out)
	}
	unfiltered := taskIDs(out)
	if _, ok := unfiltered[idAttached]; !ok {
		t.Fatalf("attached task missing from unfiltered list")
	}
	if _, ok := unfiltered[idBare]; !ok {
		t.Fatalf("bare task missing from unfiltered list")
	}
}
