package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// PATCH /api/conversations/{id} 的项目归属口径（2026-11-04 修订）：对话只绑任务，
// 项目经任务传递——绑定任务自动对齐到任务所属项目；解绑任务（task_id=0）且未
// 显式给项目时，项目归属一并解除，不留孤儿归属。
func TestConversationTaskBindingAlignsAndClearsProject(t *testing.T) {
	s, _ := newRetestServer(t)
	pg := s.m.pg
	conv, err := pg.CreateConversation("auto", "task binding project test", nil)
	if err != nil {
		t.Fatal(err)
	}
	project, err := pg.Projects().CreateProject("绑定对齐测试项目", "")
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("绑定对齐测试任务", "目标", db.TaskCreateOptions{ProjectID: &project.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
		_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_ = pg.Projects().DeleteProject(project.ID)
	})

	patch := func(t *testing.T, body string) map[string]any {
		t.Helper()
		w := retestRequest(s.pgRenameConversation, http.MethodPatch, conv.ID, body)
		if w.Code != http.StatusOK {
			t.Fatalf("patch %s: status=%d body=%s", body, w.Code, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	projectIDOf := func(t *testing.T) float64 {
		t.Helper()
		got, err := pg.GetConversation(conv.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.ProjectID == nil {
			return 0
		}
		return float64(*got.ProjectID)
	}

	// 绑定任务（只发 task_id）→ 项目自动对齐到任务所属项目。
	out := patch(t, `{"task_id": `+strconv.FormatInt(task.ID, 10)+`}`)
	if id, _ := out["task_id"].(float64); id != float64(task.ID) {
		t.Fatalf("task_id=%v, want %d", out["task_id"], task.ID)
	}
	if got := projectIDOf(t); got != float64(project.ID) {
		t.Fatalf("after bind project_id=%v, want %d", got, project.ID)
	}

	// 解绑任务（只发 task_id=0）→ 项目归属一并解除。
	patch(t, `{"task_id": 0}`)
	if got := projectIDOf(t); got != 0 {
		t.Fatalf("after unbind project_id=%v, want 0", got)
	}
}
