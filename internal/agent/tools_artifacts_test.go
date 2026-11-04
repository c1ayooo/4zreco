package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// TestListArtifactsResolvesTaskFromFinding v0.4.20：reporter 没有任务上下文，
// list_artifacts 必须能用 finding_id 反查任务，否则永远返回空列表。
func TestListArtifactsResolvesTaskFromFinding(t *testing.T) {
	oldList, oldFind := ListTaskArtifacts, FindingTaskID
	defer func() { ListTaskArtifacts, FindingTaskID = oldList, oldFind }()

	var gotTask string
	ListTaskArtifacts = func(taskID string) ([]db.TaskArtifact, error) {
		gotTask = taskID
		return []db.TaskArtifact{{ID: 9, TaskID: taskID, Name: "proof.png", Kind: "image"}}, nil
	}
	FindingTaskID = func(findingID int64) (string, error) {
		if findingID != 42 {
			t.Fatalf("findingID=%d want 42", findingID)
		}
		return "7", nil
	}

	ts := NewToolSet(nil, "reporter") // 刻意不 SetTaskID：模拟 reporter 的 chat 工具集
	tool := ts.listArtifacts()
	in, _ := json.Marshal(map[string]any{"finding_id": 42})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotTask != "7" {
		t.Fatalf("taskID=%q want 7", gotTask)
	}
	if !strings.Contains(toolResultText(t, res), "proof.png") {
		t.Fatalf("result missing artifact: %s", toolResultText(t, res))
	}
}

// TestListArtifactsWithoutContextStaysEmpty：没有 taskID 也没有 finding_id 时
// 不应误查其他任务（返回空列表而不是报错）。
func TestListArtifactsWithoutContextStaysEmpty(t *testing.T) {
	oldList := ListTaskArtifacts
	defer func() { ListTaskArtifacts = oldList }()
	ListTaskArtifacts = func(taskID string) ([]db.TaskArtifact, error) {
		t.Fatalf("must not query without task context, got %q", taskID)
		return nil, nil
	}
	ts := NewToolSet(nil, "reporter")
	tool := ts.listArtifacts()
	res, err := tool.Call(context.Background(), []byte(`{}`), nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if strings.TrimSpace(toolResultText(t, res)) != "[]" {
		t.Fatalf("want [], got %s", toolResultText(t, res))
	}
}
