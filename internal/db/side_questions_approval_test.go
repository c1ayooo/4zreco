package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/sidequestion"
)

// B2 审批旁路（第四类 parent）的存储层验收：
//   - 四种 parent 互斥：conv/task-main/task-worker/approval 各自可建，混搭被 CHECK 拒；
//   - 审批旁问快照只落 side_question_sessions，不碰 intercept 三表（append-only
//     语义不受影响，审批状态保持 pending）；
//   - 审批父会话的并发 1 / 幂等 client_id 协议与既有三类同源。
func TestSideApprovalParentExclusiveAndIsolated(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "side-approval-" + t.Name()
	t.Cleanup(func() { purgeInterceptRows(t, d, scope) })

	audit := &InterceptAudit{
		InitialAction: "ask", ExecutionStatus: "not_started",
		UserMessage: "审批旁路材料", InitialReason: "规则命中",
		ModelInput: json.RawMessage(`{"version":5,"script_files":[]}`),
	}
	approvalID, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{"command":"pwd"}`), "review", "judge", audit)
	if err != nil {
		t.Fatal(err)
	}

	keys := []string{
		fmt.Sprintf("approval-%d", approvalID),
		"approval-check-conv-" + fmt.Sprint(time.Now().UnixNano()),
		"approval-check-task-" + fmt.Sprint(time.Now().UnixNano()),
	}
	t.Cleanup(func() {
		for _, key := range keys {
			_, _ = d.Exec(`DELETE FROM side_question_sessions WHERE session_key=$1`, key)
		}
	})

	snap := sidequestion.Snapshot{
		Parent: sidequestion.Parent{ApprovalID: approvalID}, RunID: 7, Version: 1,
		CapturedAt: time.Now().UTC(), Model: sidequestion.Model{Model: "fixture"},
	}
	if err = d.SaveSideSnapshot(t.Context(), snap); err != nil {
		t.Fatal(err)
	}
	var gotKey string
	var convID, taskID, expID, intentID, approvalCol any
	if err = d.QueryRow(`SELECT session_key,conversation_id,task_id,exploration_id,intent_id,approval_id FROM side_question_sessions WHERE session_key=$1`, snap.Parent.Key()).Scan(&gotKey, &convID, &taskID, &expID, &intentID, &approvalCol); err != nil {
		t.Fatal(err)
	}
	if gotKey != fmt.Sprintf("approval-%d", approvalID) {
		t.Fatalf("session key %q", gotKey)
	}
	if convID != nil || taskID != nil || expID != nil || intentID != nil || approvalCol.(int64) != approvalID {
		t.Fatalf("approval parent columns: conv=%v task=%v exp=%v intent=%v approval=%v", convID, taskID, expID, intentID, approvalCol)
	}

	// 旁问只写 side_question_* 表：审批三表零写入，审批状态保持 pending。
	var reason string
	var decisions int
	if err = d.QueryRow(`SELECT reason FROM intercept_pending WHERE id=$1`, approvalID).Scan(&reason); err != nil || reason != "review" {
		t.Fatalf("pending mutated: reason=%q err=%v", reason, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE pending_id=$1`, approvalID).Scan(&decisions); err != nil || decisions != 0 {
		t.Fatalf("side question touched decisions: %d %v", decisions, err)
	}
	detail, err := d.GetInterceptDetail(approvalID)
	if err != nil || detail == nil || detail.Status != "pending" {
		t.Fatalf("approval status changed: %+v err=%v", detail, err)
	}

	// 四类互斥：任何两类 parent 字段混搭都过不了 CHECK（含 approval 与 conv/task 混搭）。
	cross := []string{
		// approval + conversation
		fmt.Sprintf(`INSERT INTO side_question_sessions(session_key,conversation_id,approval_id,run_id,version,snapshot) VALUES('%s',1,%d,1,1,'{}')`, keys[1], approvalID),
		// approval + task/exploration
		fmt.Sprintf(`INSERT INTO side_question_sessions(session_key,task_id,exploration_id,approval_id,run_id,version,snapshot) VALUES('%s',1,1,%d,1,1,'{}')`, keys[2], approvalID),
	}
	for _, stmt := range cross {
		if _, err = d.Exec(stmt); err == nil {
			t.Fatalf("mixed parent accepted: %s", stmt)
		}
	}

	// 四种 parent 各自独立可建（approval 已由 SaveSideSnapshot 覆盖，这里补
	// conv/task-main/task-worker 经既有 API 保存，证 CHECK 的四支互不吞并）。
	conv, err := d.CreateConversation("mainagent", "side approval exclusive", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(conv.ID) })
	task, err := d.CreateTask("side approval exclusive", "context", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	iid, err := d.Exploration(task.ExplorationID).AddNode(KindIntent, map[string]any{"summary": "worker"}, 1, "paused", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range []sidequestion.Parent{
		{ConversationID: conv.ID},
		{TaskID: task.ID, ExplorationID: task.ExplorationID},
		{TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: iid},
	} {
		s := snap
		s.Parent, s.RunID = parent, s.RunID+1
		if err = d.SaveSideSnapshot(t.Context(), s); err != nil {
			t.Fatalf("parent kind rejected: %v (%s)", err, s.Parent.Key())
		}
	}
}

func TestSideApprovalRequestDedupAndBusy(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "side-approval-dedup-" + t.Name()
	t.Cleanup(func() { purgeInterceptRows(t, d, scope) })
	approvalID, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{"command":"pwd"}`), "review", "judge",
		&InterceptAudit{InitialAction: "ask", ExecutionStatus: "not_started"})
	if err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("approval-%d", approvalID)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM side_question_sessions WHERE session_key=$1`, key) })

	snap := sidequestion.Snapshot{
		Parent: sidequestion.Parent{ApprovalID: approvalID}, RunID: 9, Version: 1,
		CapturedAt: time.Now().UTC(), Model: sidequestion.Model{Model: "fixture"},
	}
	if err = d.SaveSideSnapshot(t.Context(), snap); err != nil {
		t.Fatal(err)
	}
	first, created, err := d.StartSideRequest(t.Context(), snap, "request-0", "question-0")
	if err != nil || !created {
		t.Fatalf("start %v %v", created, err)
	}
	again, created, err := d.StartSideRequest(t.Context(), snap, "request-0", "question-0")
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("dedup %v %v", created, err)
	}
	if _, _, err = d.StartSideRequest(t.Context(), snap, "request-1", "question-1"); !errors.Is(err, ErrSideBusy) {
		t.Fatalf("busy %v", err)
	}
}
