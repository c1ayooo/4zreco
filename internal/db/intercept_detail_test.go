package db

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInterceptDetails(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "approval-detail-test"
	// Cleanup LIFO：先清行，再把链头回拨到存活行。
	t.Cleanup(func() { rewindChainHeadToSurvivors(t, d) })
	t.Cleanup(func() { purgeInterceptRows(t, d, scope) })
	create := func(t *testing.T, audit *InterceptAudit) int64 {
		t.Helper()
		id, err := d.CreateInterceptPending(0, 0, scope, "test", "Write", []byte(`{"path":"report.md"}`), "[模型] 请确认", "judge", audit)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	t.Run("legacy and lazy payload", func(t *testing.T) {
		id := create(t, nil)
		got, err := d.GetInterceptDetail(id)
		if err != nil || got == nil || got.Audit != nil {
			t.Fatalf("legacy: %+v %v", got, err)
		}
		create(t, &InterceptAudit{UserMessage: "snapshot-only-marker", InitialAction: "ask"})
		items, err := d.ListTaskIntercepts(scope)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(items)
		if strings.Contains(string(raw), "snapshot-only-marker") || strings.Contains(string(raw), `"audit"`) {
			t.Fatal("snapshot leaked into list response")
		}
		missing, err := d.GetInterceptDetail(-1)
		if err != nil || missing != nil {
			t.Fatal("missing record not reported")
		}
		// 复核回归：决定不存在的 pending id 返回 (false, nil)（HTTP 409），
		// 不得以 decisions.pending_id FK 违规透出 500。
		ok, err := d.ResolveIntercept(-1, "allowed", "allow", "人工允许执行", "admin", "human")
		if err != nil || ok {
			t.Fatalf("nonexistent pending decide: ok=%v err=%v", ok, err)
		}
	})
	t.Run("decision race and exact output", func(t *testing.T) {
		id := create(t, &InterceptAudit{RunID: "run", ToolUseID: "call", Correlation: "exact", InitialAction: "ask", ExecutionStatus: "not_started"})
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				ok, err := d.ResolveIntercept(id, "allowed", "allow", "人工允许执行", "admin", "human")
				if err != nil {
					t.Error(err)
				}
				if ok {
					wins.Add(1)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d decisions won", wins.Load())
		}
		ok, err := d.ResolveIntercept(id, "timeout", "deny", "late timeout", "", "timeout")
		if err != nil || ok {
			t.Fatal("timeout overwrote decision")
		}
		if err := d.CompleteIntercept(id, "different-run", "call", "succeeded", "WRONG", false); err != nil {
			t.Fatal(err)
		}
		got, _ := d.GetInterceptDetail(id)
		if got.Audit.Output != "" {
			t.Fatal("cross-run result attached")
		}
		if err := d.CompleteIntercept(id, "run", "call", "failed", "permission denied", true); err != nil {
			t.Fatal(err)
		}
		got, err = d.GetInterceptDetail(id)
		if err != nil || got.Status != "allowed" || got.Audit.InitialAction != "ask" || got.Audit.ExecutionStatus != "failed" || !got.Audit.OutputTruncated {
			t.Fatalf("wrong details: %+v %v", got, err)
		}
		if err := d.CompleteIntercept(id, "run", "call", "succeeded", "late duplicate", false); err != nil {
			t.Fatal(err)
		}
		got, _ = d.GetInterceptDetail(id)
		if got.Audit.Output != "permission denied" {
			t.Fatal("duplicate result rewrote output")
		}
	})
	t.Run("denied output and timeout allow", func(t *testing.T) {
		id := create(t, &InterceptAudit{RunID: "run", ToolUseID: "call", ExecutionStatus: "not_started"})
		if _, err := d.ResolveIntercept(id, "denied", "deny", "人工拒绝", "admin", "human"); err != nil {
			t.Fatal(err)
		}
		if err := d.CompleteIntercept(id, "run", "call", "failed", "Blocked by hook", false); err != nil {
			t.Fatal(err)
		}
		got, _ := d.GetInterceptDetail(id)
		if got.Audit.ExecutionStatus != "not_executed" || got.Audit.Output != "" {
			t.Fatal("denial presented as executed")
		}
		id = create(t, &InterceptAudit{RunID: "run2", ToolUseID: "call2", Correlation: "exact", InitialAction: "ask"})
		if _, err := d.ResolveIntercept(id, "timeout", "allow", "超时允许", "", "timeout"); err != nil {
			t.Fatal(err)
		}
		if err := d.CompleteIntercept(id, "run2", "call2", "succeeded", "ok", false); err != nil {
			t.Fatal(err)
		}
		got, _ = d.GetInterceptDetail(id)
		if got.Status != "timeout" || got.Audit.EffectiveAction != "allow" || got.Audit.ExecutionStatus != "succeeded" {
			t.Fatal("timeout action lost")
		}
		if got.DecisionSource != "timeout" || got.DecidedBy != "" {
			t.Fatalf("timeout decision fields: %s/%s", got.DecisionSource, got.DecidedBy)
		}
	})
	t.Run("archive compatibility", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			legacy bool
		}{{"old snapshot with status keys", true}, {"new snapshot without them", false}} {
			t.Run(tc.name, func(t *testing.T) {
				var maxID int64
				if err := d.QueryRow(`SELECT COALESCE(max(id),0) FROM intercept_pending`).Scan(&maxID); err != nil {
					t.Fatal(err)
				}
				restoredID := maxID + 1
				row := map[string]any{
					"id": restoredID, "rule_id": nil, "conversation_id": nil,
					"task_id": scope, "agent_name": "archived", "tool_name": "Write",
					"tool_input": map[string]any{"path": "report.md"},
					"reason":     "[模型] 请确认", "created_at": "2026-01-01T00:00:00Z",
					"ask_source": "model", "kind": "judge",
				}
				if tc.legacy {
					// 旧格式快照：列已删除的键仍在 JSON 里，restore 必须消化它们。
					row["status"] = "pending"
					row["decided_at"] = nil
					row["decision_source"] = ""
				} else {
					delete(row, "ask_source")
					delete(row, "kind")
				}
				archived, _ := json.Marshal([]map[string]any{row})
				tx, err := d.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback() //nolint:errcheck
				if err := restoreInterceptRows(tx, archived, nil, nil); err != nil {
					t.Fatalf("legacy=%t: %v", tc.legacy, err)
				}
				var status, source string
				var auditJSON []byte
				if err := tx.QueryRow(`SELECT status, ask_source, audit FROM v_intercept WHERE id=$1`, restoredID).Scan(&status, &source, &auditJSON); err != nil {
					t.Fatal(err)
				}
				if status != "timeout" || source != "model" {
					t.Fatalf("restored %s/%s", status, source)
				}
				if tc.legacy && len(auditJSON) > 0 {
					t.Fatal("fabricated legacy audit")
				}
				if !tc.legacy && len(auditJSON) > 0 {
					t.Fatal("unexpected audit for audit-less snapshot row")
				}
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}
