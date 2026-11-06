package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/guard"
	"github.com/c1ayooo/4zreco/internal/intercept"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/c1ayooo/4zreco/internal/norma/permission"
	"github.com/c1ayooo/4zreco/internal/norma/tool"
)

// Exercise the actual SDK event -> hook -> execution -> result path. No real
// model or command is used; the probe tool only returns a fixed string.
func TestCaptureApprovalLifecycle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorConfig := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools); _ = ic.SetJudgeConfig(priorConfig) })
	if err := ic.SetEnabledTools([]string{"ApprovalAuditProbe"}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true, AskTimeoutSeconds: 1, AskTimeoutAction: "allow"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, action, status, execution string
		manual, approve, toolError      bool
	}{
		// An unusable verdict is a JUDGE FAILURE, not an allow: the configured
		// fail action is "ask" (a downed model must not silently allow), so the
		// call goes to the human queue, expires after AskTimeoutSeconds, and
		// only then releases through AskTimeoutAction. The row therefore
		// records "timeout", not "allowed" — the effective action is allow but
		// the approval path it travelled is the timeout one.
		{"model_fallback", "invalid", "timeout", "succeeded", false, false, false},
		{"model_allow", "allow", "allowed", "succeeded", false, false, false},
		{"model_deny", "deny", "denied", "not_executed", false, false, false},
		{"human_allow_tool_error", "ask", "allowed", "failed", true, true, true},
		{"human_deny", "ask", "denied", "not_executed", true, false, false},
		{"timeout_allow", "ask", "timeout", "succeeded", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
				return intercept.Decision{Action: tc.action, Message: "probe review", ProfileID: 7}, nil
			})
			g := guard.NewWithInterceptor(ic)
			taskID := "approval-lifecycle-" + tc.name
			t.Cleanup(func() { purgeAgentInterceptRows(t, d, taskID) })
			ctx := intercept.WithTaskContext(t.Context(), taskID, "test-agent", func(a db.Activity) {
				if a.Kind != "intercept_request" || !tc.manual {
					return
				}
				var detail struct {
					ID int64 `json:"pending_id"`
				}
				if err := json.Unmarshal([]byte(a.Detail), &detail); err != nil {
					t.Error(err)
					return
				}
				if err := ic.Decide(detail.ID, tc.approve, "4ZRECO"); err != nil {
					t.Error(err)
				}
			})
			turn, executions := 0, 0
			provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
				turn++
				events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
				if turn == 1 {
					events = []llm.StreamEvent{
						{Type: llm.SEToolUseStart, ToolID: "probe-call", ToolName: "ApprovalAuditProbe"},
						{Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"},
					}
				}
				for _, event := range events {
					if !yield(event, nil) {
						return
					}
				}
			}}
			probe := tool.Build(tool.Spec{Name: "ApprovalAuditProbe", Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					executions++
					if tc.toolError {
						return tool.Errorf("probe failed"), nil
					}
					return tool.Text("probe succeeded"), nil
				},
			})
			_, _, err := captureRun(ctx, askernel.Options{Model: acllm.BridgeModel(provider), Tools: []tool.CoreTool{probe}, Hooks: g.Hooks(),
				PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir(), MaxTurns: 2}, "record this review", nil)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := d.ListTaskIntercepts(taskID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%d err=%v", len(rows), err)
			}
			detail, err := d.GetInterceptDetail(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			a := detail.Audit
			initialAction := tc.action
			if tc.action == "invalid" {
				// An unusable verdict is a judge failure, and the fail action is
				// "ask": the recorded initial action is the ask it escalated to,
				// not an allow. The eventual allow comes from the ask timeout.
				initialAction = "ask"
			}
			wantUserMessage := "record this review"
			// A routine automatic allow (the model itself returned allow) keeps
			// decision/execution metadata but intentionally omits the bulky
			// replay context. Every other path — ask, deny, and the timeout
			// that releases a failed judge — keeps it, because a human looked
			// at the queue and the context is what they audit.
			if tc.status == "allowed" && initialAction == "allow" {
				wantUserMessage = ""
			}
			// P0-6 双维：ask_source=judge（模型判定）；decision_source 按决定路径
			// 归类（人工=human，规则/模型即时观测=auto，超时兜底=timeout）。
			decideSource := "auto"
			if tc.status == "timeout" {
				decideSource = "timeout"
			} else if tc.manual {
				decideSource = "human"
			}
			if detail.Status != tc.status || detail.AskSource != "judge" || detail.DecisionSource != decideSource || a == nil || a.ExecutionStatus != tc.execution || a.ToolUseID != "probe-call" || a.UserMessage != wantUserMessage || a.InitialAction != initialAction || a.ModelFallback != (tc.action == "invalid") || a.ProfileID != 7 {
				t.Fatalf("unexpected review: row=%+v audit=%+v", detail.InterceptApprovalRow, a)
			}
			if tc.status == "allowed" && initialAction == "allow" && (len(a.Context) != 0 || a.UserTruncated || a.ContextTruncated) {
				t.Fatalf("routine allow retained replay context: %+v", a)
			}
			wantCalls := 1
			if tc.execution == "not_executed" {
				wantCalls = 0
			}
			if executions != wantCalls {
				t.Fatalf("tool ran %d times, wanted %d", executions, wantCalls)
			}
		})
	}
}
