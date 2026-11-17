package intercept

import (
	"context"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/internal/db"
)

func TestTraceExactCorrelationAndSnapshot(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), "save report", []db.InterceptContextEntry{{Kind: "user", Text: "prior message"}})
	trace.Start("call-a", "Write", []byte(`{"path":"a","n":12345678901234567890}`))
	trace.Append(db.InterceptContextEntry{Kind: "text", Text: "later context"})
	callCtx := WithCall(ctx, "Write", []byte(`{ "n":12345678901234567890, "path":"a" }`))
	// "pending" (the ask path) keeps the full snapshot; see TestAuditAllowDropsSnapshot
	// for why a routine allow does not.
	a := auditFor(callCtx, Decision{Action: "ask"}, nil, "pending")
	if a.Correlation != "exact" || a.ToolUseID != "call-a" || len(a.Context) != 1 || a.Context[0].Text != "prior message" {
		t.Fatalf("wrong snapshot: %+v", a)
	}
	var got string
	trace.bind("call-a", func(status, output string, cut bool) { got = status + ":" + output })
	trace.Complete("different-call", "wrong", false)
	if got != "" {
		t.Fatal("unrelated result attached")
	}
	trace.Complete("call-a", "written", false)
	trace.Finish()
	if got != "succeeded:written" {
		t.Fatalf("result %q", got)
	}
}

// A rule allow is logged for auditability but must not carry the replay
// snapshot: with the fallback judge on those rows are emitted per tool call, and
// keeping 24×8KiB of context plus a 32KiB prompt each would put hundreds of MB
// into intercept_pending (and from there into the task archive). Decision
// metadata and correlation must survive so the execution result still binds.
func TestAuditAllowDropsSnapshot(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), "a long user prompt", []db.InterceptContextEntry{{Kind: "user", Text: "prior message"}})
	input := []byte(`{"path":"a"}`)
	trace.Start("call-a", "Write", input)
	a := auditFor(WithCall(ctx, "Write", input), Decision{Action: "allow", RuleName: "auto"}, input, "allowed")
	if a.UserMessage != "" || a.UserTruncated || a.Context != nil || a.ContextTruncated {
		t.Fatalf("allow kept the replay snapshot: %+v", a)
	}
	if a.Correlation != "exact" || a.ToolUseID != "call-a" || a.EffectiveAction != "allow" ||
		a.ExecutionStatus != "awaiting_result" || a.RuleName != "auto" || a.InputDigest == "" {
		t.Fatalf("allow lost decision metadata: %+v", a)
	}

	// A denial is rare and worth the full context, so it keeps its snapshot.
	denied := []byte(`{"path":"b"}`)
	trace.Start("call-b", "Write", denied)
	d := auditFor(WithCall(ctx, "Write", denied), Decision{Action: "deny"}, denied, "denied")
	if len(d.Context) == 0 || d.Context[0].Text != "prior message" || d.UserMessage == "" {
		t.Fatalf("deny lost the snapshot: %+v", d)
	}
}

func TestTraceIdenticalParallelCallsAreNeverGuessed(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), "test", nil)
	input := []byte(`{"command":"pwd"}`)
	trace.Start("first", "Bash", input)
	trace.Start("second", "Bash", input)
	for range 2 {
		a := auditFor(WithCall(ctx, "Bash", input), Decision{}, input, "pending")
		if a.Correlation != "ambiguous" || a.ToolUseID != "" {
			t.Fatalf("guessed identity: %+v", a)
		}
	}
	trace.Complete("first", "first-result", false)
	a := auditFor(WithCall(ctx, "Bash", input), Decision{}, input, "pending")
	if a.Correlation != "ambiguous" {
		t.Fatal("ambiguity must survive the other call completing")
	}
}

func TestTraceSequentialIdenticalCallsAndRunIsolation(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), "test", nil)
	input := []byte(`{}`)
	trace.Start("a", "Read", input)
	a := auditFor(WithCall(ctx, "Read", input), Decision{}, input, "pending")
	trace.Start("b", "Read", input)
	b := auditFor(WithCall(ctx, "Read", input), Decision{}, input, "pending")
	other, next := WithTrace(context.Background(), "next run", nil)
	next.Start("a", "Read", input)
	c := auditFor(WithCall(other, "Read", input), Decision{}, input, "pending")
	if a.ToolUseID != "a" || b.ToolUseID != "b" || a.RunID == c.RunID {
		t.Fatal("run or call identities overlap")
	}
}

func TestTraceBoundsAndMissingResult(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), strings.Repeat("中文", promptLimit), nil)
	for range contextLimit + 5 {
		trace.Append(db.InterceptContextEntry{Kind: "text", Text: strings.Repeat("中", entryLimit)})
	}
	trace.Start("a", "Read", []byte(`{}`))
	a := auditFor(WithCall(ctx, "Read", []byte(`{}`)), Decision{}, nil, "pending")
	if !a.UserTruncated || !a.ContextTruncated || len(a.Context) != contextLimit || !utf8.ValidString(a.UserMessage) {
		t.Fatal("unbounded/invalid snapshot")
	}
	for _, e := range a.Context {
		if len(e.Text) > entryLimit || !utf8.ValidString(e.Text) {
			t.Fatal("invalid entry bound")
		}
	}
	got := ""
	trace.bind("a", func(status, _ string, _ bool) { got = status })
	trace.Finish()
	if got != "unknown" {
		t.Fatalf("missing result presented as %q", got)
	}
}

func TestTraceConcurrentDistinctCalls(t *testing.T) {
	ctx, trace := WithTrace(context.Background(), "test", nil)
	var wg sync.WaitGroup
	for _, id := range []string{"a", "b", "c", "d"} {
		wg.Go(func() {
			input := []byte(`{"path":"` + id + `"}`)
			trace.Start(id, "Read", input)
			a := auditFor(WithCall(ctx, "Read", input), Decision{}, input, "allowed")
			if a.ToolUseID != id {
				t.Errorf("got %s for %s", a.ToolUseID, id)
			}
			trace.Complete(id, "ok", false)
		})
	}
	wg.Wait()
}

// StartMasked（F3 观测面凭据打码，2026-11-13）：上下文条目落打码后的输入，
// 但关联摘要仍按原文计算——guard 链 WithCall 用原文 input，exact 关联必须不受
// 观测面打码影响。
func TestTraceStartMaskedKeepsRawDigestAndMasksEntry(t *testing.T) {
	prior := db.InterceptContextEntry{Kind: "user", Text: "prior message"}
	ctx, trace := WithTrace(context.Background(), "凭据复用", []db.InterceptContextEntry{prior})
	raw := []byte(`{"asset_id":1,"password":"hunter2"}`)
	masked := []byte(`{"asset_id":1,"password":"******"}`)
	trace.StartMasked("call-m", "auth_request", raw, masked)

	if len(trace.entries) == 0 {
		t.Fatal("no entry appended")
	}
	entry := trace.entries[len(trace.entries)-1]
	if entry.Kind != "tool_use" || entry.ToolUseID != "call-m" {
		t.Fatalf("wrong entry: %+v", entry)
	}
	if entry.Text != string(masked) {
		t.Fatalf("entry text must be the masked input: %q", entry.Text)
	}

	a := auditFor(WithCall(ctx, "auth_request", raw), Decision{Action: "ask"}, raw, "pending")
	if a.Correlation != "exact" || a.ToolUseID != "call-m" {
		t.Fatalf("masking broke raw-digest correlation: %+v", a)
	}
	// 快照是本调用【之前】的上下文（prior），不含自己的 tool_use 条目。
	if len(a.Context) != 1 || a.Context[0].Text != "prior message" {
		t.Fatalf("unexpected snapshot: %+v", a.Context)
	}

	// 后续调用的快照必须携带打码后的 tool_use 条目（凭据不进审批上下文）。
	trace.StartMasked("call-n", "Read", []byte(`{"path":"a"}`), []byte(`{"path":"a"}`))
	b := auditFor(WithCall(ctx, "Read", []byte(`{"path":"a"}`)), Decision{Action: "ask"}, []byte(`{"path":"a"}`), "pending")
	var maskedSeen bool
	for _, e := range b.Context {
		if e.Kind == "tool_use" && e.ToolUseID == "call-m" {
			maskedSeen = e.Text == string(masked)
		}
	}
	if !maskedSeen {
		t.Fatalf("later snapshot must carry the masked tool_use entry: %+v", b.Context)
	}

	// 打码后的文本不能反向关联（原文摘要 ≠ 打码摘要）。
	c := auditFor(WithCall(ctx, "auth_request", masked), Decision{Action: "ask"}, masked, "pending")
	if c.Correlation == "exact" {
		t.Fatal("masked input must not correlate to the raw-digest binding")
	}
}
