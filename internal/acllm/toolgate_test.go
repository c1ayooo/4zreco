package acllm

// ToolGate tests: per-call ToolContext injection (ToolUseID = adk.ToolContext.
// CallID), the never-error endpoint contract, permission deny, OnResult
// observation, and the concurrency discipline exercised THROUGH the gate's
// WrapInvokableToolCall endpoints (barrier-synchronized, no sleeps).

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/cloudwego/eino/adk"
)

// barrierTool builds a CoreTool that signals started and blocks on release —
// the deterministic stand-in for "a tool executing right now".
func barrierTool(name string, safe bool, started chan<- struct{}, release <-chan struct{}) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "barrier " + name,
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return safe },
		Concurrent:  func(json.RawMessage) bool { return safe },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			started <- struct{}{}
			<-release
			return actool.Text(name + " done"), nil
		},
	})
}

// endpointOf asks the gate to wrap a call and returns the wrapped endpoint.
func endpointOf(t *testing.T, g *ToolGate, name, callID string) adk.InvokableToolCallEndpoint {
	t.Helper()
	ep, err := g.WrapInvokableToolCall(context.Background(), nil, &adk.ToolContext{Name: name, CallID: callID})
	if err != nil {
		t.Fatalf("WrapInvokableToolCall(%s) error: %v", name, err)
	}
	if ep == nil {
		t.Fatalf("WrapInvokableToolCall(%s) returned nil endpoint", name)
	}
	return ep
}

// TestGateInjectsToolContext: ToolUseID comes from adk.ToolContext.CallID;
// template fields ride along (§3.2 ToolUseID 行).
func TestGateInjectsToolContext(t *testing.T) {
	var sawUseID, sawDir string
	core := actool.Build(actool.Spec{
		Name:        "probe_ctx",
		Description: "captures its ToolContext",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			if tc == nil {
				return actool.Errorf("no ToolContext"), nil
			}
			sawUseID, sawDir = tc.ToolUseID, tc.WorkingDir
			return actool.Text("ok"), nil
		},
	})
	g := NewToolGate([]actool.CoreTool{core}, ToolTemplate{WorkingDir: "/task/run"}, 0)

	out, err := endpointOf(t, g, "probe_ctx", "call_42")(context.Background(), "{}")
	if err != nil {
		t.Fatalf("gate endpoint returned Go error: %v", err)
	}
	if out != "ok" || sawUseID != "call_42" || sawDir != "/task/run" {
		t.Fatalf("out=%q useID=%q dir=%q", out, sawUseID, sawDir)
	}
}

// TestGatePassesUnknownToolsThrough: a name the gate does not manage leaves the
// endpoint untouched (nil, meaning "no wrap") — kernel-assembly tools like the
// deferred access tools go through their own paths.
func TestGatePassesUnknownToolsThrough(t *testing.T) {
	g := NewToolGate(nil, ToolTemplate{}, 0)
	ep, err := g.WrapInvokableToolCall(context.Background(), nil, &adk.ToolContext{Name: "not_mine", CallID: "c1"})
	if err != nil {
		t.Fatalf("WrapInvokableToolCall error: %v", err)
	}
	if ep != nil {
		t.Fatalf("unmanaged tool was wrapped")
	}
}

// TestGateNeverReturnsGoError: a Go error from the tool becomes "Error: …"
// text with nil error — eino would otherwise treat it as run-fatal (norma
// semantics: tool failures are error tool_results the model reacts to).
func TestGateNeverReturnsGoError(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "fails",
		Description: "always fails",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Result{}, context.DeadlineExceeded
		},
	})
	g := NewToolGate([]actool.CoreTool{core}, ToolTemplate{}, 0)

	out, err := endpointOf(t, g, "fails", "c2")(context.Background(), "{}")
	if err != nil {
		t.Fatalf("tool error leaked as Go error: %v", err)
	}
	if out != "Error: context deadline exceeded" {
		t.Fatalf("error text: %q", out)
	}
}

// TestGatePermissionDeny: a non-bypass mode + a tool that hard-denies produces
// the norma harness's denial text without running the tool.
func TestGatePermissionDeny(t *testing.T) {
	ran := false
	core := actool.Build(actool.Spec{
		Name:        "guarded",
		Description: "denies itself",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Denied("not in scope")
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			ran = true
			return actool.Text("ran"), nil
		},
	})
	g := NewToolGate([]actool.CoreTool{core}, ToolTemplate{}, 0).SetPermissionMode(acperm.ModeDefault)

	out, err := endpointOf(t, g, "guarded", "c3")(context.Background(), "{}")
	if err != nil {
		t.Fatalf("denial leaked as Go error: %v", err)
	}
	if out != "Tool call was not permitted: not in scope" {
		t.Fatalf("denial text: %q", out)
	}
	if ran {
		t.Fatalf("denied tool ran anyway")
	}
}

// TestGatePermissionPolicyLists: full norma pipeline parity — the deny list is
// a stage-1 absolute denial, the allow list auto-allows at the rule stage, and
// both ride acperm.Context the way norma harness/tools.go feeds them.
func TestGatePermissionPolicyLists(t *testing.T) {
	ran := false
	writeish := actool.Build(actool.Spec{
		Name:        "writey",
		Description: "not read-only, no self-verdict",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Decision{} // neutral — verdict comes from rules/mode/ask
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			ran = true
			return actool.Text("wrote"), nil
		},
	})

	// Deny rules win absolutely — even in bypass mode (permission.go stage 1).
	gDeny := NewToolGate([]actool.CoreTool{writeish}, ToolTemplate{}, 0).
		SetPermissionMode(acperm.ModeBypass).
		SetDenyRules([]string{"writey"})
	out, _ := endpointOf(t, gDeny, "writey", "d1")(context.Background(), "{}")
	if out != "Tool call was not permitted: denied: tool 'writey' is disallowed by policy" || ran {
		t.Fatalf("deny rule not enforced: %q ran=%v", out, ran)
	}

	// Allow rules auto-allow a non-read-only tool in default mode (stage 3).
	ran = false
	gAllow := NewToolGate([]actool.CoreTool{writeish}, ToolTemplate{}, 0).
		SetPermissionMode(acperm.ModeDefault).
		SetAllowRules([]string{"writey"})
	out, _ = endpointOf(t, gAllow, "writey", "a1")(context.Background(), "{}")
	if out != "wrote" || !ran {
		t.Fatalf("allow rule not honored: %q ran=%v", out, ran)
	}

	// Without the allow rule, default mode + no ask callback denies (stage 4).
	ran = false
	gNone := NewToolGate([]actool.CoreTool{writeish}, ToolTemplate{}, 0).
		SetPermissionMode(acperm.ModeDefault)
	out, _ = endpointOf(t, gNone, "writey", "n1")(context.Background(), "{}")
	if out != "Tool call was not permitted: denied: no approval handler configured for 'writey'" || ran {
		t.Fatalf("unhandled ask did not deny: %q ran=%v", out, ran)
	}
}

// TestGateAskCallback: a wired ask callback is consulted at stage 4 with the
// same Context the tool's CheckPermissions saw; its verdict decides execution.
func TestGateAskCallback(t *testing.T) {
	ran := false
	var sawName, sawInput string
	var sawMode acperm.Mode
	writeish := actool.Build(actool.Spec{
		Name:        "writey",
		Description: "not read-only, no self-verdict",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Decision{} // neutral — reach the ask stage
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			ran = true
			return actool.Text("wrote"), nil
		},
	})

	gAllow := NewToolGate([]actool.CoreTool{writeish}, ToolTemplate{WorkingDir: "/task/x"}, 0).
		SetPermissionMode(acperm.ModeDefault).
		SetAsk(func(_ context.Context, toolName string, input json.RawMessage, pc acperm.Context) acperm.Decision {
			sawName, sawInput, sawMode = toolName, string(input), pc.Mode
			return acperm.Allowed()
		})
	out, _ := endpointOf(t, gAllow, "writey", "ask1")(context.Background(), `{"k":1}`)
	if out != "wrote" || !ran {
		t.Fatalf("ask-allowed call did not run: %q ran=%v", out, ran)
	}
	if sawName != "writey" || sawInput != `{"k":1}` || sawMode != acperm.ModeDefault {
		t.Fatalf("ask callback saw wrong args: name=%q input=%q mode=%q", sawName, sawInput, sawMode)
	}

	ran = false
	gDeny := NewToolGate([]actool.CoreTool{writeish}, ToolTemplate{}, 0).
		SetPermissionMode(acperm.ModeDefault).
		SetAsk(func(context.Context, string, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Denied("human said no")
		})
	out, _ = endpointOf(t, gDeny, "writey", "ask2")(context.Background(), "{}")
	if out != "Tool call was not permitted: human said no" || ran {
		t.Fatalf("ask denial not enforced: %q ran=%v", out, ran)
	}
}

// TestGateManagedPreservesRegistrationOrder: Managed must return the exact
// NewToolGate list in order — the order the bound schemas follow, and the
// stability precondition for toolset_snapshot_hash (方案 §4-P1 第 8 条).
func TestGateManagedPreservesRegistrationOrder(t *testing.T) {
	names := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	tools := make([]actool.CoreTool, 0, len(names))
	for _, n := range names {
		tools = append(tools, barrierTool(n, true, make(chan struct{}, 1), make(chan struct{})))
	}
	g := NewToolGate(tools, ToolTemplate{}, 0)

	got := g.Managed()
	if len(got) != len(names) {
		t.Fatalf("Managed returned %d tools, want %d", len(got), len(names))
	}
	for i, n := range names {
		if got[i].Name() != n {
			t.Fatalf("order drift at %d: %q vs %q", i, got[i].Name(), n)
		}
	}
	// The returned slice is a copy: mutating it must not touch the gate.
	got[0] = nil
	if g.Managed()[0].Name() != names[0] {
		t.Fatalf("Managed result aliases gate state")
	}
}

// TestGateOnResultObservesResultAndExtras: the gate reports callID/text/isErr
// and passes actool.Result.Extra through for the kernel cut's transcript write.
func TestGateOnResultObservesResultAndExtras(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "guidance",
		Description: "emits an extra message",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Result{
				Content: []llm.ContentBlock{llm.TextBlock("main result")},
				Extra:   []llm.Message{llm.UserText("skill guidance")},
			}, nil
		},
	})
	g := NewToolGate([]actool.CoreTool{core}, ToolTemplate{}, 0)

	type obs struct {
		callID, name, text string
		isErr              bool
		extras             int
	}
	var got obs
	var mu sync.Mutex
	g.OnResult = func(callID, name, text string, isErr bool, extras []llm.Message) {
		mu.Lock()
		defer mu.Unlock()
		got = obs{callID: callID, name: name, text: text, isErr: isErr, extras: len(extras)}
	}

	out, _ := endpointOf(t, g, "guidance", "c4")(context.Background(), "{}")
	mu.Lock()
	defer mu.Unlock()
	if out != "main result" || got.callID != "c4" || got.name != "guidance" || got.isErr || got.extras != 1 {
		t.Fatalf("OnResult observation wrong: out=%q got=%+v", out, got)
	}
}

// TestGateConcurrencyThroughEndpoints: the discipline holds across gate
// endpoints — a safe tool in flight keeps an unsafe endpoint waiting; the
// unsafe tool in turn keeps a safe endpoint waiting (§3.3 through the real
// WrapInvokableToolCall path).
func TestGateConcurrencyThroughEndpoints(t *testing.T) {
	safeStarted := make(chan struct{}, 1)
	safeRelease := make(chan struct{})
	unsafeStarted := make(chan struct{}, 1)
	unsafeRelease := make(chan struct{})
	safe2Started := make(chan struct{}, 1)
	safe2Release := make(chan struct{})

	g := NewToolGate([]actool.CoreTool{
		barrierTool("read_only", true, safeStarted, safeRelease),
		barrierTool("write_thing", false, unsafeStarted, unsafeRelease),
		barrierTool("read_only2", true, safe2Started, safe2Release),
	}, ToolTemplate{}, 0)

	safeDone := make(chan struct{}, 1)
	go func() {
		_, _ = endpointOf(t, g, "read_only", "cs1")(context.Background(), "{}")
		safeDone <- struct{}{}
	}()
	waitFor(t, safeStarted, 1)

	unsafeDone := make(chan struct{}, 1)
	go func() {
		_, _ = endpointOf(t, g, "write_thing", "cu1")(context.Background(), "{}")
		unsafeDone <- struct{}{}
	}()
	mustStayBlocked(t, unsafeStarted, "unsafe endpoint behind safe holder")

	close(safeRelease)
	waitFor(t, safeDone, 1)
	waitFor(t, unsafeStarted, 1)

	// Unsafe now holds exclusivity: a fresh safe endpoint must wait for it.
	safeDone2 := make(chan struct{}, 1)
	go func() {
		_, _ = endpointOf(t, g, "read_only2", "cs2")(context.Background(), "{}")
		safeDone2 <- struct{}{}
	}()
	mustStayBlocked(t, safe2Started, "safe endpoint behind unsafe holder")

	close(unsafeRelease)
	waitFor(t, unsafeDone, 1)
	waitFor(t, safe2Started, 1)
	close(safe2Release)
	waitFor(t, safeDone2, 1)
}

// TestGateSerializesSameUnsafeTool: two concurrent calls to the same unsafe
// tool never overlap — the second stays blocked until the first leaves the
// critical section (barrier-proven, no timing assumption).
func TestGateSerializesSameUnsafeTool(t *testing.T) {
	firstStarted := make(chan struct{}, 1)
	firstRelease := make(chan struct{})
	secondStarted := make(chan struct{}, 1)

	g := NewToolGate([]actool.CoreTool{slowWriter(firstStarted, firstRelease, secondStarted)}, ToolTemplate{}, 0)
	ep := endpointOf(t, g, "solo_writer", "w1")

	firstDone := make(chan struct{}, 1)
	go func() { _, _ = ep(context.Background(), "{}"); firstDone <- struct{}{} }()
	waitFor(t, firstStarted, 1)

	secondDone := make(chan struct{}, 1)
	go func() { _, _ = ep(context.Background(), "{}"); secondDone <- struct{}{} }()
	mustStayBlocked(t, secondStarted, "second call to same unsafe tool")

	close(firstRelease)
	waitFor(t, firstDone, 1)
	waitFor(t, secondStarted, 1)
	waitFor(t, secondDone, 1)
}

// slowWriter is the two-phase tool used by TestGateSerializesSameUnsafeTool:
// the first caller holds the critical section on firstRelease, every later
// caller signals secondStarted (only reachable once the first left).
func slowWriter(firstStarted chan<- struct{}, firstRelease <-chan struct{}, secondStarted chan<- struct{}) actool.CoreTool {
	var left bool // set once the first caller passed the barrier; single critical section ⇒ no race
	return actool.Build(actool.Spec{
		Name:        "solo_writer",
		Description: "must never overlap with itself",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if !left {
				firstStarted <- struct{}{}
				<-firstRelease
				left = true
				return actool.Text("first written"), nil
			}
			secondStarted <- struct{}{}
			return actool.Text("second written"), nil
		},
	})
}
