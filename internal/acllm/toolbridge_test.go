package acllm

// Unit tests for the actool.CoreTool ↔ eino tool bridge (toolbridge.go):
// Info fidelity against norma Registry.Schemas, the never-error execution
// contract, the RawInput opt-out, panic recovery, and the idempotent output
// cap (spill to OutputDir / head+tail truncation) — behavior-aligned with the
// norma harness by reusing actool.CaptureOnce.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/cloudwego/eino/schema"
)

// echoTool builds a CoreTool whose Run captures what it saw: the ToolContext
// fields and the raw input, returned as JSON so tests assert the whole picture.
func echoTool(name string, _ func(tc *actool.ToolContext) map[string]any) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "echo " + name,
		Prompt:      "extended guidance for " + name,
		Schema:      objSchema(map[string]string{"q": "string"}),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			out := map[string]any{"input": string(in)}
			if tc != nil {
				out["use_id"] = tc.ToolUseID
				out["workdir"] = tc.WorkingDir
				out["agent"] = tc.AgentID
				out["maxchars"] = tc.MaxOutputChars
				out["outdir"] = tc.OutputDir
				out["env_len"] = len(tc.Env)
			} else {
				out["tc"] = false
			}
			b, _ := json.Marshal(out)
			return actool.Text(string(b)), nil
		},
	})
}

// objSchema is a minimal JSON-schema object with required string properties.
// objSchema is a minimal JSON-schema object with required string properties.
// required is []any — the shape norma's own schemas use (bash.go, webfetch.go,
// …) and the only shape tool.ValidateInput's toStrings recognizes. (4zreco's
// agent/obj() helper emits []string, which ValidateInput silently ignores — a
// pre-existing norma-path quirk the bridge deliberately mirrors, not fixes.)
func objSchema(props map[string]string) map[string]any {
	properties := map[string]any{}
	required := make([]any, 0, len(props))
	for name, typ := range props {
		properties[name] = map[string]any{"type": typ}
		required = append(required, name)
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}
}

func mustInfo(t *testing.T, et *einoTool) *schema.ToolInfo {
	t.Helper()
	info, err := et.Info(context.Background())
	if err != nil {
		t.Fatalf("Info error: %v", err)
	}
	return info
}

// TestToolInfoFidelity: the bridge must render the model-facing definition
// exactly like norma Registry.Schemas (desc + "\n\n" + Prompt, schema verbatim).
func TestToolInfoFidelity(t *testing.T) {
	core := echoTool("echo_it", nil)
	et := ToEinoTool(core)
	info := mustInfo(t, et.(*einoTool))

	if info.Name != "echo_it" {
		t.Fatalf("name = %q", info.Name)
	}
	wantDesc := core.Description() + "\n\n" + core.Prompt()
	if info.Desc != wantDesc {
		t.Fatalf("desc mismatch:\n got %q\nwant %q", info.Desc, wantDesc)
	}
	if info.ParamsOneOf == nil {
		t.Fatalf("ParamsOneOf nil — input schema lost in bridging")
	}
}

// TestToolBridgeRoundTrip: InvokableRun flattens the tool's text result and the
// ToolContext injected on ctx reaches the tool (ToolUseID filled by the gate,
// template fields from assembly).
func TestToolBridgeRoundTrip(t *testing.T) {
	core := echoTool("echo_rt", nil)
	et := ToEinoTool(core)

	tc := ToolTemplate{
		WorkingDir:     "/tmp/run-dir",
		AgentID:        "worker-1",
		MaxOutputChars: 5000,
		OutputDir:      "/tmp/run-dir/cmd-output",
		Env:            []string{"K=V"},
	}.toolContext("tu_123")
	ctx := WithToolContext(context.Background(), tc)

	out, err := et.InvokableRun(ctx, `{"q":"hello"}`)
	if err != nil {
		t.Fatalf("InvokableRun error: %v", err) // never-error contract
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("flatten output not JSON: %v\nraw: %s", err, out)
	}
	if got["use_id"] != "tu_123" {
		t.Fatalf("ToolUseID = %v, want tu_123", got["use_id"])
	}
	if got["workdir"] != "/tmp/run-dir" || got["agent"] != "worker-1" {
		t.Fatalf("template fields lost: %v", got)
	}
	if got["maxchars"] != float64(5000) || got["env_len"] != float64(1) {
		t.Fatalf("cap/env wiring lost: %v", got)
	}
	if got["input"] != `{"q":"hello"}` {
		t.Fatalf("args mangled: %v", got["input"])
	}
}

// TestToolBridgeValidationRejectsBadInput: schema-invalid args are rejected
// before Run with the norma harness's error text.
func TestToolBridgeValidationRejectsBadInput(t *testing.T) {
	core := echoTool("echo_val", nil)
	et := ToEinoTool(core)

	out, err := et.InvokableRun(context.Background(), `{}`)
	if err != nil {
		t.Fatalf("InvokableRun error: %v", err)
	}
	if !strings.HasPrefix(out, "Error: invalid tool input:") {
		t.Fatalf("want validation error text, got %q", out)
	}
}

// TestToolBridgeEmptyArgsBecomeObject: eino may deliver "" arguments; the
// bridge normalizes to "{}" before validation (norma parity).
func TestToolBridgeEmptyArgsBecomeObject(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "no_args",
		Description: "takes nothing",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return actool.Text("input=" + string(in)), nil
		},
	})
	out, err := ToEinoTool(core).InvokableRun(context.Background(), "")
	if err != nil {
		t.Fatalf("InvokableRun error: %v", err)
	}
	if out != "input={}" {
		t.Fatalf("empty args not normalized: %q", out)
	}
}

// rawEchoTool opts out of validation (actool.Spec.RawInput discovery path).
type rawEchoTool struct {
	actool.CoreTool
}

func (rawEchoTool) AcceptsRawInput() bool { return true }

func TestToolBridgeRawInputOptOut(t *testing.T) {
	base := actool.Build(actool.Spec{
		Name:        "raw_tool",
		Description: "repairs its own args",
		Schema:      objSchema(map[string]string{"q": "string"}), // advertised but NOT enforced
		RawInput:    true,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return actool.Text("raw:" + string(in)), nil
		},
	})
	out, err := ToEinoTool(rawEchoTool{base}).InvokableRun(context.Background(), `{"q":  truncated`)
	if err != nil {
		t.Fatalf("InvokableRun error: %v", err)
	}
	if !strings.HasPrefix(out, "raw:") {
		t.Fatalf("raw-input tool was schema-gated: %q", out)
	}
}

// TestToolBridgePanicBecomesErrorText: a panicking tool must not take the run
// down — the panic surfaces as error text, nil error (norma guardPanic).
func TestToolBridgePanicBecomesErrorText(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "panic_tool",
		Description: "always panics",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			panic("boom")
		},
	})
	out, err := ToEinoTool(core).InvokableRun(context.Background(), `{}`)
	if err != nil {
		t.Fatalf("panic leaked as Go error: %v", err)
	}
	if !strings.HasPrefix(out, "Error: tool panic_tool panicked: boom") {
		t.Fatalf("panic text wrong: %q", out)
	}
}

// TestToolBridgeCallErrorPrefixed: a Go error from Run becomes "Error: …" text.
func TestToolBridgeCallErrorPrefixed(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "err_tool",
		Description: "always fails",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Result{}, errors.New("disk on fire")
		},
	})
	out, err := ToEinoTool(core).InvokableRun(context.Background(), `{}`)
	if err != nil {
		t.Fatalf("call error leaked as Go error: %v", err)
	}
	if out != "Error: disk on fire" {
		t.Fatalf("error text wrong: %q", out)
	}
}

// ---- capOutput / FlattenToolResult ----

// TestFlattenSpillsToOutputDir: oversized output spills FULL content to
// OutputDir; the model-facing text keeps a head + absolute-path pointer — the
// norma harness's spill contract.
func TestFlattenSpillsToOutputDir(t *testing.T) {
	dir := t.TempDir()
	tc := (&ToolTemplate{MaxOutputChars: 100, OutputDir: dir}).toolContext("tu_cap")
	body := strings.Repeat("x", 1000) + "\nEND-MARKER"

	out := FlattenToolResult(tc, actool.Text(body))

	// Spill mode returns the HEAD (first MaxOutputChars chars) + the pointer —
	// the tail stays out of the model view (that is what the pointer replaces).
	if !strings.HasPrefix(out, strings.Repeat("x", 100)) {
		t.Fatalf("head missing from spill output: %q", out)
	}
	if !strings.Contains(out, "<persisted-output>") || !strings.Contains(out, "full 1011 bytes / 2 lines") {
		t.Fatalf("no spill pointer with size stats in output: %q", out)
	}
	// Extract the absolute path from the pointer and verify the FULL body is on disk.
	start := strings.Index(out, "saved to") + len("saved to")
	path := strings.TrimSpace(out[start:])
	path = strings.TrimSuffix(strings.TrimPrefix(path, " "), " </persisted-output>")
	if !filepath.IsAbs(path) {
		t.Fatalf("spill pointer not absolute: %q", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("spill file unreadable: %v", err)
	}
	if string(b) != body {
		t.Fatalf("spilled content not byte-identical: %d vs %d bytes", len(b), len(body))
	}
}

// TestFlattenTruncatesWithoutOutputDir: no spill dir → head+tail truncation
// with the norma marker.
func TestFlattenTruncatesWithoutOutputDir(t *testing.T) {
	tc := (&ToolTemplate{MaxOutputChars: 100}).toolContext("tu_trunc")
	body := strings.Repeat("a", 500) + "TAIL-MARKER"

	out := FlattenToolResult(tc, actool.Text(body))

	if !strings.Contains(out, "characters truncated]") {
		t.Fatalf("no truncation marker: %q", out)
	}
	if !strings.Contains(out, "TAIL-MARKER") {
		t.Fatalf("tail lost in truncation: %q", out)
	}
	if len(out) > 300 {
		t.Fatalf("truncation not bounded: %d chars", len(out))
	}
}

// TestFlattenCaptureOnceIdempotent: output a tool already captured carries a
// marker and is left alone (no double-truncation/double-spill).
func TestFlattenCaptureOnceIdempotent(t *testing.T) {
	tc := (&ToolTemplate{MaxOutputChars: 10}).toolContext("tu_idem")
	already := "already handled <persisted-output> saved to /tmp/output-1-1.txt"
	out := FlattenToolResult(tc, actool.Text(already))
	if out != already {
		t.Fatalf("pre-captured output was re-capped: %q", out)
	}
}

// TestFlattenJoinsBlocksAndNoOutput: multiple text blocks join with newlines;
// an empty result normalizes to "(no output)" (norma execOne).
func TestFlattenJoinsBlocksAndNoOutput(t *testing.T) {
	tc := (&ToolTemplate{}).toolContext("tu_join")
	res := actool.Result{Content: []llm.ContentBlock{llm.TextBlock("one"), llm.TextBlock("two")}}
	if got := FlattenToolResult(tc, res); got != "one\ntwo" {
		t.Fatalf("blocks not joined: %q", got)
	}
	if got := FlattenToolResult(tc, actool.Result{}); got != "(no output)" {
		t.Fatalf("empty result not normalized: %q", got)
	}
}

// TestEmitBridgesThroughGate: §3.2 Emit 行 — a tool reporting progress has it
// land in the run-level sink the template wired (the host's event-stream
// bridge), through the gate's per-call context injection.
func TestEmitBridgesThroughGate(t *testing.T) {
	core := actool.Build(actool.Spec{
		Name:        "progressy",
		Description: "emits progress mid-run",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			tc.Emit(actool.ProgressInfo{Message: "halfway"})
			return actool.Text("finished"), nil
		},
	})

	var got []string
	g := NewToolGate([]actool.CoreTool{core}, ToolTemplate{
		Emit: func(p actool.ProgressInfo) { got = append(got, p.Message) },
	}, 0)

	out, err := endpointOf(t, g, "progressy", "c5")(context.Background(), "{}")
	if err != nil || out != "finished" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if len(got) != 1 || got[0] != "halfway" {
		t.Fatalf("progress sink got %v", got)
	}
}

// TestBareAdapterContractPolicyFree is the tripwire for the ToEinoTool bare
// path contract (see the "Scope of the bare path" doc on ToEinoTool): the
// adapter carries NO permission pipeline — a tool that hard-denies itself
// still executes when invoked bare, while the SAME tool through a ToolGate is
// denied without running. If either side of this contract changes (someone
// adds permission to the adapter, or the gate stops replacing the endpoint),
// this test fails and forces the decision to be conscious, not accidental.
// 4zrec precedent: toolface/tools/eino.go:15-35 (adapter deliberately
// dependency-minimal; permission lives in the kernel gate); in-repo bare-Call
// precedent: server/customtool.go:162-168 smoke path.
func TestBareAdapterContractPolicyFree(t *testing.T) {
	mk := func() (actool.CoreTool, *bool) {
		ran := false
		core := actool.Build(actool.Spec{
			Name:        "selfdenying",
			Description: "denies itself",
			Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
			Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
				return acperm.Denied("policy")
			},
			Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
				ran = true
				return actool.Text("ran"), nil
			},
		})
		return core, &ran
	}

	// Bare path: the denial is NOT consulted — the tool executes.
	coreBare, ranBare := mk()
	out, err := ToEinoTool(coreBare).InvokableRun(context.Background(), "{}")
	if err != nil {
		t.Fatalf("bare run error: %v", err)
	}
	if out != "ran" || !*ranBare {
		t.Fatalf("bare path contract drift: out=%q ran=%v (adapter grew a permission pipeline?)", out, *ranBare)
	}

	// Gate path: the SAME denial is enforced — text, no execution.
	coreGate, ranGate := mk()
	g := NewToolGate([]actool.CoreTool{coreGate}, ToolTemplate{}, 0).SetPermissionMode(acperm.ModeDefault)
	out, err = endpointOf(t, g, "selfdenying", "d9")(context.Background(), "{}")
	if err != nil {
		t.Fatalf("gate run error: %v", err)
	}
	if out != "Tool call was not permitted: policy" || *ranGate {
		t.Fatalf("gate contract drift: out=%q ran=%v", out, *ranGate)
	}
}

// TestToEinoToolsBatchOrder: batch bridging preserves order and names.
func TestToEinoToolsBatchOrder(t *testing.T) {
	tools := []actool.CoreTool{echoTool("b_one", nil), echoTool("b_two", nil), echoTool("b_three", nil)}
	bridged, err := ToEinoTools(tools)
	if err != nil {
		t.Fatalf("ToEinoTools error: %v", err)
	}
	if len(bridged) != len(tools) {
		t.Fatalf("bridged %d, want %d", len(bridged), len(tools))
	}
	for i, bt := range bridged {
		info, err := bt.Info(context.Background())
		if err != nil {
			t.Fatalf("Info error at %d: %v", i, err)
		}
		if info.Name != tools[i].Name() {
			t.Fatalf("order/name drift at %d: %q vs %q", i, info.Name, tools[i].Name())
		}
	}
}
