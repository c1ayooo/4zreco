package acllm_test

// Benchmark case for §3.3 read/write split (docs/Eino深度接入方案 §4-P1 第 4 条
// 规格 5): one model round with 8 read-only tools must take the eino bridge no
// more than 1.2× the norma harness wall clock. Both paths run the SAME tools
// with the SAME busy work through their real executors — norma's streaming
// executor (harness.Query, the path this repo runs in production today) and
// the eino ToolsNode + ToolGate. A global-mutex regression on the eino side
// serializes the eight calls and blows far past the threshold.
//
// No sleep-based assertions: the per-tool work is CPU busy loops calibrated at
// test start so the fixed framework overhead stays in the noise on any
// machine. A stability guard re-measures the norma path and skips (not fails)
// when the machine is too noisy to judge ratios.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"iter"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/acllm"
)

const busyTarget = 25 * time.Millisecond // per-tool work; big enough to drown fixed overhead

// busyHash burns CPU deterministically: n sha256 rounds over a fixed block.
func busyHash(n int) {
	buf := make([]byte, 64)
	for i := 0; i < n; i++ {
		buf[0] = byte(i)
		sum := sha256.Sum256(buf)
		buf[1] = sum[0]
	}
}

// calibrateBusy finds the iteration count that makes one busy() call ≈ busyTarget.
func calibrateBusy(t *testing.T) int {
	t.Helper()
	const probe = 20000
	start := time.Now()
	busyHash(probe)
	perIter := time.Since(start) / probe
	if perIter <= 0 {
		t.Skip("timer resolution too coarse to calibrate busy work")
	}
	n := int(busyTarget / perIter)
	if n < probe {
		n = probe
	}
	return n
}

// busyTool builds one read-only (concurrency-safe) tool burning n CPU rounds.
func busyTool(name string, n int) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "read-only busy tool " + name,
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			busyHash(n)
			return actool.Text(name + " ok"), nil
		},
	})
}

func eightBusyTools(n int) []actool.CoreTool {
	tools := make([]actool.CoreTool, 0, 8)
	for i := 0; i < 8; i++ {
		tools = append(tools, busyTool("busy_"+strconv.Itoa(i), n))
	}
	return tools
}

// normaCallModel scripts the norma loop's model: call 0 → 8 tool_use blocks,
// call 1 → closing text.
func normaCallModel(calls *int) func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		return func(yield func(llm.StreamEvent, error) bool) {
			defer func() { *calls++ }()
			if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
				return
			}
			if *calls == 0 {
				for i := 0; i < 8; i++ {
					if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "call_" + strconv.Itoa(i), ToolName: "busy_" + strconv.Itoa(i)}, nil) {
						return
					}
					if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: "{}"}, nil) {
						return
					}
				}
			} else {
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "done"}, nil) {
					return
				}
			}
			stop := "end_turn"
			if *calls == 0 {
				stop = "tool_use"
			}
			if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
				return
			}
			yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		}
	}
}

// measureNorma runs one norma harness round over the 8 busy tools and returns
// the wall clock until KindResult.
func measureNorma(t *testing.T, tools []actool.CoreTool) time.Duration {
	t.Helper()
	calls := 0
	in := harness.QueryInput{
		System:         []string{"benchmark"},
		Messages:       []llm.Message{llm.UserText("run the probes")},
		Tools:          actool.NewRegistry(tools...),
		MaxConcurrency: 10,
		MaxTurns:       8,
		WorkingDir:     "/tmp/bench",
		PermissionMode: permission.ModeBypass,
	}
	deps := harness.QueryDeps{CallModel: normaCallModel(&calls)}

	start := time.Now()
	for ev, err := range harness.Query(context.Background(), in, deps) {
		if err != nil {
			t.Fatalf("norma harness error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			if ev.Terminal == nil || ev.Terminal.Reason != harness.ReasonCompleted {
				t.Fatalf("norma round ended with %v", ev.Terminal)
			}
			return time.Since(start)
		}
	}
	t.Fatalf("norma harness stream ended without KindResult")
	return 0
}

// measureEino runs one eino bridge round (ChatModelAgent + ToolsNode + ToolGate)
// over the same tools and returns the wall clock until the iterator closes.
func measureEino(t *testing.T, tools []actool.CoreTool) time.Duration {
	t.Helper()
	einoTools, err := acllm.ToEinoTools(tools)
	if err != nil {
		t.Fatalf("ToEinoTools: %v", err)
	}
	gate := acllm.NewToolGate(tools, acllm.ToolTemplate{WorkingDir: "/tmp/bench"}, 10)

	fm := &fakeModel{}
	calls := make([]schema.ToolCall, 0, 8)
	for i := 0; i < 8; i++ {
		calls = append(calls, schema.ToolCall{
			ID:       "call_" + strconv.Itoa(i),
			Function: schema.FunctionCall{Name: "busy_" + strconv.Itoa(i), Arguments: "{}"},
		})
	}
	fm.script(schema.AssistantMessage("", calls))
	fm.script(schema.AssistantMessage("done", nil))

	cfg := &adk.ChatModelAgentConfig{
		Name:          "bridge-bench",
		Model:         fm,
		MaxIterations: 8,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{Tools: einoTools},
		},
		Handlers: []adk.ChatModelAgentMiddleware{gate},
	}
	ag, err := adk.NewChatModelAgent(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{Agent: ag, EnableStreaming: false})

	start := time.Now()
	iter := runner.Run(context.Background(), []*schema.Message{schema.UserMessage("run the probes")})
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Err != nil {
			t.Fatalf("eino run error: %v", ev.Err)
		}
	}
	return time.Since(start)
}

// compile-time: fakeModel (toolbridge_e2e_test.go) satisfies the model
// interface the agent binds tools through.
var _ model.ToolCallingChatModel = (*fakeModel)(nil)

// TestBridgeParallelReadOnlyWithinNormaBudget: 规格 5 — same round, 8 read-only
// tools, eino ≤ 1.2× norma. Each side is measured twice and the better run
// counts: a transient host-load spike landing on ONE measurement (this is a
// WSL2 box) must not fail the comparison symmetrically — norma and eino get
// the same treatment. The drift guard only skips when BOTH norma runs
// disagree with each other (machine-wide noise, ratio unfathomable); a spike
// on the single eino run between two clean norma runs is absorbed by the
// second eino run instead of failing.
func TestBridgeParallelReadOnlyWithinNormaBudget(t *testing.T) {
	n := calibrateBusy(t)
	tools := eightBusyTools(n)

	norma1 := measureNorma(t, tools)
	eino1 := measureEino(t, tools)
	eino2 := measureEino(t, tools)
	norma2 := measureNorma(t, tools)

	norma := minDur(norma1, norma2)
	einoDur := minDur(eino1, eino2)
	drift := float64(norma1) / float64(norma2)
	if drift < 1 {
		drift = 1 / drift
	}
	if drift > 1.25 {
		t.Skipf("machine too noisy to judge ratios (norma runs %v vs %v, drift %.2f)", norma1, norma2, drift)
	}

	budget := time.Duration(float64(norma) * 1.2)
	t.Logf("busy=%d iters/tool | norma=%v (runs %v/%v) eino=%v (runs %v/%v) budget(1.2x)=%v",
		n, norma, norma1, norma2, einoDur, eino1, eino2, budget)
	if einoDur > budget {
		t.Fatalf("eino bridge round took %v > 1.2× norma (%v, budget %v) — parallel read path degraded", einoDur, norma, budget)
	}
}

func minDur(a, b time.Duration) time.Duration {
	if b < a {
		return b
	}
	return a
}
