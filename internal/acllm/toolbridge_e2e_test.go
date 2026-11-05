package acllm_test

// End-to-end bridge tests (docs/Eino深度接入方案-2026-11-05.md §4-P1 第 4 条):
//
//   - TestE2EThreeToolsThroughBridge: three REAL 4zreco tools — one read
//     (list_assets), one write (report_finding), one network (an http-kind
//     custom tool, the same exec shape as internal/server/customtool.go's
//     runHTTPTool, driven against an httptest server) — run through a full
//     eino ReAct round: fake model → ChatModelAgent → ToolsNode → ToolGate →
//     CoreTool → cap/flatten → tool_result back to the model. The two DB-backed
//     tools need PG (ZRECO_PG_DSN); without it the test skips.
//   - TestE2EBatchBridgeFidelity: batch migration (§4-P1 第 4 条 "再批量迁移")
//     over the full WorkerTools / PlannerTools / MainAgentTools lists — every
//     tool bridges, Info fidelity holds, the gate can wrap every call.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

// testDB opens a DB connection, skipping if PG is unavailable (same gate as
// the agent package's tests).
func testDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	return d
}

// ---- fake model (scripted turns; 4zrec askernel fakemodel shape) ----

type fakeTurn struct {
	msg *schema.Message
}

// fakeModel plays a scripted sequence of model turns; after the script runs
// out it answers "done".
type fakeModel struct {
	mu     sync.Mutex
	turns  []fakeTurn
	calls  int
	inputs [][]*schema.Message
}

func (f *fakeModel) script(msgs ...*schema.Message) {
	for _, m := range msgs {
		f.turns = append(f.turns, fakeTurn{msg: m})
	}
}

func (f *fakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	f.mu.Lock()
	call := f.calls
	f.calls++
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	if call < len(f.turns) && f.turns[call].msg != nil {
		return f.turns[call].msg, nil
	}
	return schema.AssistantMessage("done", nil), nil
}

func (f *fakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := f.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (f *fakeModel) WithTools(infos []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return f, nil
}

func (f *fakeModel) inputOf(i int) []*schema.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < len(f.inputs) {
		return f.inputs[i]
	}
	return nil
}

// ---- the network tool: http-kind custom tool (customtool.go runHTTPTool shape) ----

// newHTTPTool mirrors internal/server/customtool.go's http-kind custom tool:
// renders {param} placeholders into a URL, executes the request natively, and
// returns {"status":..,"body":..} through actool.Capture — so it consumes the
// ToolContext the bridge injects (cap + spill dir), exactly like the real
// custom tools will once assembled on the eino path.
func newHTTPTool(base string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "http_fetch_e2e",
		Description: "GET a URL and return status/body (http-kind custom tool)",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string", "description": "path to append to the base url"},
			},
			"required": []any{"path"},
		},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(in, &a)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+a.Path, nil)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			resp, err := new(http.Client).Do(req)
			if err != nil {
				return actool.Errorf("请求失败: " + err.Error()), nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			out, _ := json.Marshal(map[string]any{"status": resp.StatusCode, "body": string(body)})
			return actool.Text(actool.Capture(tc, string(out))), nil
		},
	})
}

// pickTool pulls one tool out of a ToolSet list by name.
func pickTool(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name() == name {
			return tl
		}
	}
	t.Fatalf("tool %q not in list", name)
	return nil
}

// drainRunner drains one Run to the end, collecting tool-message texts and the
// terminal event.
func drainRunner(t *testing.T, iter *adk.AsyncIterator[*adk.AgentEvent]) (toolTexts []string, terminal *adk.AgentEvent) {
	t.Helper()
	for {
		ev, ok := iter.Next()
		if !ok {
			return toolTexts, terminal
		}
		if ev.Err != nil {
			t.Fatalf("run error: %v", ev.Err)
		}
		if ev.Action != nil && ev.Action.Interrupted != nil {
			t.Fatalf("unexpected interrupt")
		}
		if ev.Output != nil && ev.Output.MessageOutput != nil && ev.Output.MessageOutput.Role == schema.Tool && ev.Output.MessageOutput.Message != nil {
			toolTexts = append(toolTexts, ev.Output.MessageOutput.Message.Content)
		}
		if ev.Output != nil && ev.Output.MessageOutput != nil && ev.Output.MessageOutput.Role == schema.Assistant && ev.Output.MessageOutput.Message != nil {
			if len(ev.Output.MessageOutput.Message.ToolCalls) == 0 && ev.Output.MessageOutput.Message.Content != "" {
				terminal = ev
			}
		}
	}
}

// TestE2EThreeToolsThroughBridge drives one ReAct round over three real tools.
func TestE2EThreeToolsThroughBridge(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("eino-bridge-e2e", "bridge e2e goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascade(task.ID, true, true) })

	ts := agent.NewToolSet(d.Exploration(task.ExplorationID), "worker-e2e")
	ts.SetAssetStore(d.Assets(), d.Companies())

	// Seed one asset so list_assets has something real to return.
	insert := pickTool(t, ts.WorkerTools(), "insert_assets")
	seedRaw, _ := json.Marshal(map[string]any{
		"assets": []any{map[string]any{"type": "root_domain", "domain": "e2e-bridge.example"}},
	})
	if res, err := insert.Call(context.Background(), seedRaw, nil); err != nil {
		t.Fatalf("insert_assets: %v", err)
	} else if res.IsError {
		t.Fatalf("insert_assets errored: %s", res.Flatten())
	}

	// Network tool against a loopback server.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("bridge-e2e-http-body"))
	}))
	defer srv.Close()

	tools := []actool.CoreTool{
		pickTool(t, ts.WorkerTools(), "list_assets"),    // 1 read
		pickTool(t, ts.WorkerTools(), "report_finding"), // 1 write
		newHTTPTool(srv.URL),                            // 1 network
	}

	var (
		mu       sync.Mutex
		onResult []string // "callID=name:isErr"
	)
	gate := acllm.NewToolGate(tools, acllm.ToolTemplate{
		WorkingDir:     "/tmp/e2e-run",
		AgentID:        "worker-e2e",
		MaxOutputChars: 12000,
		OutputDir:      t.TempDir(),
	}, 10)
	gate.OnResult = func(callID, name, text string, isErr bool, extras []llm.Message) {
		mu.Lock()
		defer mu.Unlock()
		flag := "ok"
		if isErr {
			flag = "err"
		}
		onResult = append(onResult, callID+"="+name+":"+flag)
	}

	einoTools, err := acllm.ToEinoTools(tools)
	if err != nil {
		t.Fatalf("ToEinoTools: %v", err)
	}

	fm := &fakeModel{}
	fm.script(schema.AssistantMessage("", []schema.ToolCall{
		{ID: "call_read", Function: schema.FunctionCall{Name: "list_assets", Arguments: `{"dsl":"domain==\"e2e-bridge.example\"","limit":5}`}},
		{ID: "call_write", Function: schema.FunctionCall{Name: "report_finding", Arguments: `{"vulnclass":"注入","name":"e2e-bridge SQLi","severity":"medium","summary":"桥接层端到端用例上报的漏洞","evidence":"GET /?id=1 OR 1=1 返回了非预期数据"}`}},
		{ID: "call_net", Function: schema.FunctionCall{Name: "http_fetch_e2e", Arguments: `{"path":"/probe"}`}},
	}))
	fm.script(schema.AssistantMessage("round complete", nil))

	ctx := context.Background()
	cfg := &adk.ChatModelAgentConfig{
		Name:          "bridge-e2e",
		Model:         fm,
		MaxIterations: 8,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{Tools: einoTools},
		},
		Handlers: []adk.ChatModelAgentMiddleware{gate},
	}
	ag, err := adk.NewChatModelAgent(ctx, cfg)
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	runner := adk.NewRunner(ctx, adk.RunnerConfig{Agent: ag, EnableStreaming: false})
	toolTexts, terminal := drainRunner(t, runner.Run(ctx, []*schema.Message{schema.UserMessage("probe the bridge")}))

	if terminal == nil || terminal.Output.MessageOutput.Message.Content != "round complete" {
		t.Fatalf("run did not complete with the scripted final turn")
	}
	if len(toolTexts) != 3 {
		t.Fatalf("expected 3 tool messages on the stream, got %d: %v", len(toolTexts), toolTexts)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(onResult) != 3 {
		t.Fatalf("gate executed %d calls, want 3: %v", len(onResult), onResult)
	}
	want := map[string]bool{
		"call_read=list_assets:ok":     true,
		"call_write=report_finding:ok": true,
		"call_net=http_fetch_e2e:ok":   true,
	}
	for _, got := range onResult {
		if !want[got] {
			t.Fatalf("unexpected gate result %q (want %v)", got, want)
		}
	}

	if hits != 1 {
		t.Fatalf("network tool hit the server %d times, want 1", hits)
	}

	// The model's second call must carry all three results as tool messages.
	second := fm.inputOf(1)
	var sawRead, sawWrite, sawNet bool
	for _, m := range second {
		if m.Role != schema.Tool {
			continue
		}
		switch m.ToolCallID {
		case "call_read":
			sawRead = strings.Contains(m.Content, "e2e-bridge.example")
		case "call_write":
			sawWrite = strings.Contains(m.Content, "finding_id")
		case "call_net":
			sawNet = strings.Contains(m.Content, `"status":200`) && strings.Contains(m.Content, "bridge-e2e-http-body")
		}
	}
	if !sawRead || !sawWrite || !sawNet {
		t.Fatalf("second model call missing real tool results (read=%v write=%v net=%v)", sawRead, sawWrite, sawNet)
	}
}

// TestE2EBatchBridgeFidelity: batch migration over the full built-in tool
// lists — every tool bridges, Info fidelity holds against the CoreTool, and
// the gate wraps every name (no unmanaged stragglers inside a managed batch).
func TestE2EBatchBridgeFidelity(t *testing.T) {
	ts := agent.NewToolSet(nil, "worker-e2e-batch")
	batches := map[string][]actool.CoreTool{
		"worker":     ts.WorkerTools(),
		"planner":    ts.PlannerTools(),
		"main_agent": ts.MainAgentTools(),
	}
	for label, list := range batches {
		if len(list) == 0 {
			t.Fatalf("%s batch empty", label)
		}
		einoTools, err := acllm.ToEinoTools(list)
		if err != nil {
			t.Fatalf("%s: ToEinoTools: %v", label, err)
		}
		if len(einoTools) != len(list) {
			t.Fatalf("%s: bridged %d of %d", label, len(einoTools), len(list))
		}
		gate := acllm.NewToolGate(list, acllm.ToolTemplate{}, 10)
		for i, core := range list {
			info, err := einoTools[i].Info(context.Background())
			if err != nil {
				t.Fatalf("%s: Info(%s): %v", label, core.Name(), err)
			}
			if info.Name != core.Name() {
				t.Fatalf("%s: name drift at %d: %q vs %q", label, i, info.Name, core.Name())
			}
			// The gate must own every tool of the batch it was built from.
			if _, ok := gate.Tool(core.Name()); !ok {
				t.Fatalf("%s: gate lost %q", label, core.Name())
			}
			// Wrap each call: managed names must produce a wrapped endpoint.
			ep, err := gate.WrapInvokableToolCall(context.Background(), nil, &adk.ToolContext{Name: core.Name(), CallID: "probe"})
			if err != nil {
				t.Fatalf("%s: wrap(%s): %v", label, core.Name(), err)
			}
			if ep == nil {
				t.Fatalf("%s: wrap(%s) passed through unmanaged", label, core.Name())
			}
		}
	}
}
