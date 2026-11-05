package acllm

// End-to-end middleware-chain test (评审第 1 轮 #3): the four 刀③ middlewares —
// view (projection + compaction wiring), injection, deferred, gate — run inside
// a REAL adk.NewChatModelAgent + Runner, not against hand-built
// ChatModelAgentState. The integration assumptions the other tests verify by
// hand (Before* order, After* capture timing, per-round ToolInfos dispatch,
// WrapModel composition) are exercised live here:
//
//   - the runner's input never reaches the model unless the host seeds it into
//     the DTO master — this test plays the 刀④ host for the seams the assembly
//     cut owns: master seeding, OnResult → master tool-result writes, and the
//     injection drain closure;
//   - deferred: the locked tool's schema is withheld from the model binding
//     (WithTools records), yet a scripted direct call still runs into the
//     gate's hard gate ("not unlocked" error reaches the model as a tool
//     result) — V5 双保险 live;
//   - view: the first model call sees the projected view (system message,
//     post-boundary working set — pre-boundary junk stays out);
//   - injection: the drained steer message rides the first call;
//   - the second model call sees the captured assistant + the three tool
//     results (OnResult → master → re-projection loop), so the ReAct round
//     closes over the DTO master like norma's loop.messages.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// mustToEinoTools bridges a tool list for the agent config, failing the test
// on any conversion error.
func mustToEinoTools(t *testing.T, tools []actool.CoreTool) []tool.BaseTool {
	t.Helper()
	out, err := ToEinoTools(tools)
	if err != nil {
		t.Fatalf("ToEinoTools: %v", err)
	}
	return out
}

func mwEchoTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "mw e2e " + name,
		Schema:      objSchema(map[string]string{"q": "string"}),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return actool.Text(name + " ran"), nil
		},
	})
}

// drainMWRunner mirrors toolbridge_e2e_test.go's drainRunner (that one lives in
// the external test package).
func drainMWRunner(t *testing.T, iter *adk.AsyncIterator[*adk.AgentEvent]) (toolTexts []string, terminal *adk.AgentEvent) {
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

func TestE2EMiddlewareChainThroughRunner(t *testing.T) {
	// three tools: plain core, locked deferred, unlocked deferred
	echo := mwEchoTool("echo_mw")
	locked := mwEchoTool("mcp__e2e__locked")
	free := mwEchoTool("mcp__e2e__free")
	tools := []actool.CoreTool{echo, locked, free}
	deferred := []string{"mcp__e2e__locked", "mcp__e2e__free"}
	unlock := actool.NewUnlockSet("mcp__e2e__free") // locked stays locked

	var infos []*schema.ToolInfo
	for _, tl := range tools {
		ti, err := ToolInfoOf(tl)
		if err != nil {
			t.Fatalf("ToolInfoOf(%s): %v", tl.Name(), err)
		}
		infos = append(infos, ti)
	}

	// the DTO master, seeded the way the 刀④ host seeds it: a compact boundary
	// with pre-boundary junk the model must never see, then the run input.
	store := &messageStore{}
	store.Append(llm.UserText("pre-boundary junk the model must not see"))
	store.Append(llm.BoundaryMessage(llm.BoundaryMeta{Trigger: "test"}))
	store.Append(llm.UserText("probe the middleware chain"))

	ps := &promptState{}
	vm := newViewMiddleware(store, ps, NewCompactor(CompactionConfig{ContextWindow: 200000}, nil), []string{"mw e2e system"}, 0, nil)
	drained := 0
	inj := newInjectionMiddleware(store, func(ctx context.Context) []llm.Message {
		drained++
		if drained == 1 {
			return []llm.Message{llm.UserText("【规划者实时纠偏】mw-e2e 注入")}
		}
		return nil
	})
	dm := newDeferredMiddleware(infos, deferred, unlock)
	gate := NewToolGate(tools, ToolTemplate{}, 0).SetDeferred(deferred, unlock)

	// the gate's OnResult host wiring: tool results land in the master as
	// norma-shaped DTO (user message with tool_result blocks), so the next
	// projection carries them after the captured assistant.
	var mu sync.Mutex
	onResult := []string{}
	gate.OnResult = func(callID, name, text string, isErr bool, extras []llm.Message) {
		store.Append(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
			llm.ToolResultText(callID, text, isErr),
		}})
		mu.Lock()
		flag := "ok"
		if isErr {
			flag = "err"
		}
		onResult = append(onResult, callID+"="+name+":"+flag)
		mu.Unlock()
	}

	fm := &scriptedModel{}
	fm.script(func(_ context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
		return schema.AssistantMessage("", []schema.ToolCall{
			{ID: "c_echo", Function: schema.FunctionCall{Name: "echo_mw", Arguments: `{"q":"1"}`}},
			{ID: "c_locked", Function: schema.FunctionCall{Name: "mcp__e2e__locked", Arguments: `{"q":"2"}`}},
			{ID: "c_free", Function: schema.FunctionCall{Name: "mcp__e2e__free", Arguments: `{"q":"3"}`}},
		}), nil
	})
	fm.script(func(_ context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
		return schema.AssistantMessage("mw e2e complete", nil), nil
	})

	cfg := &adk.ChatModelAgentConfig{
		Name:          "mw-e2e",
		Model:         fm,
		MaxIterations: 8,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{Tools: mustToEinoTools(t, tools)},
		},
		Handlers: []adk.ChatModelAgentMiddleware{vm, inj, dm, gate},
	}
	ag, err := adk.NewChatModelAgent(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{Agent: ag, EnableStreaming: false})
	toolTexts, terminal := drainMWRunner(t, runner.Run(context.Background(), []*schema.Message{schema.UserMessage("probe the middleware chain")}))

	if terminal == nil || terminal.Output.MessageOutput.Message.Content != "mw e2e complete" {
		t.Fatalf("run did not complete with the scripted final turn: %+v", terminal)
	}

	// gate executed all three scripted calls; the locked one hit the hard gate
	mu.Lock()
	if len(onResult) != 3 {
		t.Fatalf("gate executed %d calls, want 3: %v", len(onResult), onResult)
	}
	mu.Unlock()
	found := map[string]string{}
	for _, tt := range toolTexts {
		switch {
		case strings.Contains(tt, "echo_mw ran"):
			found["echo"] = tt
		case strings.Contains(tt, "mcp__e2e__free ran"):
			found["free"] = tt
		case strings.Contains(tt, "not unlocked in this session"):
			found["locked"] = tt
		}
	}
	if len(found) != 3 {
		t.Fatalf("expected echo/free success + locked hard-gate error among tool texts, got %v", toolTexts)
	}

	// deferred filter survived the real dispatch: eino pushes state.ToolInfos
	// to the model as a per-call option (adk/wrappers.go:1240-1248 — WithTools
	// appended after caller opts), so the effective per-call tool list is what
	// the filter controls. The locked schema must never ride a call; the
	// unlocked one must.
	if len(fm.opts) != 2 {
		t.Fatalf("model called %d times, want 2", len(fm.opts))
	}
	for i, snap := range fm.opts {
		for _, n := range snap.tools {
			if n == "mcp__e2e__locked" {
				t.Fatalf("call %d bound the locked deferred schema to the model: %v", i, snap.tools)
			}
		}
	}
	if !containsStr(fm.opts[0].tools, "mcp__e2e__free") {
		t.Fatalf("unlocked deferred tool missing from call 1 bindings: %v", fm.opts[0].tools)
	}

	// first model call: projected view — system message, injection appended,
	// pre-boundary junk withheld
	first := fm.callInputs()[0]
	if first[0].Role != schema.System || first[0].Content != "mw e2e system" {
		t.Fatalf("first input lacks the projected system message: %+v", first[0])
	}
	for _, m := range first {
		if strings.Contains(m.Content, "pre-boundary junk") {
			t.Fatalf("pre-boundary junk leaked into the model view")
		}
	}
	sawInjection := false
	for _, m := range first {
		if strings.Contains(m.Content, "mw-e2e 注入") {
			sawInjection = true
		}
	}
	if !sawInjection {
		t.Fatalf("injected steer message missing from the first call")
	}

	// second model call: the ReAct round closed over the DTO master — the
	// captured assistant turn is followed by the three tool results (including
	// the locked tool's hard-gate error text)
	second := fm.callInputs()[1]
	joined := ""
	toolMsgs := 0
	for _, m := range second {
		if m.Role == schema.Tool {
			toolMsgs++
			joined += m.Content + "\n"
		}
	}
	if toolMsgs != 3 {
		t.Fatalf("second call saw %d tool messages, want 3", toolMsgs)
	}
	for _, want := range []string{"echo_mw ran", "mcp__e2e__free ran", "not unlocked in this session"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("second call missing tool result %q; got:\n%s", want, joined)
		}
	}
}

// drainMWRunnerStreaming drains a streaming Runner: text chunks from every
// message output, WillRetryError (the rejected attempt of a model retry)
// tolerated as non-fatal, anything else fatal.
func drainMWRunnerStreaming(t *testing.T, iter *adk.AsyncIterator[*adk.AgentEvent]) string {
	t.Helper()
	var text strings.Builder
	for {
		ev, ok := iter.Next()
		if !ok {
			return text.String()
		}
		if ev.Err != nil {
			var willRetry *adk.WillRetryError
			if errors.As(ev.Err, &willRetry) {
				continue // rejected attempt — the retry follows
			}
			t.Fatalf("run error: %v", ev.Err)
		}
		if ev.Output == nil || ev.Output.MessageOutput == nil {
			continue
		}
		mv := ev.Output.MessageOutput
		if mv.IsStreaming && mv.MessageStream != nil {
			for {
				chunk, err := mv.MessageStream.Recv()
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					var willRetry *adk.WillRetryError
					if errors.As(err, &willRetry) {
						break // rejected attempt's stream terminated by the verdict
					}
					t.Fatalf("stream recv: %v", err)
				}
				text.WriteString(chunk.Content)
			}
			continue
		}
		if mv.Message != nil {
			text.WriteString(mv.Message.Content)
		}
	}
}

// TestE2EMidStreamOverflowRecoveredByRetryConfig (评审第 2 轮 #1 的运行时证明):
// a mid-stream prompt-too-long error — the reader opens fine, yields one chunk,
// then fails — is recovered by the ModelRetryConfig built from
// NewReactiveRetryConfig: the ADK retry wrapper consumes the attempt for
// inspection, ShouldRetry compacts the master once, and the retry re-opens the
// model against the compacted projection; the run completes on the retry turn.
func TestE2EMidStreamOverflowRecoveredByRetryConfig(t *testing.T) {
	// history below the proactive thresholds (40×1000 chars ≈ 13k tokens < micro
	// 115k) so the recovery is the FIRST compaction — exactly the real 413 shape.
	store := &messageStore{}
	store.Append(newBigHistory(40, 1000)...)
	store.Append(llm.UserText("probe mid-stream recovery"))
	ps := &promptState{}
	vm := newViewMiddleware(store, ps, NewCompactor(CompactionConfig{ContextWindow: 200000}, fakeSummary), []string{"mid-stream sys"}, 0, nil)
	inj := newInjectionMiddleware(store)
	dm := newDeferredMiddleware(nil, nil, nil)
	gate := NewToolGate(nil, ToolTemplate{}, 0)

	fm := &scriptedModel{}
	fm.scriptStream(func(ctx context.Context, input []*schema.Message, opts []model.Option) (*schema.StreamReader[*schema.Message], error) {
		if len(fm.callInputs()) == 1 {
			sr, sw := schema.Pipe[*schema.Message](2)
			go func() {
				sw.Send(schema.AssistantMessage("partial ", nil), nil)
				sw.Send(nil, overflowErr()) // prompt-too-long AFTER the first chunk
				sw.Close()
			}()
			return sr, nil
		}
		return schema.StreamReaderFromArray([]*schema.Message{
			schema.AssistantMessage("mw retry complete", nil),
		}), nil
	})

	cfg := &adk.ChatModelAgentConfig{
		Name:             "mw-retry-e2e",
		Model:            fm,
		MaxIterations:    8,
		ModelRetryConfig: NewReactiveRetryConfig(vm),
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{},
		},
		Handlers: []adk.ChatModelAgentMiddleware{vm, inj, dm, gate},
	}
	ag, err := adk.NewChatModelAgent(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	runner := adk.NewRunner(context.Background(), adk.RunnerConfig{Agent: ag, EnableStreaming: true})
	text := drainMWRunnerStreaming(t, runner.Run(context.Background(), []*schema.Message{schema.UserMessage("probe mid-stream recovery")}))

	if !strings.Contains(text, "mw retry complete") {
		t.Fatalf("run did not complete on the retry turn; stream text = %q", text)
	}

	// exactly two model invocations: the mid-stream-failed attempt + the retry
	if got := len(fm.callInputs()); got != 2 {
		t.Fatalf("model called %d times, want 2 (failed attempt + recovered retry)", got)
	}
	// the retry went out against the compacted projection: system message,
	// no summarized-head junk, master carries the reactive boundary
	second := fm.callInputs()[1]
	if second[0].Role != schema.System || second[0].Content != "mid-stream sys" {
		t.Fatalf("retry input lacks the projected system message: %+v", second[0])
	}
	for _, m := range second {
		if strings.Contains(m.Content, "h-00:") {
			t.Fatalf("summarized head leaked into the retry input")
		}
	}
	if countBoundaryMarkers(store.Get()) != 1 {
		t.Fatalf("master boundaries = %d, want 1 (the reactive one)", countBoundaryMarkers(store.Get()))
	}
	if !vm.reactiveTried == false {
		_ = fmt.Sprint() // keep fmt imported if assertions above change
	}
}
