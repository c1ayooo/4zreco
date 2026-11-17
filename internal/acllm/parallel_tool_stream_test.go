package acllm

// Regression tests for parallel tool calls through the real norma providers:
// a turn that returns TWO function calls must survive the full eino-side path
// (BridgeModel → schema.ConcatMessages folds chunks BY ToolCall.Index) as two
// separate, well-formed tool calls. Upstream norma v0.4.4 anchored every
// Responses tool event at index 0, so two calls surfaced as
// "cannot concat ToolCalls with different tool id" and killed the run — the
// frames below replicate the DeepSeek /responses wire shape that triggered it
// (function_call items at output_index 1 and 2, after a reasoning/message
// item), plus the Chat Completions equivalent with interleaved argument
// fragments.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/cloudwego/eino/schema"
)

// sseFrame renders one SSE message (event line optional, blank-line
// terminated) the way norma's sseScanner reads it.
func sseFrame(t *testing.T, event string, payload any) string {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if event == "" {
		return "data: " + string(b) + "\n\n"
	}
	return "event: " + event + "\ndata: " + string(b) + "\n\n"
}

// sseServer serves one canned SSE body on every POST.
func sseServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// streamEvents drains a provider Stream into the event slice.
func streamEvents(t *testing.T, p llm.Provider) []llm.StreamEvent {
	t.Helper()
	var evs []llm.StreamEvent
	for ev, err := range p.Stream(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("hi")}}},
	}) {
		if err != nil {
			t.Fatalf("provider stream: %v", err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// bridgeConcat runs the eino-side fold the kernel performs on every assistant
// turn (askernel/run.go: schema.ConcatMessages over the model's chunks).
func bridgeConcat(t *testing.T, p llm.Provider) *schema.Message {
	t.Helper()
	m := BridgeModel(p)
	sr, err := m.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("bridge stream: %v", err)
	}
	defer sr.Close()
	var chunks []*schema.Message
	for {
		chunk, err := sr.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("bridge recv: %v", err)
		}
		if chunk != nil {
			chunks = append(chunks, chunk)
		}
	}
	final, cerr := schema.ConcatMessages(chunks)
	if cerr != nil {
		t.Fatalf("ConcatMessages: %v", cerr)
	}
	return final
}

func toolCallByID(t *testing.T, msg *schema.Message, id string) schema.ToolCall {
	t.Helper()
	for _, tc := range msg.ToolCalls {
		if tc.ID == id {
			return tc
		}
	}
	t.Fatalf("tool call %q missing from %+v", id, msg.ToolCalls)
	return schema.ToolCall{}
}

// TestResponsesParallelToolCallsAnchorsByOutputIndex: the DeepSeek-shaped
// /responses stream with two function_call items at output_index 1 and 2.
func TestResponsesParallelToolCallsAnchorsByOutputIndex(t *testing.T) {
	frames := ""
	// call 0 of the turn (output_index 1 — index 0 was the reasoning item)
	frames += sseFrame(t, "response.output_item.added", map[string]any{
		"type": "response.output_item.added",
		"item": map[string]any{"type": "function_call", "id": "item-a", "call_id": "call_00_x", "name": "get_weather_a"},
		"output_index": 1,
	})
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `{"city": `, "item_id": "item-a", "output_index": 1,
	})
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `"Beijing"}`, "item_id": "item-a", "output_index": 1,
	})
	// call 1 of the turn (output_index 2)
	frames += sseFrame(t, "response.output_item.added", map[string]any{
		"type": "response.output_item.added",
		"item": map[string]any{"type": "function_call", "id": "item-b", "call_id": "call_01_y", "name": "get_weather_b"},
		"output_index": 2,
	})
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `{"city": `, "item_id": "item-b", "output_index": 2,
	})
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `"Shanghai"}`, "item_id": "item-b", "output_index": 2,
	})
	frames += sseFrame(t, "response.completed", map[string]any{
		"type": "response.completed",
		"response": map[string]any{"status": "completed", "usage": map[string]int{"input_tokens": 10, "output_tokens": 5}},
	})

	srv := sseServer(t, frames)
	prov, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAIResponses, BaseURL: srv.URL, Model: "deepseek-flash", APIKey: "test"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// Provider level: the two starts carry distinct anchors, and every args
	// delta carries the anchor of its own call.
	evs := streamEvents(t, prov)
	starts := map[int]string{}
	for _, ev := range evs {
		switch ev.Type {
		case llm.SEToolUseStart:
			if _, dup := starts[ev.ToolIndex]; dup {
				t.Fatalf("two tool_use_start events anchored at index %d", ev.ToolIndex)
			}
			starts[ev.ToolIndex] = ev.ToolID
		case llm.SEToolInputJSON:
			if _, known := starts[ev.ToolIndex]; !known {
				t.Fatalf("tool_input_delta anchored at index %d before/without a matching tool_use_start", ev.ToolIndex)
			}
		}
	}
	if len(starts) != 2 || starts[1] != "call_00_x" || starts[2] != "call_01_y" {
		t.Fatalf("want starts {1:call_00_x, 2:call_01_y}, got %v", starts)
	}

	// eino side: the exact fold the kernel runs must yield two well-formed
	// calls — pre-fix this is "cannot concat ToolCalls with different tool id".
	final := bridgeConcat(t, prov)
	if len(final.ToolCalls) != 2 {
		t.Fatalf("want 2 tool calls, got %d: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	if tc := toolCallByID(t, final, "call_00_x"); tc.Function.Name != "get_weather_a" || tc.Function.Arguments != `{"city": "Beijing"}` {
		t.Fatalf("call_00_x wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_01_y"); tc.Function.Name != "get_weather_b" || tc.Function.Arguments != `{"city": "Shanghai"}` {
		t.Fatalf("call_01_y wrong: %+v", tc)
	}
}

// TestResponsesParallelToolCallsFallbacksWithoutOutputIndex: a gateway that
// omits output_index still gets distinct anchors via the item-id mapping and
// the sequential fallback.
func TestResponsesParallelToolCallsFallbacksWithoutOutputIndex(t *testing.T) {
	frames := ""
	frames += sseFrame(t, "response.output_item.added", map[string]any{
		"type": "response.output_item.added",
		"item": map[string]any{"type": "function_call", "id": "item-a", "call_id": "call_0", "name": "tool_a"},
	})
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `{"n": 1}`, "item_id": "item-a",
	})
	frames += sseFrame(t, "response.output_item.added", map[string]any{
		"type": "response.output_item.added",
		"item": map[string]any{"type": "function_call", "id": "item-b", "call_id": "call_1", "name": "tool_b"},
	})
	// no item_id either: sequential fallback routes it to the call in flight
	frames += sseFrame(t, "response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "delta": `{"n": 2}`,
	})
	frames += sseFrame(t, "response.completed", map[string]any{
		"type": "response.completed", "response": map[string]any{"status": "completed"},
	})

	srv := sseServer(t, frames)
	prov, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAIResponses, BaseURL: srv.URL, Model: "m", APIKey: "test"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	final := bridgeConcat(t, prov)
	if len(final.ToolCalls) != 2 {
		t.Fatalf("want 2 tool calls, got %d: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	if tc := toolCallByID(t, final, "call_0"); tc.Function.Arguments != `{"n": 1}` {
		t.Fatalf("call_0 args wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_1"); tc.Function.Arguments != `{"n": 2}` {
		t.Fatalf("call_1 args wrong: %+v", tc)
	}
}

// TestOpenAIChatParallelToolCallArgsRouteByIndex: Chat Completions already
// anchored the starts by tool_calls[].index but left the argument fragments at
// 0, so with interleaved parallel calls every fragment merged onto call 0.
func TestOpenAIChatParallelToolCallArgsRouteByIndex(t *testing.T) {
	frame := func(delta map[string]any) string {
		return sseFrame(t, "", map[string]any{"choices": []any{map[string]any{"delta": delta}}})
	}
	frames := ""
	frames += frame(map[string]any{"tool_calls": []any{map[string]any{
		"index": 0, "id": "call_0", "type": "function", "function": map[string]any{"name": "tool_a", "arguments": `{"x": `},
	}}})
	frames += frame(map[string]any{"tool_calls": []any{map[string]any{
		"index": 1, "id": "call_1", "type": "function", "function": map[string]any{"name": "tool_b", "arguments": `{"y": `},
	}}})
	// interleaved tails: a-tail, b-tail
	frames += frame(map[string]any{"tool_calls": []any{map[string]any{
		"index": 0, "function": map[string]any{"arguments": `1}`},
	}}})
	frames += frame(map[string]any{"tool_calls": []any{map[string]any{
		"index": 1, "function": map[string]any{"arguments": `2}`},
	}}})
	frames += sseFrame(t, "", map[string]any{
		"choices": []any{map[string]any{"delta": map[string]any{}, "finish_reason": "tool_calls"}},
		"usage":   map[string]int{"prompt_tokens": 3, "completion_tokens": 4},
	})
	frames += "data: [DONE]\n\n"

	srv := sseServer(t, frames)
	prov, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAI, BaseURL: srv.URL, Model: "m", APIKey: "test"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	final := bridgeConcat(t, prov)
	if len(final.ToolCalls) != 2 {
		t.Fatalf("want 2 tool calls, got %d: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	if tc := toolCallByID(t, final, "call_0"); tc.Function.Name != "tool_a" || tc.Function.Arguments != `{"x": 1}` {
		t.Fatalf("call_0 wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_1"); tc.Function.Name != "tool_b" || tc.Function.Arguments != `{"y": 2}` {
		t.Fatalf("call_1 wrong: %+v", tc)
	}
}

// anthropicFrames renders the GLM-shaped Anthropic stream: a thinking block at
// wire index 0, then parallel tool_use blocks at 1..n. With blockIndex=false
// the frames omit the event-level index entirely (emulation fallback).
func anthropicFrames(t *testing.T, blockIndex bool, calls []struct {
	block int
	id    string
	args  string
}) string {
	frame := func(payload map[string]any) string {
		return sseFrame(t, "", payload)
	}
	frames := ""
	start := func(idx int, block map[string]any) string {
		if blockIndex {
			return frame(map[string]any{"type": "content_block_start", "index": idx, "content_block": block})
		}
		return frame(map[string]any{"type": "content_block_start", "content_block": block})
	}
	delta := func(idx int, delta map[string]any) string {
		if blockIndex {
			return frame(map[string]any{"type": "content_block_delta", "index": idx, "delta": delta})
		}
		return frame(map[string]any{"type": "content_block_delta", "delta": delta})
	}
	stop := func(idx int) string {
		if blockIndex {
			return frame(map[string]any{"type": "content_block_stop", "index": idx})
		}
		return frame(map[string]any{"type": "content_block_stop"})
	}
	frames += frame(map[string]any{"type": "message_start", "message": map[string]any{"usage": map[string]int{"input_tokens": 10, "output_tokens": 1}}})
	frames += start(0, map[string]any{"type": "thinking"})
	frames += delta(0, map[string]any{"type": "thinking_delta", "thinking": "let me check the traces"})
	frames += stop(0)
	for _, c := range calls {
		frames += start(c.block, map[string]any{"type": "tool_use", "id": c.id, "name": "get_worker_output"})
		frames += delta(c.block, map[string]any{"type": "input_json_delta", "partial_json": c.args})
		frames += stop(c.block)
	}
	frames += frame(map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "tool_use"}, "usage": map[string]int{"input_tokens": 10, "output_tokens": 5}})
	frames += frame(map[string]any{"type": "message_stop"})
	return frames
}

// TestAnthropicParallelToolCallsAnchorsByBlockIndex: the GLM-shaped Anthropic
// stream (thinking block at 0, three parallel tool_use at 1/2/3). Upstream
// norma left ToolIndex at zero on every tool event, so the kernel's
// schema.ConcatMessages died with "cannot concat ToolCalls with different tool
// id" the moment the model emitted parallel calls — task 1541's planner rounds
// were the live trigger.
func TestAnthropicParallelToolCallsAnchorsByBlockIndex(t *testing.T) {
	frames := anthropicFrames(t, true, []struct {
		block int
		id    string
		args  string
	}{
		{1, "call_aaa", `{"intent": 1}`},
		{2, "call_bbb", `{"intent": 2}`},
		{3, "call_ccc", `{"intent": 3}`},
	})
	srv := sseServer(t, frames)
	prov, err := llm.NewProvider(llm.Config{Format: llm.FormatAnthropic, BaseURL: srv.URL, Model: "glm-5.3-flash", APIKey: "test"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// Provider level: three starts with distinct anchors; every args delta
	// carries the anchor of its own call.
	evs := streamEvents(t, prov)
	starts := map[int]string{}
	for _, ev := range evs {
		switch ev.Type {
		case llm.SEToolUseStart:
			if _, dup := starts[ev.ToolIndex]; dup {
				t.Fatalf("two tool_use_start events anchored at index %d", ev.ToolIndex)
			}
			starts[ev.ToolIndex] = ev.ToolID
		case llm.SEToolInputJSON:
			if _, known := starts[ev.ToolIndex]; !known {
				t.Fatalf("tool_input_delta anchored at unknown index %d", ev.ToolIndex)
			}
		}
	}
	if len(starts) != 3 || starts[0] != "call_aaa" || starts[1] != "call_bbb" || starts[2] != "call_ccc" {
		t.Fatalf("want starts {0:call_aaa, 1:call_bbb, 2:call_ccc}, got %v", starts)
	}

	// eino side: the exact kernel fold must yield three well-formed calls —
	// pre-fix this is "cannot concat ToolCalls with different tool id".
	final := bridgeConcat(t, prov)
	if len(final.ToolCalls) != 3 {
		t.Fatalf("want 3 tool calls, got %d: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	if tc := toolCallByID(t, final, "call_aaa"); tc.Function.Arguments != `{"intent": 1}` {
		t.Fatalf("call_aaa wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_bbb"); tc.Function.Arguments != `{"intent": 2}` {
		t.Fatalf("call_bbb wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_ccc"); tc.Function.Arguments != `{"intent": 3}` {
		t.Fatalf("call_ccc wrong: %+v", tc)
	}
}

// TestAnthropicParallelToolCallsFallbacksWithoutBlockIndex: an emulation that
// omits the event-level index still gets distinct anchors via the sequential
// fallback, and each delta routes to the call in flight.
func TestAnthropicParallelToolCallsFallbacksWithoutBlockIndex(t *testing.T) {
	frames := anthropicFrames(t, false, []struct {
		block int
		id    string
		args  string
	}{
		{0, "call_0", `{"n": 1}`},
		{0, "call_1", `{"n": 2}`},
	})
	srv := sseServer(t, frames)
	prov, err := llm.NewProvider(llm.Config{Format: llm.FormatAnthropic, BaseURL: srv.URL, Model: "m", APIKey: "test"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	final := bridgeConcat(t, prov)
	if len(final.ToolCalls) != 2 {
		t.Fatalf("want 2 tool calls, got %d: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	if tc := toolCallByID(t, final, "call_0"); tc.Function.Arguments != `{"n": 1}` {
		t.Fatalf("call_0 args wrong: %+v", tc)
	}
	if tc := toolCallByID(t, final, "call_1"); tc.Function.Arguments != `{"n": 2}` {
		t.Fatalf("call_1 args wrong: %+v", tc)
	}
}
