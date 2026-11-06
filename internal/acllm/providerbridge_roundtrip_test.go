package acllm

// BridgeModel 双向对拍（刀④ 主循环切换的模型面）：
//
//   - generate roundtrip: 一个 scripted eino model → BridgeProvider（得到 norma
//     Provider）→ BridgeModel（回到 eino model）→ ADK 风格调用（工具按 per-call
//     option 推送，wrappers.go:1240-1248 路径）。消息形状、system 归位、工具绑定、
//     usage/finish reason 全程不丢；
//   - stream: norma 事件流 → eino delta chunk → schema.ConcatMessages 折叠出与
//     Complete 等价的整条 assistant 消息（含按 ToolIndex 归位的并行工具调用与
//     交错到达的参数片段）；
//   - overflow passthrough: provider 的 413 错误原样透传（acllm.IsOverflow /
//     termmap.PromptTooLong 分类不变）。

import (
	"context"
	"errors"
	"io"
	"iter"
	"sync"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// fakeNormaProvider replays scripted norma StreamEvents / a scripted Complete.
type fakeNormaProvider struct {
	mu       sync.Mutex
	events   []llm.StreamEvent
	complete func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
	reqs     []llm.CompletionRequest
}

func (f *fakeNormaProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	events := append([]llm.StreamEvent(nil), f.events...)
	f.mu.Unlock()
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (f *fakeNormaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	fn := f.complete
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return llm.UserText("ok"), "end_turn", llm.Usage{}, nil
}

// TestBridgeModelGenerateRoundtrip: system 归位、DTO 消息体、per-call 工具推送、
// max tokens 与 usage/finish 在 BridgeProvider→BridgeModel 一个来回后不丢。
func TestBridgeModelGenerateRoundtrip(t *testing.T) {
	inner := &bridgeFakeModel{
		generate: func(_ context.Context, input []*schema.Message, _ []model.Option) (*schema.Message, error) {
			msg := schema.AssistantMessage("roundtrip ok", []schema.ToolCall{
				{ID: "rt-1", Function: schema.FunctionCall{Name: "echo", Arguments: `{"q":"1"}`}},
			})
			msg.ResponseMeta = &schema.ResponseMeta{
				FinishReason: "tool_use",
				Usage:        &schema.TokenUsage{PromptTokens: 120, CompletionTokens: 30, TotalTokens: 150},
			}
			return msg, nil
		},
	}

	bm := BridgeModel(BridgeProvider(inner))
	bound, err := bm.WithTools([]*schema.ToolInfo{
		{Name: "echo", Desc: "echo it"},
		{Name: "noop", Desc: "do nothing"},
	})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}

	input := []*schema.Message{
		schema.SystemMessage("rt system part A"),
		schema.UserMessage("hello"),
	}
	out, err := bound.Generate(context.Background(), input, model.WithMaxTokens(777))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out.Content != "roundtrip ok" || len(out.ToolCalls) != 1 || out.ToolCalls[0].ID != "rt-1" {
		t.Fatalf("assistant shape drifted: %+v", out)
	}
	if out.ResponseMeta == nil || out.ResponseMeta.FinishReason != "tool_use" {
		t.Fatalf("finish reason lost: %+v", out.ResponseMeta)
	}
	if out.ResponseMeta.Usage == nil || out.ResponseMeta.Usage.CompletionTokens != 30 {
		t.Fatalf("usage lost: %+v", out.ResponseMeta.Usage)
	}

	// the provider received: system segment restored, DTO messages, tools from
	// the per-call option, max tokens carried
	calls := inner.inputs
	if len(calls) != 1 {
		t.Fatalf("model called %d times", len(calls))
	}
	if calls[0][0].Role != schema.System || calls[0][0].Content != "rt system part A" {
		t.Fatalf("system message not restored on the wire: %+v", calls[0][0])
	}
	if got := inner.optSnap[0].maxTokens; got == nil || *got != 777 {
		t.Fatalf("max tokens option lost: %+v", inner.optSnap[0].maxTokens)
	}
	// WithTools 绑定路径：req.Tools 由 BridgeProvider 还原成 eino ToolInfo 并经
	// WithTools 重新绑回底层模型（直接调用不走 per-call option）。
	if len(inner.withTools) != 1 || len(inner.withTools[0]) != 2 {
		t.Fatalf("WithTools-bound tools lost on the wire: %v", inner.withTools)
	}
}

// TestBridgeModelStreamConcat: a norma event stream (thinking/text interleaved
// with two parallel tool calls whose args arrive in fragments) folds back into
// one assistant message equal to what Complete would have produced.
func TestBridgeModelStreamConcat(t *testing.T) {
	p := &fakeNormaProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageStart},
		{Type: llm.SEThinkingDelta, Text: "let me "},
		{Type: llm.SEThinkingDelta, Text: "think"},
		{Type: llm.SETextDelta, Text: "calling "},
		{Type: llm.SETextDelta, Text: "tools"},
		{Type: llm.SEToolUseStart, ToolID: "t-1", ToolName: "probe", ToolIndex: 0},
		{Type: llm.SEToolInputJSON, Text: `{"u":"a`, ToolIndex: 0},
		{Type: llm.SEToolUseStart, ToolID: "t-2", ToolName: "scan", ToolIndex: 1},
		{Type: llm.SEToolInputJSON, Text: `","x":1}`, ToolIndex: 0},
		{Type: llm.SEToolInputJSON, Text: `{"h":"b"}`, ToolIndex: 1},
		{Type: llm.SEMessageDelta, StopReason: "tool_use", Usage: llm.Usage{InputTokens: 50, OutputTokens: 20}},
		{Type: llm.SEMessageStop},
	}}

	bm := BridgeModel(p)
	sr, err := bm.Stream(context.Background(), []*schema.Message{schema.UserMessage("go")})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer sr.Close()
	var chunks []*schema.Message
	for {
		chunk, rerr := sr.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("Recv: %v", rerr)
		}
		if chunk != nil {
			chunks = append(chunks, chunk)
		}
	}
	final, cerr := schema.ConcatMessages(chunks)
	if cerr != nil {
		t.Fatalf("ConcatMessages: %v", cerr)
	}
	if final.Content != "calling tools" {
		t.Fatalf("content = %q", final.Content)
	}
	if final.ReasoningContent != "let me think" {
		t.Fatalf("thinking = %q", final.ReasoningContent)
	}
	if len(final.ToolCalls) != 2 {
		t.Fatalf("tool calls = %d, want 2: %+v", len(final.ToolCalls), final.ToolCalls)
	}
	byID := map[string]schema.ToolCall{}
	for _, tc := range final.ToolCalls {
		byID[tc.ID] = tc
	}
	if got := byID["t-1"]; got.Function.Name != "probe" || got.Function.Arguments != `{"u":"a","x":1}` {
		t.Fatalf("t-1 drifted: %+v", got)
	}
	if got := byID["t-2"]; got.Function.Name != "scan" || got.Function.Arguments != `{"h":"b"}` {
		t.Fatalf("t-2 drifted: %+v", got)
	}
	if final.ResponseMeta == nil || final.ResponseMeta.FinishReason != "tool_use" {
		t.Fatalf("stream finish reason lost: %+v", final.ResponseMeta)
	}
	if final.ResponseMeta.Usage == nil || final.ResponseMeta.Usage.CompletionTokens != 20 {
		t.Fatalf("stream usage lost: %+v", final.ResponseMeta.Usage)
	}
}

// TestBridgeModelOverflowPassthrough: provider 错误原样透传，acllm.IsOverflow
// 判定（→ termmap.PromptTooLong）与 norma 时代同串同判。
func TestBridgeModelOverflowPassthrough(t *testing.T) {
	want := errors.New("request failed: status 413: prompt is too long: 210000 tokens > 200000 maximum")
	p := &fakeNormaProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		return llm.Message{}, "", llm.Usage{}, want
	}}
	bm := BridgeModel(p)
	_, err := bm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("error passthrough drifted: %v", err)
	}
	if !IsOverflow(err) {
		t.Fatalf("bridged 413 must still classify as overflow")
	}
}
