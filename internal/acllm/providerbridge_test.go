package acllm

// Tests for the provider bridge (providerbridge.go): the eino model →
// llm.Provider adaptation the cold-node compactor will be handed in 刀④ —
// Complete request/response/usage mapping, per-request tool binding, Stream
// event synthesis from delta chunks, and error passthrough (IsOverflow
// judgment unchanged).

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// bridgeFakeModel records calls and streams scripted delta chunks.
type bridgeFakeModel struct {
	mu       sync.Mutex
	generate func(ctx context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error)
	stream   func(ctx context.Context, input []*schema.Message, opts []model.Option) ([]*schema.Message, error)

	inputs    [][]*schema.Message
	optSnap   []optsSnapshot
	withTools [][]bool // per derived-withtools call: the bound names
}

func (f *bridgeFakeModel) record(input []*schema.Message, opts []model.Option) {
	common := model.GetCommonOptions(&model.Options{}, opts...)
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	f.optSnap = append(f.optSnap, optsSnapshot{maxTokens: common.MaxTokens})
	f.mu.Unlock()
}

func (f *bridgeFakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	f.record(input, opts)
	if f.generate != nil {
		return f.generate(ctx, input, opts)
	}
	return schema.AssistantMessage("ok", nil), nil
}

func (f *bridgeFakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.record(input, opts)
	if f.stream != nil {
		chunks, err := f.stream(ctx, input, opts)
		if err != nil {
			return nil, err
		}
		return schema.StreamReaderFromArray(chunks), nil
	}
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("ok", nil)}), nil
}

func (f *bridgeFakeModel) WithTools(infos []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	names := make([]bool, len(infos))
	f.mu.Lock()
	f.withTools = append(f.withTools, names)
	f.mu.Unlock()
	return f, nil
}

func TestBridgeCompleteMapsRequestAndResponse(t *testing.T) {
	fake := &bridgeFakeModel{
		generate: func(ctx context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
			msg := schema.AssistantMessage("the answer", nil)
			msg.ResponseMeta = &schema.ResponseMeta{
				FinishReason: "end_turn",
				Usage:        UsageToToken(llm.Usage{InputTokens: 100, OutputTokens: 10, CacheReadTokens: 20, CacheWriteTokens: 30}),
			}
			return msg, nil
		},
	}
	prov := BridgeProvider(fake)

	req := llm.CompletionRequest{
		System:    []string{"be terse", "second segment"},
		Messages:  []llm.Message{llm.UserText("hello"), {Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("hi")}}, llm.UserText("go on")},
		MaxTokens: 777,
	}
	msg, stop, usage, err := prov.Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if msg.Text() != "the answer" || msg.Role != llm.RoleAssistant {
		t.Fatalf("assistant DTO = %+v", msg)
	}
	if stop != "end_turn" {
		t.Fatalf("stop = %q", stop)
	}
	if usage != (llm.Usage{InputTokens: 100, OutputTokens: 10, CacheReadTokens: 20, CacheWriteTokens: 30}) {
		t.Fatalf("usage round-trip = %+v", usage)
	}
	// request shape on the wire: one joined system message + converted history
	in := fake.inputs[0]
	if in[0].Role != schema.System || in[0].Content != "be terse\n\nsecond segment" {
		t.Fatalf("system join = %+v", in[0])
	}
	if len(in) != 4 { // system + 3 converted
		t.Fatalf("input length = %d, want 4", len(in))
	}
	if got := fake.optSnap[0].maxTokens; got == nil || *got != 777 {
		t.Fatalf("max tokens = %v, want 777", got)
	}
}

func TestBridgeCompleteBindsRequestTools(t *testing.T) {
	fake := &bridgeFakeModel{}
	prov := BridgeProvider(fake)
	req := llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("scan")},
		Tools: []llm.ToolSchema{
			{Name: "probe", Description: "scan a host"},
		},
	}
	if _, _, _, err := prov.Complete(context.Background(), req); err != nil {
		t.Fatalf("Complete with tools: %v", err)
	}
	if len(fake.withTools) != 1 {
		t.Fatalf("WithTools not called for request tools (calls=%d)", len(fake.withTools))
	}
}

func TestBridgeStreamSynthesizesNormaEvents(t *testing.T) {
	think := &schema.Message{Role: schema.Assistant, ReasoningContent: "pondering"}
	text1 := schema.AssistantMessage("hello ", nil)
	text2 := schema.AssistantMessage("world", nil)
	toolCall := schema.AssistantMessage("", []schema.ToolCall{
		{ID: "tu_1", Function: schema.FunctionCall{Name: "probe", Arguments: `{"hos`}},
	})
	toolCall2 := schema.AssistantMessage("", []schema.ToolCall{
		{ID: "tu_1", Function: schema.FunctionCall{Name: "probe", Arguments: `t":"x"}`}},
	})
	// the usage-bearing terminal chunk carries metadata only (delta chunks, per
	// the eino contract ConcatMessages relies on)
	final := schema.AssistantMessage("", nil)
	final.ResponseMeta = &schema.ResponseMeta{
		FinishReason: "tool_calls",
		Usage:        UsageToToken(llm.Usage{InputTokens: 9, OutputTokens: 3}),
	}

	fake := &bridgeFakeModel{
		stream: func(ctx context.Context, input []*schema.Message, opts []model.Option) ([]*schema.Message, error) {
			return []*schema.Message{think, text1, text2, toolCall, toolCall2, final}, nil
		},
	}
	prov := BridgeProvider(fake)

	var events []llm.StreamEvent
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("go")}}) {
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		events = append(events, ev)
	}
	if len(events) == 0 || events[0].Type != llm.SEMessageStart {
		t.Fatalf("first event = %+v, want message_start", events)
	}
	var (
		texts   strings.Builder
		thinkDs strings.Builder
		sawTool bool
		sawArgs strings.Builder
		sawStop bool
		sawMsgD bool
	)
	for _, ev := range events {
		switch ev.Type {
		case llm.SETextDelta:
			texts.WriteString(ev.Text)
		case llm.SEThinkingDelta:
			thinkDs.WriteString(ev.Text)
		case llm.SEToolUseStart:
			sawTool = true
			if ev.ToolID != "tu_1" || ev.ToolName != "probe" {
				t.Fatalf("tool start = %+v", ev)
			}
		case llm.SEToolInputJSON:
			sawArgs.WriteString(ev.Text)
		case llm.SEMessageDelta:
			sawMsgD = true
			if ev.StopReason != "tool_calls" || ev.Usage.OutputTokens != 3 || ev.Usage.InputTokens != 9 {
				t.Fatalf("message_delta = %+v", ev)
			}
		case llm.SEMessageStop:
			sawStop = true
		}
	}
	if texts.String() != "hello world" {
		t.Fatalf("text deltas = %q", texts.String())
	}
	if thinkDs.String() != "pondering" {
		t.Fatalf("thinking deltas = %q", thinkDs.String())
	}
	if !sawTool || sawArgs.String() != `{"host":"x"}` {
		t.Fatalf("tool events: sawTool=%v args=%q", sawTool, sawArgs.String())
	}
	if !sawMsgD || !sawStop {
		t.Fatalf("missing terminal events: delta=%v stop=%v", sawMsgD, sawStop)
	}
}

// TestBridgeStreamAccumulatorParity: folding the synthesized events with
// norma's Accumulator yields the same message a native provider would hand over.
func TestBridgeStreamAccumulatorParity(t *testing.T) {
	chunks := []*schema.Message{
		schema.AssistantMessage("hel", nil),
		schema.AssistantMessage("lo", nil),
	}
	// the usage-bearing terminal chunk carries metadata only
	msg := schema.AssistantMessage("", nil)
	msg.ResponseMeta = &schema.ResponseMeta{FinishReason: "end_turn", Usage: UsageToToken(llm.Usage{InputTokens: 5, OutputTokens: 2})}
	chunks = append(chunks, msg)

	fake := &bridgeFakeModel{stream: func(ctx context.Context, input []*schema.Message, opts []model.Option) ([]*schema.Message, error) {
		return chunks, nil
	}}
	prov := BridgeProvider(fake)
	acc := llm.NewAccumulator()
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("x")}}) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		acc.Add(ev)
	}
	got := acc.Message()
	if got.Text() != "hello" {
		t.Fatalf("accumulated text = %q", got.Text())
	}
	if acc.Usage.OutputTokens != 2 || acc.Usage.InputTokens != 5 {
		t.Fatalf("accumulated usage = %+v", acc.Usage)
	}
}

// TestBridgeErrorPassthrough: provider errors surface unchanged so overflow
// classification (acllm.IsOverflow) keeps its norma judgment.
func TestBridgeErrorPassthrough(t *testing.T) {
	sentinel := fmt.Errorf("prompt is too long: 210000 tokens > 200000 maximum")
	fake := &bridgeFakeModel{
		generate: func(ctx context.Context, input []*schema.Message, opts []model.Option) (*schema.Message, error) {
			return nil, sentinel
		},
		stream: func(ctx context.Context, input []*schema.Message, opts []model.Option) ([]*schema.Message, error) {
			return nil, sentinel
		},
	}
	prov := BridgeProvider(fake)
	_, _, _, err := prov.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("x")}})
	if !errorsIs(err, sentinel) || !IsOverflow(err) {
		t.Fatalf("complete error = %v (overflow=%v)", err, IsOverflow(err))
	}
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("x")}}) {
		if !errorsIs(err, sentinel) {
			t.Fatalf("stream error = %v", err)
		}
		if ev.Type != llm.StreamEventType("") {
			t.Fatalf("unexpected event with error: %+v", ev)
		}
		break
	}
	// sanity: io import kept for the stream loop contract
	_ = io.EOF
}

func errorsIs(a, b error) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a == b || strings.Contains(a.Error(), b.Error())
}
