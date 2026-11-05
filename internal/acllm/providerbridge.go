// The provider bridge (方案 §2.1.2 冷节点压缩行 + §3.2 同一层): adapts an eino
// model.ToolCallingChatModel back onto the norma llm.Provider vocabulary, so
// domain components that call the LLM OUTSIDE the agent loop can keep their
// llm.Provider injection point while the provider stack beneath them switches
// to the eino side (llmpool.ModelPool + llmrec.ModelRecorder + eino-ext
// providers).
//
// The motivating consumer is the cold-node compactor
// (internal/agent/compaction.go — 领域逻辑，整包不进 eino): its §4 body call is
// `prov.Complete(ctx, llm.CompletionRequest{...})` (compaction.go:701). The
// compactor's constructor signature and 领域参数 stay untouched; the host hands
// it a BridgeProvider over the eino model instead of a native norma provider
// (wiring switch: 刀④). The assembly-side summarizer of the context-compaction
// middleware does NOT go through here — NewModelSummarizer calls the eino
// model directly.
//
// Fidelity notes:
//   - Tools ride the request: req.Tools are bound via WithTools per call, the
//     way norma providers serialize them onto the wire.
//   - MaxTokens rides as model.WithMaxTokens (0 = uncapped).
//   - req.Thinking ("disabled" per-request override) has no eino equivalent —
//     thinking config is baked into the model at construction. Same limitation
//     NewModelSummarizer documents; build the wrapped model with thinking off
//     when the caller needs a thinking-free completion.
//   - Error text passes through untouched, so compaction judgment
//     (acllm.IsOverflow) classifies bridged failures by the same string
//     criteria it used under norma.
//   - Stream synthesizes norma's normalized event vocabulary from the eino
//     chunk stream. eino stream chunks are DELTAS (schema.ConcatMessages folds
//     them — llmrec.observe and NewModelSummarizer's streamText both append
//     chunk.Content verbatim), so each chunk's Content/ReasoningContent and
//     tool-call argument fragment IS the delta and is forwarded as such.
package acllm

import (
	"context"
	"errors"
	"io"
	"iter"

	"github.com/Autumn-27/norma/llm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// BridgeProvider returns the norma llm.Provider view of an eino model.
func BridgeProvider(m model.ToolCallingChatModel) llm.Provider {
	return &bridgeProvider{m: m}
}

type bridgeProvider struct {
	m model.ToolCallingChatModel
}

// prepare renders a CompletionRequest into the eino call shape: system
// segments joined into one system message, DTO history converted, tools bound
// per call (norma request semantics — the derived model is returned as the
// caller for this request), max tokens carried as an option.
func (b *bridgeProvider) prepare(ctx context.Context, req llm.CompletionRequest) ([]*schema.Message, []model.Option, model.ToolCallingChatModel, error) {
	var msgs []*schema.Message
	if txt := joinSystemSegments(req.System); txt != "" {
		msgs = append(msgs, schema.SystemMessage(txt))
	}
	msgs = append(msgs, ToSchema(req.Messages)...)

	var opts []model.Option
	if req.MaxTokens > 0 {
		opts = append(opts, model.WithMaxTokens(req.MaxTokens))
	}
	caller := b.m
	if len(req.Tools) > 0 {
		infos := make([]*schema.ToolInfo, 0, len(req.Tools))
		for _, ts := range req.Tools {
			info, err := ToolSchemaToInfo(ts)
			if err != nil {
				return nil, nil, nil, err
			}
			infos = append(infos, info)
		}
		derived, err := b.m.WithTools(infos)
		if err != nil {
			return nil, nil, nil, err
		}
		caller = derived
	}
	return msgs, opts, caller, nil
}

// assistantDTO projects one eino assistant message back into the DTO
// vocabulary for the Complete return.
func assistantDTO(m *schema.Message) llm.Message {
	out := FromSchema([]*schema.Message{m})
	if len(out) == 0 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("")}}
	}
	return out[0]
}

func (b *bridgeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	input, opts, caller, err := b.prepare(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	msg, err := caller.Generate(ctx, input, opts...)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	var (
		stop  string
		usage llm.Usage
	)
	if msg.ResponseMeta != nil {
		stop = msg.ResponseMeta.FinishReason
		usage = UsageFromToken(msg.ResponseMeta.Usage)
	}
	return assistantDTO(msg), stop, usage, nil
}

// Stream synthesizes norma's normalized event stream from the eino chunk
// stream: message_start, thinking/text deltas, tool_use_start /
// tool_input_json per tool call, the usage/stop-bearing message_delta, and
// message_stop at EOF. Consumers that fold events with llm.Accumulator get the
// same message shape they would from a native provider.
func (b *bridgeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		input, opts, caller, err := b.prepare(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		sr, err := caller.Stream(ctx, input, opts...)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		defer sr.Close()

		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		toolStarted := map[int]bool{}
		for {
			chunk, err := sr.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				yield(llm.StreamEvent{}, err)
				return
			}
			if chunk == nil {
				continue
			}
			if chunk.ReasoningContent != "" {
				if !yield(llm.StreamEvent{Type: llm.SEThinkingDelta, Text: chunk.ReasoningContent}, nil) {
					return
				}
			}
			if chunk.Content != "" {
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: chunk.Content}, nil) {
					return
				}
			}
			for i, tc := range chunk.ToolCalls {
				if !toolStarted[i] && (tc.ID != "" || tc.Function.Name != "") {
					toolStarted[i] = true
					if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: tc.ID, ToolName: tc.Function.Name, ToolIndex: i}, nil) {
						return
					}
				}
				if args := tc.Function.Arguments; args != "" {
					if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: args, ToolIndex: i}, nil) {
						return
					}
				}
			}
			if chunk.ResponseMeta != nil && (chunk.ResponseMeta.Usage != nil || chunk.ResponseMeta.FinishReason != "") {
				ev := llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: chunk.ResponseMeta.FinishReason}
				if chunk.ResponseMeta.Usage != nil {
					ev.Usage = UsageFromToken(chunk.ResponseMeta.Usage)
				}
				if !yield(ev, nil) {
					return
				}
			}
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}
