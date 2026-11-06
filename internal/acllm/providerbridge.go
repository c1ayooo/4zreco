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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
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

// --- BridgeModel: the reverse bridge (刀④ 主循环切换的模型面) ---

// BridgeModel adapts a norma llm.Provider onto model.ToolCallingChatModel so
// the P1 eino kernel can run the agent loop while the provider stack beneath
// it stays byte-identical (llmpool failover, llmrec recording, quota capture,
// the 2013-thinking-retry — all live at the llm.Provider level and are NOT
// reimplemented on the eino side). This is the loop-switch counterpart of
// BridgeProvider: that one lets norma-facing domain code call an eino model;
// this one lets the eino kernel call a norma provider.
//
// Tool binding follows the eino contract: the agent binds the per-round tool
// list via WithTools (the ADK pushes state.ToolInfos this way), and the derived
// view serializes them into req.Tools for each call — exactly where norma
// providers expect them. Call options (MaxTokens/Temperature/Stop) map onto
// the request fields.
//
// Fidelity notes:
//   - The kernel's projected input carries the system prompt as a leading
//     schema system message (viewMiddleware.project prepends it); Generate
//     routes it back into req.System as one segment. FromSchema skips system
//     messages, so without this the system prompt would vanish on the wire.
//   - Stream synthesizes eino DELTA chunks from the norma event stream —
//     content/thinking deltas verbatim; tool calls are re-anchored by their
//     provider-assigned ToolIndex (schema.ConcatMessages merges by Index,
//     concatenating argument fragments); usage/finish ride the chunk that
//     carried the message_delta, which ConcatMessages folds (last finish
//     reason wins, usage max-merges — the anthropic echo shape is harmless).
//   - req.Thinking has no eino equivalent on this bridge either: the provider
//     keeps its configured default.
func BridgeModel(p llm.Provider) model.ToolCallingChatModel {
	return &bridgeModel{p: p}
}

type bridgeModel struct {
	p     llm.Provider
	tools []llm.ToolSchema // the WithTools-bound tool schemas for this view
}

// InfoToToolSchema is the inverse of ToolSchemaToInfo: an eino ToolInfo back
// into the DTO tool schema (name/description verbatim, ParamsOneOf → JSON
// schema via the same jsonschema vocabulary). Used by the BridgeModel binding.
func InfoToToolSchema(info *schema.ToolInfo) (llm.ToolSchema, error) {
	if info == nil {
		return llm.ToolSchema{}, fmt.Errorf("acllm: nil tool info")
	}
	ts := llm.ToolSchema{Name: info.Name, Description: info.Desc}
	if info.ParamsOneOf != nil {
		js, err := info.ParamsOneOf.ToJSONSchema()
		if err != nil {
			return llm.ToolSchema{}, fmt.Errorf("acllm: tool %q params: %w", info.Name, err)
		}
		raw, err := json.Marshal(js)
		if err != nil {
			return llm.ToolSchema{}, fmt.Errorf("acllm: tool %q params marshal: %w", info.Name, err)
		}
		var schemaMap map[string]any
		if err := json.Unmarshal(raw, &schemaMap); err != nil {
			return llm.ToolSchema{}, fmt.Errorf("acllm: tool %q params decode: %w", info.Name, err)
		}
		ts.InputSchema = schemaMap
	}
	return ts, nil
}

// WithTools binds the per-call tool set: the returned view serializes infos
// into req.Tools on every Generate/Stream. The receiver is never mutated.
func (b *bridgeModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	schemas := make([]llm.ToolSchema, 0, len(tools))
	for _, ti := range tools {
		ts, err := InfoToToolSchema(ti)
		if err != nil {
			return nil, err
		}
		schemas = append(schemas, ts)
	}
	return &bridgeModel{p: b.p, tools: schemas}, nil
}

// requestFromEino renders the eino call into a norma CompletionRequest: the
// leading system message routes back into req.System (one segment — norma
// providers join segments with "\n\n", so the wire text is unchanged), the
// rest converts via FromSchema, and call options map onto request fields.
func (b *bridgeModel) requestFromEino(input []*schema.Message, opts []model.Option) llm.CompletionRequest {
	req := llm.CompletionRequest{Tools: b.tools}
	if n := len(input); n > 0 && input[0] != nil && input[0].Role == schema.System {
		req.System = []string{input[0].Content}
		req.Messages = FromSchema(input[1:])
	} else {
		req.Messages = FromSchema(input)
	}
	common := model.GetCommonOptions(&model.Options{}, opts...)
	if common.MaxTokens != nil && *common.MaxTokens > 0 {
		req.MaxTokens = *common.MaxTokens
	}
	if common.Temperature != nil {
		t := float64(*common.Temperature)
		req.Temperature = &t
	}
	if len(common.Stop) > 0 {
		req.Stop = common.Stop
	}
	if len(common.Tools) > 0 {
		// Per-call tools override the binding: the ADK pushes state.ToolInfos
		// (the deferred-filtered list) as a per-call option
		// (adk/wrappers.go:1240-1248), so this is the path the kernel actually
		// exercises; the WithTools binding covers direct callers.
		schemas := make([]llm.ToolSchema, 0, len(common.Tools))
		for _, ti := range common.Tools {
			if ts, err := InfoToToolSchema(ti); err == nil {
				schemas = append(schemas, ts)
			}
		}
		if len(schemas) > 0 {
			req.Tools = schemas
		}
	}
	return req
}

// Generate implements model.BaseChatModel over Provider.Complete.
func (b *bridgeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	msg, stop, usage, err := b.p.Complete(ctx, b.requestFromEino(input, opts))
	if err != nil {
		return nil, err
	}
	out := ToSchema([]llm.Message{msg})
	if len(out) == 0 {
		out = []*schema.Message{schema.AssistantMessage("", nil)}
	}
	if stop != "" || usage != (llm.Usage{}) {
		m := out[0]
		rm := &schema.ResponseMeta{FinishReason: stop}
		if usage != (llm.Usage{}) {
			rm.Usage = UsageToToken(usage)
		}
		m.ResponseMeta = rm
	}
	return out[0], nil
}

// Stream implements model.BaseChatModel over Provider.Stream: norma's
// normalized event vocabulary back into eino delta chunks.
func (b *bridgeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	events := b.p.Stream(ctx, b.requestFromEino(input, opts))
	sr, sw := schema.Pipe[*schema.Message](1)
	go func() {
		defer sw.Close()
		// toolIdx anchors tool-call chunks for ConcatMessages' index merge.
		open := false
		toolIdx := -1
		for ev, err := range events {
			if err != nil {
				sw.Send(nil, err)
				return
			}
			switch ev.Type {
			case llm.SEMessageStart:
				// input-side usage rides message_start (anthropic echoes it here):
				// emit a usage-only chunk so ConcatMessages / the pump's per-chunk
				// MergeEcho fold sees it.
				if ev.Usage != (llm.Usage{}) {
					m := schema.AssistantMessage("", nil)
					m.ResponseMeta = &schema.ResponseMeta{Usage: UsageToToken(ev.Usage)}
					sw.Send(m, nil)
				}
			case llm.SEThinkingDelta:
				if ev.Text != "" {
					m := schema.AssistantMessage("", nil)
					m.ReasoningContent = ev.Text
					sw.Send(m, nil)
				}
			case llm.SETextDelta:
				if ev.Text != "" {
					sw.Send(schema.AssistantMessage(ev.Text, nil), nil)
				}
			case llm.SEToolUseStart:
				idx := ev.ToolIndex
				toolIdx = idx
				open = true
				sw.Send(schema.AssistantMessage("", []schema.ToolCall{{
					ID:       ev.ToolID,
					Function: schema.FunctionCall{Name: ev.ToolName},
					Index:    &idx,
				}}), nil)
			case llm.SEToolInputJSON:
				idx := ev.ToolIndex
				if idx < 0 {
					idx = toolIdx // no index from this provider: most recent call
				}
				if ev.Text != "" {
					i := idx
					sw.Send(schema.AssistantMessage("", []schema.ToolCall{{
						Function: schema.FunctionCall{Arguments: ev.Text},
						Index:    &i,
					}}), nil)
				}
			case llm.SEMessageDelta:
				m := schema.AssistantMessage("", nil)
				rm := &schema.ResponseMeta{FinishReason: ev.StopReason}
				if ev.Usage != (llm.Usage{}) {
					rm.Usage = UsageToToken(ev.Usage)
				}
				m.ResponseMeta = rm
				sw.Send(m, nil)
			case llm.SEMessageStop:
				// EOF marker; the pipe closes below
				_ = open
			}
		}
	}()
	return sr, nil
}

var _ model.ToolCallingChatModel = (*bridgeModel)(nil)
