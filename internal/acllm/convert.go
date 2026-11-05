// Package acllm is the conversion layer of the eino migration
// (docs/Eino深度接入方案-2026-11-05.md §4-P1 第 2 条).
//
// It is the only sanctioned place where two vocabularies meet:
//
//   - the on-disk conversation vocabulary: norma's llm.Message / llm.ContentBlock
//     (Anthropic content-block shape: text/thinking/tool_use/tool_result blocks,
//     compact_boundary markers, Usage with cache tokens). Its JSON field names are
//     FROZEN — existing JSONL transcripts and resume paths decode against them.
//   - eino's schema.Message, the in-memory runtime representation the P1 kernel
//     will run on.
//
// convert.go maps between the two. ToSchema feeds transcript-loaded history into
// eino models; FromSchema projects eino-side messages back to the DTO vocabulary
// for transcript writes and recorded request bodies. The on-disk JSON shape is
// unchanged by construction: the DTO side of every function is norma's llm types
// themselves, not a re-declared look-alike. When norma is deleted (P4), these
// DTO types must be re-owned here with identical JSON tags (4zrec's acllm dto.go
// is the precedent) — until then this package deliberately keeps importing them.
//
// Shadow-run status (刀①): nothing in the norma main loop calls this package
// yet. The provider decorators (internal/llmpool model.go, internal/llmrec
// model.go) and their tests are the only consumers, validating conversion and
// usage mapping before the loop switches over.
package acllm

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/norma/llm"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

// schema-side markers. eino's schema.Message carries no error flag on tool
// messages and no compaction-boundary concept, so both ride in Extra under
// these keys. Thinking replay for the eino-ext claude provider deliberately
// uses the provider's own Extra keys (see toSchemaAssistant) — the adapter
// itself defines "_eino_claude_thinking(_signature)" (message_extra.go), so a
// replayed history round-trips through the adapter without a second mapping.
const (
	// ExtraIsError marks a tool message whose result was an error.
	ExtraIsError = "_acllm_is_error"
	// ExtraBoundary marks a compact-boundary carrier message; the value is the
	// JSON encoding of the original DTO message (payload preserved verbatim —
	// both the structured BoundaryMeta form and the legacy bare-integer form
	// round-trip byte-exactly).
	ExtraBoundary = "_acllm_compact_boundary"
	// ExtraThinkingSignature carries the Anthropic thinking signature on
	// assistant messages (mirrors the eino-ext claude provider's key so replay
	// round-trips through it).
	ExtraThinkingSignature = "_eino_claude_thinking_signature"
	// ExtraThinking carries the raw thinking text for claude replay.
	ExtraThinking = "_eino_claude_thinking"
	// ExtraThoughtSignature carries Gemini's opaque per-tool-call token on a
	// ToolCall (schema.ToolCall.Extra) — mirrors DTO ContentBlock.ThoughtSignature.
	// The eino-ext openai adapter (libs/acl/openai v0.1.17) has no
	// thought-signature wire support, so a resumed Gemini-recorded tool call
	// replayed THROUGH that adapter still loses the signature on the wire; the
	// conversion layer keeps it faithful so no information is lost in the DTO
	// vocabulary itself.
	ExtraThoughtSignature = "_acllm_thought_signature"
)

// ToSchema converts DTO history into eino runtime messages. A DTO user message
// carrying tool_result blocks splits into separate schema tool messages (eino
// models tool results as role=tool messages, one per tool call); text rides in
// a user message. Thinking replays via the claude provider's Extra keys.
//
// Known fidelity limit (accepted drift, same as 4zrec): a DTO assistant message
// with several interleaved thinking blocks collapses into one ReasoningContent
// with the last block's signature — Anthropic interleaved-thinking replay
// across a resume of such a turn may be rejected by the API. Normal turns
// (thinking → tool_use → text) round-trip exactly.
func ToSchema(msgs []llm.Message) []*schema.Message {
	out := make([]*schema.Message, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case llm.RoleAssistant:
			if s := toSchemaAssistant(m); s != nil {
				out = append(out, s)
			}
		case llm.RoleUser:
			out = append(out, toSchemaUser(m)...)
		}
	}
	return out
}

func toSchemaAssistant(m llm.Message) *schema.Message {
	var (
		thinkBuf, textBuf string
		sig               string
		toolCalls         []schema.ToolCall
	)
	for _, b := range m.Content {
		switch b.Type {
		case llm.BlockThinking:
			if thinkBuf != "" {
				thinkBuf += "\n"
			}
			thinkBuf += b.Thinking
			if b.Signature != "" {
				sig = b.Signature
			}
		case llm.BlockText:
			textBuf += b.Text
		case llm.BlockToolUse:
			args := string(b.Input)
			if args == "" || !json.Valid([]byte(args)) {
				args = "{}"
			}
			tc := schema.ToolCall{
				ID:       b.ID,
				Function: schema.FunctionCall{Name: b.Name, Arguments: args},
			}
			if b.ThoughtSignature != "" {
				tc.Extra = map[string]any{ExtraThoughtSignature: b.ThoughtSignature}
			}
			toolCalls = append(toolCalls, tc)
		}
	}
	sm := schema.AssistantMessage(textBuf, toolCalls)
	if thinkBuf != "" {
		sm.ReasoningContent = thinkBuf
		if sm.Extra == nil {
			sm.Extra = map[string]any{}
		}
		sm.Extra[ExtraThinking] = thinkBuf
		if sig != "" {
			sm.Extra[ExtraThinkingSignature] = sig
		}
	}
	if len(sm.Content) == 0 && len(toolCalls) == 0 && thinkBuf == "" {
		return nil
	}
	return sm
}

func toSchemaUser(m llm.Message) []*schema.Message {
	var out []*schema.Message
	var textBuf string
	flush := func() {
		if textBuf != "" {
			out = append(out, schema.UserMessage(textBuf))
			textBuf = ""
		}
	}
	for _, b := range m.Content {
		switch b.Type {
		case llm.BlockText:
			textBuf += b.Text
		case llm.BlockToolResult:
			flush()
			out = append(out, toolResultSchema(b))
		case llm.BlockCompactBoundary:
			flush()
			payload, err := json.Marshal(m)
			if err != nil {
				continue // marshal of an llm.Message cannot fail in practice
			}
			out = append(out, &schema.Message{
				Role:  schema.User,
				Extra: map[string]any{ExtraBoundary: json.RawMessage(payload)},
			})
		}
	}
	flush()
	return out
}

func toolResultSchema(b llm.ContentBlock) *schema.Message {
	var text string
	for i, cb := range b.Content {
		if i > 0 {
			text += "\n"
		}
		text += cb.Text
	}
	sm := schema.ToolMessage(text, b.ToolUseID)
	if b.IsError {
		if sm.Extra == nil {
			sm.Extra = map[string]any{}
		}
		sm.Extra[ExtraIsError] = true
	}
	return sm
}

// FromSchema converts eino runtime messages back into DTO history (resume
// seeding, transcript writing, recorded request bodies). System messages are
// skipped — this project keeps the system prompt outside the message array, as
// before.
func FromSchema(msgs []*schema.Message) []llm.Message {
	out := make([]llm.Message, 0, len(msgs))
	for _, m := range msgs {
		if m == nil {
			continue
		}
		switch m.Role {
		case schema.Assistant:
			out = append(out, fromSchemaAssistant(m))
		case schema.User:
			if msg, ok := boundaryMessage(m); ok {
				out = append(out, msg)
				continue
			}
			// Known fidelity limit (accepted drift, same as 4zrec): multimodal
			// user input (MultiContent / UserInputMultiContent — image parts)
			// projects to Content only, so image parts are LOST here. The frozen
			// DTO vocabulary (norma llm.ContentBlock) has no image block type and
			// cannot grow without changing the on-disk transcript shape. When a
			// later cut needs multimodal input across the seam (e.g. docpreview
			// images), it must extend the DTO vocabulary deliberately and revisit
			// this projection — together with the eino-ext openai adapter's
			// missing thought-signature wire support.
			out = append(out, llm.UserText(m.Content))
		case schema.Tool:
			out = append(out, fromSchemaTool(m))
		}
	}
	return out
}

func fromSchemaAssistant(m *schema.Message) llm.Message {
	var blocks []llm.ContentBlock
	if m.ReasoningContent != "" {
		sig, _ := m.Extra[ExtraThinkingSignature].(string)
		blocks = append(blocks, llm.ContentBlock{Type: llm.BlockThinking, Thinking: m.ReasoningContent, Signature: sig})
	}
	if m.Content != "" {
		blocks = append(blocks, llm.TextBlock(m.Content))
	}
	for _, tc := range m.ToolCalls {
		b := llm.ContentBlock{
			Type:  llm.BlockToolUse,
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(tc.Function.Arguments),
		}
		if ts, ok := tc.Extra[ExtraThoughtSignature].(string); ok {
			b.ThoughtSignature = ts
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		blocks = []llm.ContentBlock{llm.TextBlock("")}
	}
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}
}

func fromSchemaTool(m *schema.Message) llm.Message {
	isErr, _ := m.Extra[ExtraIsError].(bool)
	return llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
		llm.ToolResultText(m.ToolCallID, m.Content, isErr),
	}}
}

// boundaryMessage decodes a boundary carrier back into the exact DTO message
// that was stored in Extra (payload verbatim — legacy bare-integer boundaries
// come back as they went in).
func boundaryMessage(m *schema.Message) (llm.Message, bool) {
	raw, ok := m.Extra[ExtraBoundary]
	if !ok {
		return llm.Message{}, false
	}
	switch t := raw.(type) {
	case json.RawMessage:
		var msg llm.Message
		if err := json.Unmarshal(t, &msg); err != nil {
			return llm.Message{}, false
		}
		return msg, true
	default:
		return llm.Message{}, false
	}
}

// ToolSchemaToInfo converts a DTO tool definition into eino's ToolInfo for
// model.WithTools: name and description verbatim, the JSON-schema input schema
// carried as ParamsOneOf. A tool without an input schema yields a ToolInfo with
// nil ParamsOneOf (eino's "no parameters" signal).
func ToolSchemaToInfo(ts llm.ToolSchema) (*schema.ToolInfo, error) {
	info := &schema.ToolInfo{Name: ts.Name, Desc: ts.Description}
	if len(ts.InputSchema) > 0 {
		raw, err := json.Marshal(ts.InputSchema)
		if err != nil {
			return nil, err
		}
		var js jsonschema.Schema
		if err := json.Unmarshal(raw, &js); err != nil {
			return nil, fmt.Errorf("acllm: tool %q input schema: %w", ts.Name, err)
		}
		info.ParamsOneOf = schema.NewParamsOneOfByJSONSchema(&js)
	}
	return info, nil
}

// UsageFromToken normalizes an eino TokenUsage into the DTO Usage. eino's
// PromptTokens is total prompt tokens INCLUDING cache reads/writes for both
// providers (the claude adapter adds them in; OpenAI's prompt_tokens already
// includes cached tokens), so the raw non-cache input is recovered by
// subtraction — matching what norma recorded in ledgers and UI.
func UsageFromToken(u *schema.TokenUsage) llm.Usage {
	if u == nil {
		return llm.Usage{}
	}
	in := u.PromptTokens - u.PromptTokenDetails.CachedTokens - u.PromptTokenDetails.CacheWriteTokens
	if in < 0 {
		in = u.PromptTokens
	}
	return llm.Usage{
		InputTokens:      in,
		OutputTokens:     u.CompletionTokens,
		CacheReadTokens:  u.PromptTokenDetails.CachedTokens,
		CacheWriteTokens: u.PromptTokenDetails.CacheWriteTokens,
	}
}

// UsageToToken builds an eino TokenUsage from DTO Usage (PromptTokens as the
// total, mirroring provider semantics).
func UsageToToken(u llm.Usage) *schema.TokenUsage {
	return &schema.TokenUsage{
		PromptTokens:     u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens + u.OutputTokens,
		PromptTokenDetails: schema.PromptTokenDetails{
			CachedTokens:     u.CacheReadTokens,
			CacheWriteTokens: u.CacheWriteTokens,
		},
	}
}
