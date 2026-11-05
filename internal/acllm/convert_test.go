package acllm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/cloudwego/eino/schema"
)

// The transcript on-disk shape is frozen from the norma era. These fixtures are
// the exact JSON norma wrote; decoding must keep working byte-for-byte.
const normaShapedAssistant = `{"role":"assistant","content":[
  {"type":"thinking","thinking":"ponder the input","signature":"sig==1"},
  {"type":"text","text":"running scan"},
  {"type":"tool_use","id":"toolu_01","name":"Bash","input":{"command":"ls"}}]}`

const normaShapedToolResult = `{"role":"user","content":[
  {"type":"tool_result","tool_use_id":"toolu_01","content":[{"type":"text","text":"file.txt"}],"is_error":true}]}`

// Gemini-shaped tool_use: the thought_signature field 4zreco's norma carries on
// tool_use blocks (frozen DTO field) must survive conversion both ways.
const geminiShapedAssistant = `{"role":"assistant","content":[
  {"type":"tool_use","id":"call_9","name":"run","input":{"cmd":"x"},"thought_signature":"gem-sig"}]}`

func decode(t *testing.T, s string) llm.Message {
	t.Helper()
	var m llm.Message
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestGoldenNormaJSONShape(t *testing.T) {
	m := decode(t, normaShapedAssistant)
	if len(m.Content) != 3 || m.Content[0].Signature != "sig==1" || m.Content[2].Name != "Bash" {
		t.Fatalf("assistant decoded wrong: %+v", m)
	}
	r := decode(t, normaShapedToolResult)
	if r.Content[0].ToolUseID != "toolu_01" || !r.Content[0].IsError {
		t.Fatalf("tool result decoded wrong: %+v", r)
	}
	// Round-trip through encoding keeps the same field names.
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var again llm.Message
	if err := json.Unmarshal(out, &again); err != nil || !again.Content[0].IsError {
		t.Fatalf("re-encode lost is_error: %s", out)
	}
}

func TestToSchemaAssistantRoundTrip(t *testing.T) {
	m := decode(t, normaShapedAssistant)
	sm := ToSchema([]llm.Message{m})
	if len(sm) != 1 {
		t.Fatalf("want 1 schema message, got %d", len(sm))
	}
	a := sm[0]
	if a.Role != schema.Assistant || a.Content != "running scan" {
		t.Errorf("content wrong: %+v", a)
	}
	if a.ReasoningContent != "ponder the input" {
		t.Errorf("ReasoningContent = %q", a.ReasoningContent)
	}
	if a.Extra[ExtraThinkingSignature] != "sig==1" {
		t.Errorf("signature = %v", a.Extra[ExtraThinkingSignature])
	}
	if len(a.ToolCalls) != 1 || a.ToolCalls[0].Function.Name != "Bash" {
		t.Fatalf("tool calls wrong: %+v", a.ToolCalls)
	}
	back := FromSchema(sm)
	if len(back) != 1 || back[0].Role != llm.RoleAssistant {
		t.Fatalf("round trip role wrong: %+v", back)
	}
	b := back[0]
	if b.Content[0].Type != llm.BlockThinking || b.Content[0].Thinking != "ponder the input" || b.Content[0].Signature != "sig==1" {
		t.Errorf("thinking block lost: %+v", b.Content[0])
	}
	if b.Content[1].Type != llm.BlockText || b.Content[1].Text != "running scan" {
		t.Errorf("text block lost: %+v", b.Content[1])
	}
	tb := b.Content[2]
	if tb.Type != llm.BlockToolUse || tb.ID != "toolu_01" || tb.Name != "Bash" || string(tb.Input) != `{"command":"ls"}` {
		t.Errorf("tool_use block lost: %+v", tb)
	}
	// The rebuilt message must marshal to the frozen JSON vocabulary.
	out, _ := json.Marshal(b)
	var original, rebuilt map[string]any
	_ = json.Unmarshal([]byte(normaShapedAssistant), &original)
	if err := json.Unmarshal(out, &rebuilt); err != nil {
		t.Fatalf("rebuild marshal: %v", err)
	}
	if !jsonEqual(original, rebuilt) {
		t.Errorf("round-trip JSON drifted:\noriginal: %s\nrebuilt:  %s", normaShapedAssistant, out)
	}
}

// jsonEqual compares decoded JSON trees so key ORDER (irrelevant to decoders)
// never fails an otherwise identical shape.
func jsonEqual(a, b map[string]any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb) // canonical via re-marshal of map[string]any is order-stable for our flat shapes
}

func TestToSchemaToolResultRoundTrip(t *testing.T) {
	r := decode(t, normaShapedToolResult)
	sm := ToSchema([]llm.Message{r})
	if len(sm) != 1 || sm[0].Role != schema.Tool {
		t.Fatalf("want single tool message, got %+v", sm)
	}
	if sm[0].ToolCallID != "toolu_01" || sm[0].Content != "file.txt" {
		t.Errorf("tool message wrong: %+v", sm[0])
	}
	if sm[0].Extra[ExtraIsError] != true {
		t.Errorf("is_error marker lost: %v", sm[0].Extra)
	}
	back := FromSchema(sm)
	if len(back) != 1 || back[0].Role != llm.RoleUser {
		t.Fatalf("tool result must come back as user message: %+v", back)
	}
	tb := back[0].Content[0]
	if tb.Type != llm.BlockToolResult || tb.ToolUseID != "toolu_01" || !tb.IsError || tb.Content[0].Text != "file.txt" {
		t.Errorf("tool_result block lost: %+v", tb)
	}
}

func TestThoughtSignatureRoundTrip(t *testing.T) {
	m := decode(t, geminiShapedAssistant)
	if m.Content[0].ThoughtSignature != "gem-sig" {
		t.Fatalf("fixture decode lost thought_signature: %+v", m.Content[0])
	}
	sm := ToSchema([]llm.Message{m})
	tc := sm[0].ToolCalls[0]
	if got, ok := tc.Extra[ExtraThoughtSignature].(string); !ok || got != "gem-sig" {
		t.Fatalf("thought signature lost on ToolCall.Extra: %+v", tc.Extra)
	}
	back := FromSchema(sm)
	if back[0].Content[0].ThoughtSignature != "gem-sig" {
		t.Fatalf("thought signature lost on the way back: %+v", back[0].Content[0])
	}
	// Marshaled shape keeps the frozen field name.
	out, _ := json.Marshal(back[0])
	if !strings.Contains(string(out), `"thought_signature":"gem-sig"`) {
		t.Errorf("rebuilt JSON lost thought_signature key: %s", out)
	}
}

func TestBoundarySchemaRoundTrip(t *testing.T) {
	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 123456, MessagesSummarized: 42}
	dto := llm.BoundaryMessage(meta)
	sm := ToSchema([]llm.Message{dto})
	if len(sm) != 1 {
		t.Fatalf("boundary must survive ToSchema: %+v", sm)
	}
	if _, ok := sm[0].Extra[ExtraBoundary]; !ok {
		t.Fatalf("boundary marker missing in schema message: %+v", sm[0])
	}
	back := FromSchema(sm)
	if len(back) != 1 || !llm.IsBoundaryMarker(back[0]) {
		t.Fatalf("boundary must survive FromSchema: %+v", back)
	}
	got, ok := llm.ParseBoundaryMeta(back[0])
	if !ok || got.Trigger != "auto" || got.PreTokens != 123456 || got.MessagesSummarized != 42 {
		t.Errorf("boundary meta lost: %+v ok=%v", got, ok)
	}
}

// The legacy bare-integer boundary payload (older transcripts) must come back
// byte-identically — the Extra carrier stores the whole DTO message verbatim.
func TestBoundaryLegacyIntegerFormRoundTrip(t *testing.T) {
	original := `{"role":"user","content":[{"type":"compact_boundary","input":98765}]}`
	dto := decode(t, original)
	sm := ToSchema([]llm.Message{dto})
	back := FromSchema(sm)
	out, err := json.Marshal(back[0])
	if err != nil {
		t.Fatal(err)
	}
	var o, r map[string]any
	if err := json.Unmarshal([]byte(original), &o); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("rebuilt boundary unmarshal: %v (%s)", err, out)
	}
	ob, _ := json.Marshal(o)
	rb, _ := json.Marshal(r)
	if string(ob) != string(rb) {
		t.Errorf("legacy boundary payload drifted:\noriginal: %s\nrebuilt:  %s", ob, rb)
	}
}

func TestFromSchemaSkipsSystemAndNil(t *testing.T) {
	msgs := []*schema.Message{
		schema.SystemMessage("sys prompt"),
		nil,
		schema.UserMessage("hello"),
	}
	back := FromSchema(msgs)
	if len(back) != 1 || back[0].Role != llm.RoleUser || back[0].Text() != "hello" {
		t.Fatalf("system/nil not skipped: %+v", back)
	}
}

// Empty assistant turns vanish going in (nothing to send) and come back with
// the norma empty-text-block shape so the transcript line stays well-formed.
func TestEmptyAssistantCollapsesToEmptyTextBlock(t *testing.T) {
	// A fully empty assistant message yields NO schema message (nothing to send).
	if got := ToSchema([]llm.Message{{Role: llm.RoleAssistant}}); len(got) != 0 {
		t.Fatalf("empty assistant must vanish, got %+v", got)
	}
	// The reverse: an eino assistant message with no content comes back with the
	// norma empty-text-block shape so the transcript line stays well-formed.
	back := FromSchema([]*schema.Message{schema.AssistantMessage("", nil)})
	if len(back) != 1 || len(back[0].Content) != 1 || back[0].Content[0].Type != llm.BlockText || back[0].Content[0].Text != "" {
		t.Fatalf("empty assistant rebuild wrong: %+v", back)
	}
	out, _ := json.Marshal(back[0])
	if string(out) != `{"role":"assistant","content":[{"type":"text"}]}` {
		t.Errorf("empty assistant JSON shape drifted: %s", out)
	}
}

func TestToolSchemaToInfo(t *testing.T) {
	info, err := ToolSchemaToInfo(llm.ToolSchema{
		Name:        "scan_host",
		Description: "run a scan",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string"},
			},
			"required": []any{"target"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "scan_host" || info.Desc != "run a scan" {
		t.Fatalf("info wrong: %+v", info)
	}
	if info.ParamsOneOf == nil {
		t.Fatal("ParamsOneOf lost")
	}
	// A schema-less tool keeps nil ParamsOneOf (eino's no-parameters signal).
	bare, err := ToolSchemaToInfo(llm.ToolSchema{Name: "noop"})
	if err != nil || bare.ParamsOneOf != nil {
		t.Fatalf("bare tool wrong: %+v err=%v", bare, err)
	}
}
