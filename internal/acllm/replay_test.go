package acllm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// The replay fixtures are exact JSONL lines in the frozen norma transcript.Record
// shape — what every pre-existing session file on disk contains. Each line is
// loaded through the REAL norma transcript store (the same Load path resume uses
// today), converted DTO → schema → DTO, and the rebuilt message must marshal to
// the same JSON shape so the session can be re-persisted and re-read unchanged.
const replayJSONL = `{"uuid":"01","session_id":"exp7-worker-i2","timestamp":"2026-11-04T21:00:00Z","type":"message","message":{"role":"user","content":[{"type":"text","text":"对 10.0.0.8 做端口扫描"}]},"usage":null}
{"uuid":"02","parent_uuid":"01","session_id":"exp7-worker-i2","timestamp":"2026-11-04T21:00:03Z","type":"message","message":{"role":"assistant","content":[{"type":"thinking","thinking":"目标在内网,先扫常见端口","signature":"sigAB=="},{"type":"text","text":"开始扫描"},{"type":"tool_use","id":"toolu_1A","name":"nmap_scan","input":{"target":"10.0.0.8","ports":"1-1024"}}]},"usage":{"input_tokens":812,"output_tokens":214,"cache_read_tokens":640,"cache_write_tokens":120}}
{"uuid":"03","parent_uuid":"02","session_id":"exp7-worker-i2","timestamp":"2026-11-04T21:00:09Z","type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1A","content":[{"type":"text","text":"22/tcp open ssh\n80/tcp open http"}]}]},"usage":null}
{"uuid":"04","parent_uuid":"03","session_id":"exp7-worker-i2","timestamp":"2026-11-04T21:00:14Z","type":"boundary","boundary":{"trigger":"reactive","pre_tokens":91234,"messages_summarized":3},"message":null,"usage":null}
{"uuid":"05","parent_uuid":"04","session_id":"exp7-worker-i2","timestamp":"2026-11-04T21:00:15Z","type":"message","message":{"role":"user","content":[{"type":"text","text":"[压缩摘要] 此前已完成对 10.0.0.8 的端口扫描"}]},"usage":null}
`

// TestOldTranscriptReplay proves existing sessions are recoverable: load the
// frozen JSONL with norma's own store, replay through the conversion layer both
// ways, and require the on-disk JSON shape to survive byte-shape-identically.
// This is the P1 acceptance item "transcript 回放旧会话正常" at conversion-layer
// scale (方案 §4-P1 验收).
func TestOldTranscriptReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exp7-worker-i2.jsonl")
	if err := os.WriteFile(path, []byte(replayJSONL), 0o644); err != nil {
		t.Fatal(err)
	}

	store := transcript.NewStore(dir)
	recs, err := store.Load(path)
	if err != nil {
		t.Fatalf("old transcript failed to load: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("loaded %d records, want 5", len(recs))
	}

	// Collect the message records (skip the boundary line) and remember which
	// line each came from for the shape comparison below.
	var lines []msgLine
	raws := splitJSONLines(t, replayJSONL)
	for i, r := range recs {
		if r.Type != "message" || r.Message == nil {
			continue
		}
		raw := messageField(t, raws[i])
		lines = append(lines, msgLine{raw: raw, msg: *r.Message, lineIdx: i})
	}
	if len(lines) != 4 {
		t.Fatalf("expected 4 message records, got %d", len(lines))
	}

	// DTO → eino runtime messages.
	var msgs []llm.Message
	for _, l := range lines {
		msgs = append(msgs, l.msg)
	}
	schemaMsgs := ToSchema(msgs)
	// Shape expectations on the eino side:
	//  user text → 1 user message; assistant(thinking+text+tool_use) → 1;
	//  tool_result user → 1 tool message; summary user text → 1. Boundary line
	//  is not part of this set.
	if len(schemaMsgs) != 4 {
		t.Fatalf("ToSchema produced %d messages, want 4: %+v", len(schemaMsgs), schemaMsgs)
	}
	if schemaMsgs[1].ReasoningContent != "目标在内网,先扫常见端口" {
		t.Errorf("thinking did not replay: %q", schemaMsgs[1].ReasoningContent)
	}
	if schemaMsgs[1].Extra[ExtraThinkingSignature] != "sigAB==" {
		t.Errorf("thinking signature did not replay: %v", schemaMsgs[1].Extra)
	}
	if len(schemaMsgs[1].ToolCalls) != 1 || schemaMsgs[1].ToolCalls[0].ID != "toolu_1A" {
		t.Errorf("tool_use did not replay: %+v", schemaMsgs[1].ToolCalls)
	}
	if schemaMsgs[2].Role != "tool" || schemaMsgs[2].ToolCallID != "toolu_1A" {
		t.Errorf("tool_result did not replay as tool message: %+v", schemaMsgs[2])
	}

	// eino → DTO (what a resumed session would seed and persist).
	rebuilt := FromSchema(schemaMsgs)
	if len(rebuilt) != 4 {
		t.Fatalf("FromSchema produced %d messages, want 4", len(rebuilt))
	}

	// Every rebuilt message must marshal to the same JSON shape it had on disk.
	for i, l := range rebuilt {
		out, err := json.Marshal(l)
		if err != nil {
			t.Fatalf("rebuild marshal: %v", err)
		}
		var orig, got any
		if err := json.Unmarshal([]byte(lines[i].raw), &orig); err != nil {
			t.Fatalf("original message field decode: %v", err)
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("rebuilt message decode: %v (%s)", err, out)
		}
		ob, _ := json.Marshal(orig) // canonical key order via map decode+encode
		gb, _ := json.Marshal(got)
		if string(ob) != string(gb) {
			t.Errorf("line %d shape drifted:\n  on disk: %s\n  rebuilt: %s", lines[i].lineIdx, ob, gb)
		}
	}

	// The boundary record survives the load itself (its payload is DTO-native
	// and never passes through the conversion layer).
	boundary := recs[3]
	if boundary.Type != "boundary" || boundary.Boundary == nil {
		t.Fatalf("boundary record not loaded: %+v", boundary)
	}
	if boundary.Boundary.Trigger != "reactive" || boundary.Boundary.PreTokens != 91234 {
		t.Errorf("boundary meta lost on load: %+v", boundary.Boundary)
	}
}

// TestOldTranscriptResumeSeed replays a full loaded transcript through
// ToSchema the way the P1 kernel will seed a resumed session, verifying the
// message sequence the model would see (positions and roles).
func TestOldTranscriptResumeSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exp7-worker-i2.jsonl")
	if err := os.WriteFile(path, []byte(replayJSONL), 0o644); err != nil {
		t.Fatal(err)
	}
	recs, err := transcript.NewStore(dir).Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []llm.Message
	for _, r := range recs {
		if r.Type == "message" && r.Message != nil {
			msgs = append(msgs, *r.Message)
		}
	}
	sm := ToSchema(msgs)
	// user / assistant / tool / user — the exact sequence norma's
	// MessagesForAPI would produce for this working set.
	if len(sm) != 4 {
		t.Fatalf("seed = %d messages, want 4", len(sm))
	}
	wantRoles := []string{"user", "assistant", "tool", "user"}
	for i, role := range wantRoles {
		if string(sm[i].Role) != role {
			t.Errorf("seed[%d].Role = %s, want %s", i, sm[i].Role, role)
		}
	}
	if sm[3].Content != "[压缩摘要] 此前已完成对 10.0.0.8 的端口扫描" {
		t.Errorf("post-boundary summary lost: %q", sm[3].Content)
	}
}

// msgLine pairs a loaded DTO message with the exact "message" JSON it was
// decoded from (for the on-disk shape comparison).
type msgLine struct {
	raw     string
	msg     llm.Message
	lineIdx int
}

func splitJSONLines(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// messageField extracts the value of the "message" key from one JSONL line,
// preserving its exact on-disk encoding (raw bytes, not re-marshaled).
func messageField(t *testing.T, line string) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		t.Fatalf("fixture line is not valid JSON: %v", err)
	}
	raw, ok := obj["message"]
	if !ok || string(raw) == "null" {
		t.Fatalf("fixture line has no message field: %s", line)
	}
	return string(raw)
}
