package acllm

// Differential tests for the norma/compaction port (compaction.go): the port
// and the norma original run the SAME scenarios through their public API with
// the same fake summarizer, and the outputs must be byte-identical (JSON) —
// the proof that the 判据 survived the move (方案 §2.1.2: 阈值/分块算法移植，
// 判据一个不改).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	ncomp "github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
)

// fakeSummary is deterministic so both compactors see identical digests.
func fakeSummary(ctx context.Context, msgs []llm.Message) (string, error) {
	return fmt.Sprintf("summary of %d messages", len(msgs)), nil
}

// dtos builds n filler user messages with `size`-char texts.
func dtos(n, size int) []llm.Message {
	out := make([]llm.Message, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, llm.UserText(fmt.Sprintf("msg-%02d:%s", i, strings.Repeat("x", size))))
	}
	return out
}

func jsonEq(t *testing.T, name string, a, b []llm.Message) {
	t.Helper()
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatalf("%s diverged from norma compaction:\n port:  %s\n norma: %s", name, ab, bb)
	}
}

func newPair(windowTokens int) (*Compactor, *ncomp.Compactor) {
	cfg := func() CompactionConfig { return CompactionConfig{ContextWindow: windowTokens} }
	ncfg := func() ncomp.Config { return ncomp.Config{ContextWindow: windowTokens} }
	return NewCompactor(cfg(), fakeSummary), ncomp.New(ncfg(), fakeSummary)
}

// TestPortMatchesNormaBelowThreshold: small histories pass through untouched,
// identically.
func TestPortMatchesNormaBelowThreshold(t *testing.T) {
	port, norma := newPair(200000)
	in := dtos(6, 40)
	ctx := context.Background()
	jsonEq(t, "below-micro-threshold", port.Pre(ctx, in, 0), norma.Pre(ctx, in, 0))
}

// TestPortMatchesNormaMicroCompact: many compactable tool results → the old
// ones cleared identically (keep the most recent 5). Sized to cross the micro
// threshold (8×48000 chars ≈ 128k tokens > 115.2k) but stay below the auto
// threshold (179k), so only MicroCompact fires.
func TestPortMatchesNormaMicroCompact(t *testing.T) {
	port, norma := newPair(200000)
	var in []llm.Message
	for i := 0; i < 8; i++ {
		in = append(in, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: fmt.Sprintf("tu_%d", i), Name: "Bash", Input: json.RawMessage(`{"command":"ls"}`)},
		}})
		in = append(in, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
			llm.ToolResultText(fmt.Sprintf("tu_%d", i), strings.Repeat("r", 48000), false),
		}})
	}
	ctx := context.Background()
	outP := port.Pre(ctx, append([]llm.Message(nil), in...), 0)
	outN := norma.Pre(ctx, append([]llm.Message(nil), in...), 0)
	jsonEq(t, "micro-compact", outP, outN)
	// And the clearing actually happened (5 most recent kept).
	if got := countCleared(outP); got != 3 {
		t.Fatalf("cleared %d results, want 3", got)
	}
}

func countCleared(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && len(b.Content) == 1 && b.Content[0].Text == "[Old tool result content cleared]" {
				n++
			}
		}
	}
	return n
}

// TestPortMatchesNormaAutoCompact: a history at the token threshold → boundary
// + summary inserted at the same place with the same kept tail.
func TestPortMatchesNormaAutoCompact(t *testing.T) {
	// window 60000 → reserved 8000 → effective 52000 → buffer 13000 →
	// autoThreshold 39000 tokens; 40×4000 chars ≈ 53k tokens clears it.
	port, norma := newPair(60000)
	in := dtos(40, 4000)
	ctx := context.Background()
	outP := port.Pre(ctx, append([]llm.Message(nil), in...), 0)
	outN := norma.Pre(ctx, append([]llm.Message(nil), in...), 0)
	jsonEq(t, "auto-compact", outP, outN)
	if countBoundaryMarkers(outP) == 0 {
		t.Fatalf("expected a compact boundary, none inserted")
	}
}

// TestPortMatchesNormaReactive: Reactive shrinks identically.
func TestPortMatchesNormaReactive(t *testing.T) {
	port, norma := newPair(60000)
	in := dtos(40, 4000)
	ctx := context.Background()
	outP, okP := port.Reactive(ctx, append([]llm.Message(nil), in...))
	outN, okN := norma.Reactive(ctx, append([]llm.Message(nil), in...))
	if okP != okN {
		t.Fatalf("reactive ok mismatch: port=%v norma=%v", okP, okN)
	}
	if !okP {
		t.Fatalf("expected reactive compaction to shrink")
	}
	jsonEq(t, "reactive", outP, outN)
}

// TestPortMatchesNormaKeepRecent: the preserved tail (KeepRecent default 8)
// survives behind the boundary identically.
func TestPortMatchesNormaKeepRecent(t *testing.T) {
	port, norma := newPair(60000)
	in := dtos(30, 4000)
	ctx := context.Background()
	outP := port.Pre(ctx, append([]llm.Message(nil), in...), 0)
	outN := norma.Pre(ctx, append([]llm.Message(nil), in...), 0)
	jsonEq(t, "keep-recent", outP, outN)
	i := llm.LastBoundaryIndex(outP)
	tail := len(outP) - (i + 1)
	if tail < 8 {
		t.Fatalf("kept tail = %d, want >= 8", tail)
	}
}

// TestPortMatchesNormaSkillReinject: a skill invocation in the summarized head
// is re-injected verbatim after the summary, identically.
func TestPortMatchesNormaSkillReinject(t *testing.T) {
	port, norma := newPair(60000)
	var in []llm.Message
	in = append(in, llm.UserText("kick off"))
	skill := llm.SkillInvocationMessage("nmap", "/skills/nmap", strings.Repeat("s", 3000))
	if _, ok := llm.SkillInvocationName(skill); !ok {
		t.Fatalf("test setup: skill message not recognized as skill invocation")
	}
	in = append(in, skill)
	in = append(in, dtos(30, 4000)...)
	ctx := context.Background()
	outP := port.Pre(ctx, append([]llm.Message(nil), in...), 0)
	outN := norma.Pre(ctx, append([]llm.Message(nil), in...), 0)
	jsonEq(t, "skill-reinject", outP, outN)
	// The skill really was re-injected behind the boundary.
	i := llm.LastBoundaryIndex(outP)
	if i < 0 || !llm.IsBoundaryMarker(outP[i+1]) && !strings.Contains(outP[i+2].Text(), "invoked-skill") {
		// boundary, summary, then the re-injected skill message
		found := false
		for _, m := range outP[i+1:] {
			if _, ok := llm.SkillInvocationName(m); ok {
				found = true
			}
		}
		if !found {
			t.Fatalf("skill invocation not re-injected after boundary")
		}
	}
}

// TestPortMatchesNormaOverflowClassification: identical verdicts on the error
// strings both providers can emit.
func TestPortMatchesNormaOverflowClassification(t *testing.T) {
	cases := []error{
		nil,
		fmt.Errorf("request too long: 300000 tokens"),
		fmt.Errorf("prompt is too long: 210000 tokens > 200000 maximum"),
		fmt.Errorf("context length exceeded"),
		fmt.Errorf("context_length_exceeded"),
		fmt.Errorf("this model's maximum context length is 128000 tokens"),
		fmt.Errorf("status 413"),
		fmt.Errorf("status code: 413"), // eino-ext adapter phrasing — same verdict on both sides
		fmt.Errorf("connection refused"),
	}
	port, norma := newPair(60000)
	for i, err := range cases {
		if port.IsOverflow(err) != norma.IsOverflow(err) {
			t.Fatalf("case %d (%v): port=%v norma=%v", i, err, port.IsOverflow(err), norma.IsOverflow(err))
		}
	}
}

// TestPortSummarizerFailureTrip: three consecutive summarizer failures trip the
// compactor (norma maxAutoCompactFails), identically.
func TestPortSummarizerFailureTrip(t *testing.T) {
	ctx := context.Background()
	fail := func(ctx context.Context, msgs []llm.Message) (string, error) { return "", fmt.Errorf("boom") }

	port := NewCompactor(CompactionConfig{ContextWindow: 60000}, fail)
	norma := ncomp.New(ncomp.Config{ContextWindow: 60000}, fail)
	in := dtos(40, 4000)
	for attempt := 0; attempt < 5; attempt++ {
		outP := port.Pre(ctx, append([]llm.Message(nil), in...), 0)
		outN := norma.Pre(ctx, append([]llm.Message(nil), in...), 0)
		jsonEq(t, fmt.Sprintf("fail-trip-%d", attempt), outP, outN)
	}
	// After the trip, nothing compacts anymore.
	if countBoundaryMarkers(port.Pre(ctx, in, 0)) != 0 {
		t.Fatalf("port compactor did not trip after repeated failures")
	}
}
