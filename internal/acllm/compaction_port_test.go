package acllm

// Golden tests for the norma/compaction port (compaction.go): each scenario's
// expected output is the BYTE-EXACT result the norma original produced for the
// same input — captured by a differential run (port vs norma oracle) at P4
// time, before norma left go.mod. The goldens pin the 判据 that survived the
// move (方案 §2.1.2: 阈值/分块算法移植，判据一个不改); divergence from them
// means the threshold/chunking behavior drifted, not just encoding.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

// fakeSummary is deterministic so compactors see identical digests.
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

func cp(in []llm.Message) []llm.Message { return append([]llm.Message(nil), in...) }

func overflowCases() []error {
	return []error{
		nil,
		fmt.Errorf("request too long: 300000 tokens"),
		fmt.Errorf("prompt is too long: 210000 tokens > 200000 maximum"),
		fmt.Errorf("context length exceeded"),
		fmt.Errorf("context_length_exceeded"),
		fmt.Errorf("this model's maximum context length is 128000 tokens"),
		fmt.Errorf("status 413"),
		fmt.Errorf("status code: 413"), // eino-ext adapter phrasing
		fmt.Errorf("connection refused"),
	}
}

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "compaction_port", name+".json"))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate via git history: compaction_port_golden_gen_test.go @ P4)", name, err)
	}
	return b
}

// jsonEqGolden marshals the port's output and compares byte-exact against the
// frozen norma-side golden (goldens are stored indented; Compact text-level
// folding is exactly what MarshalIndent added, so comparison stays byte-exact).
func jsonEqGolden(t *testing.T, name string, port []llm.Message) {
	t.Helper()
	ab, _ := json.Marshal(port)
	var buf bytes.Buffer
	if err := json.Compact(&buf, golden(t, name)); err != nil {
		t.Fatalf("%s golden: %v", name, err)
	}
	if string(ab) != buf.String() {
		t.Fatalf("%s diverged from the norma-frozen golden:\n got:    %s\n golden: %s", name, ab, buf.String())
	}
}

func newCompactor(windowTokens int) *Compactor {
	return NewCompactor(CompactionConfig{ContextWindow: windowTokens}, fakeSummary)
}

// TestPortGoldenBelowThreshold: small histories pass through untouched.
func TestPortGoldenBelowThreshold(t *testing.T) {
	port := newCompactor(200000)
	in := dtos(6, 40)
	jsonEqGolden(t, "below-micro", port.Pre(context.Background(), in, 0))
}

// TestPortGoldenMicroCompact: many compactable tool results → the old ones
// cleared (keep the most recent 5). Sized to cross the micro threshold
// (8×48000 chars ≈ 128k tokens > 115.2k) but stay below the auto threshold
// (179k), so only MicroCompact fires.
func TestPortGoldenMicroCompact(t *testing.T) {
	port := newCompactor(200000)
	var in []llm.Message
	for i := 0; i < 8; i++ {
		in = append(in, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: fmt.Sprintf("tu_%d", i), Name: "Bash", Input: json.RawMessage(`{"command":"ls"}`)},
		}})
		in = append(in, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
			llm.ToolResultText(fmt.Sprintf("tu_%d", i), strings.Repeat("r", 48000), false),
		}})
	}
	out := port.Pre(context.Background(), cp(in), 0)
	jsonEqGolden(t, "micro-compact", out)
	// And the clearing actually happened (5 most recent kept).
	if got := countCleared(out); got != 3 {
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

// TestPortGoldenAutoCompact: a history at the token threshold → boundary +
// summary inserted at the same place with the same kept tail.
func TestPortGoldenAutoCompact(t *testing.T) {
	// window 60000 → reserved 8000 → effective 52000 → buffer 13000 →
	// autoThreshold 39000 tokens; 40×4000 chars ≈ 53k tokens clears it.
	port := newCompactor(60000)
	in := dtos(40, 4000)
	out := port.Pre(context.Background(), in, 0)
	jsonEqGolden(t, "auto-compact", out)
	if countBoundaryMarkers(out) == 0 {
		t.Fatalf("expected a compact boundary, none inserted")
	}
}

// TestPortGoldenReactive: Reactive shrinks (ok flag frozen alongside).
func TestPortGoldenReactive(t *testing.T) {
	port := newCompactor(60000)
	in := dtos(40, 4000)
	out, ok := port.Reactive(context.Background(), cp(in))
	var want struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(golden(t, "reactive-ok"), &want); err != nil {
		t.Fatalf("reactive-ok golden: %v", err)
	}
	if ok != want.OK {
		t.Fatalf("reactive ok = %v, want %v", ok, want.OK)
	}
	if !ok {
		t.Fatalf("expected reactive compaction to shrink")
	}
	jsonEqGolden(t, "reactive", out)
}

// TestPortGoldenKeepRecent: the preserved tail (KeepRecent default 8) survives
// behind the boundary.
func TestPortGoldenKeepRecent(t *testing.T) {
	port := newCompactor(60000)
	in := dtos(30, 4000)
	out := port.Pre(context.Background(), in, 0)
	jsonEqGolden(t, "keep-recent", out)
	i := llm.LastBoundaryIndex(out)
	tail := len(out) - (i + 1)
	if tail < 8 {
		t.Fatalf("kept tail = %d, want >= 8", tail)
	}
}

// TestPortGoldenSkillReinject: a skill invocation in the summarized head is
// re-injected verbatim after the summary.
func TestPortGoldenSkillReinject(t *testing.T) {
	port := newCompactor(60000)
	var in []llm.Message
	in = append(in, llm.UserText("kick off"))
	skill := llm.SkillInvocationMessage("nmap", "/skills/nmap", strings.Repeat("s", 3000))
	if _, ok := llm.SkillInvocationName(skill); !ok {
		t.Fatalf("test setup: skill message not recognized as skill invocation")
	}
	in = append(in, skill)
	in = append(in, dtos(30, 4000)...)
	out := port.Pre(context.Background(), in, 0)
	jsonEqGolden(t, "skill-reinject", out)
	// The skill really was re-injected behind the boundary.
	i := llm.LastBoundaryIndex(out)
	if i < 0 || !llm.IsBoundaryMarker(out[i+1]) && !strings.Contains(out[i+2].Text(), "invoked-skill") {
		// boundary, summary, then the re-injected skill message
		found := false
		for _, m := range out[i+1:] {
			if _, ok := llm.SkillInvocationName(m); ok {
				found = true
			}
		}
		if !found {
			t.Fatalf("skill invocation not re-injected after boundary")
		}
	}
}

// TestPortGoldenOverflowClassification: frozen verdicts on the error strings
// both providers can emit.
func TestPortGoldenOverflowClassification(t *testing.T) {
	port := newCompactor(60000)
	var want []bool
	if err := json.Unmarshal(golden(t, "overflow-verdicts"), &want); err != nil {
		t.Fatalf("overflow-verdicts golden: %v", err)
	}
	for i, err := range overflowCases() {
		if port.IsOverflow(err) != want[i] {
			t.Fatalf("case %d (%v): got %v, want %v", i, err, port.IsOverflow(err), want[i])
		}
	}
}

// TestPortSummarizerFailureTrip: three consecutive summarizer failures trip
// the compactor (norma maxAutoCompactFails); per-attempt outputs frozen.
func TestPortSummarizerFailureTrip(t *testing.T) {
	ctx := context.Background()
	fail := func(ctx context.Context, msgs []llm.Message) (string, error) { return "", fmt.Errorf("boom") }
	port := NewCompactor(CompactionConfig{ContextWindow: 60000}, fail)
	in := dtos(40, 4000)
	for attempt := 0; attempt < 5; attempt++ {
		jsonEqGolden(t, fmt.Sprintf("fail-trip-%d", attempt), port.Pre(ctx, cp(in), 0))
	}
	// After the trip, nothing compacts anymore.
	if countBoundaryMarkers(port.Pre(ctx, in, 0)) != 0 {
		t.Fatalf("port compactor did not trip after repeated failures")
	}
}
