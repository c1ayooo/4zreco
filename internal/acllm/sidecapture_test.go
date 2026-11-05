package acllm

// Tests for the eino-side CallModel snapshot decorator (sidecapture.go):
// pre-call snapshot, post-success final snapshot (boundProvider's clean-end
// rule), WithTools re-wrap survival, passthrough without a Capture, and the
// stream error path (no final save).

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/sidequestion"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// snapSpy is a sidequestion.Publisher capturing snapshots in order.
type snapSpy struct {
	mu    sync.Mutex
	snaps []sidequestion.Snapshot
}

func (s *snapSpy) publish(snap sidequestion.Snapshot) {
	s.mu.Lock()
	s.snaps = append(s.snaps, snap)
	s.mu.Unlock()
}

func (s *snapSpy) all() []sidequestion.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sidequestion.Snapshot(nil), s.snaps...)
}

// sqFakeModel answers / streams scripted chunks and records inputs.
type sqFakeModel struct {
	mu     sync.Mutex
	inputs [][]*schema.Message
	chunks []*schema.Message
	err    error
}

func (f *sqFakeModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	msg := schema.AssistantMessage("side answer", nil)
	msg.ResponseMeta = &schema.ResponseMeta{FinishReason: "end_turn", Usage: &schema.TokenUsage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12}}
	return msg, nil
}

func (f *sqFakeModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	onceErr := f.err
	f.mu.Unlock()
	if onceErr != nil {
		return nil, onceErr
	}
	return schema.StreamReaderFromArray(f.chunks), nil
}

func (f *sqFakeModel) WithTools(infos []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return f, nil
}

func sqTestModel() sidequestion.Model {
	return sidequestion.Model{ProfileID: 3, Name: "default", Format: "openai", Model: "gpt-x", Identity: "abc", Streaming: true, WindowTokens: 200000}
}

func newSqCapture(spy *snapSpy) *sidequestion.Capture {
	return sidequestion.NewCapture(sidequestion.Parent{ConversationID: 7}, 1, spy.publish)
}

// TestCaptureModelGenerateSnapshots: pre-call snapshot with the request view,
// then the final snapshot folding the assistant answer behind it.
func TestCaptureModelGenerateSnapshots(t *testing.T) {
	spy := &snapSpy{}
	cap := newSqCapture(spy)
	cm := BindCaptureModel(&sqFakeModel{}, sqTestModel())

	ctx := sidequestion.WithAttempt(context.Background(), cap)
	input := []*schema.Message{
		schema.SystemMessage("main system"),
		schema.UserMessage("what's the status?"),
	}
	if _, err := cm.Generate(ctx, input, model.WithMaxTokens(512)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snaps := spy.all()
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2 (pre-call + final)", len(snaps))
	}
	pre := snaps[0]
	if pre.Parent.ConversationID != 7 || pre.Model.Model != "gpt-x" {
		t.Fatalf("pre snapshot identity = %+v", pre)
	}
	if len(pre.Request.System) != 1 || pre.Request.System[0] != "main system" {
		t.Fatalf("pre system = %v", pre.Request.System)
	}
	if len(pre.Request.Messages) != 1 || pre.Request.Messages[0].Text() != "what's the status?" {
		t.Fatalf("pre messages = %+v", pre.Request.Messages)
	}
	if pre.Request.MaxTokens != 512 {
		t.Fatalf("pre max tokens = %d", pre.Request.MaxTokens)
	}
	final := snaps[1]
	if len(final.Request.Messages) != 2 || final.Request.Messages[1].Text() != "side answer" {
		t.Fatalf("final messages = %+v", final.Request.Messages)
	}
}

// TestCaptureModelPassthroughWithoutCapture: no Capture on ctx → the inner
// model is called directly and nothing is saved (boundProvider's rule).
func TestCaptureModelPassthroughWithoutCapture(t *testing.T) {
	spy := &snapSpy{}
	inner := &sqFakeModel{}
	cm := BindCaptureModel(inner, sqTestModel())
	if _, err := cm.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(spy.all()) != 0 {
		t.Fatalf("snapshots saved without a Capture: %d", len(spy.all()))
	}
	if len(inner.inputs) != 1 {
		t.Fatalf("inner model not called: %d", len(inner.inputs))
	}
}

// TestCaptureModelStreamCleanEndSavesFinal: streamed deltas fold into the
// final snapshot; an error mid-stream leaves only the pre-call snapshot; a
// cancelled context likewise.
func TestCaptureModelStreamCleanEndSavesFinal(t *testing.T) {
	chunks := []*schema.Message{
		schema.AssistantMessage("partial ", nil),
		schema.AssistantMessage("answer", nil),
	}

	t.Run("clean-end", func(t *testing.T) {
		spy := &snapSpy{}
		cap := newSqCapture(spy)
		cm := BindCaptureModel(&sqFakeModel{chunks: chunks}, sqTestModel())
		sr, err := cm.Stream(sidequestion.WithAttempt(context.Background(), cap), []*schema.Message{schema.UserMessage("q")})
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		for {
			if _, err := sr.Recv(); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("recv: %v", err)
				}
				break
			}
		}
		// the observer folds asynchronously — bounded polling, no sleep-timing assertions
		waitForCond(t, 2*time.Second, func() bool { return len(spy.all()) == 2 })
		snaps := spy.all()
		if got := snaps[1].Request.Messages; len(got) != 2 || got[1].Text() != "partial answer" {
			t.Fatalf("final streamed messages = %+v", got)
		}
	})

	t.Run("error-end", func(t *testing.T) {
		spy := &snapSpy{}
		cap := newSqCapture(spy)
		cm := BindCaptureModel(&sqFakeModel{chunks: chunks, err: errors.New("boom")}, sqTestModel())
		if _, err := cm.Stream(sidequestion.WithAttempt(context.Background(), cap), []*schema.Message{schema.UserMessage("q")}); err == nil {
			t.Fatalf("expected stream open error")
		}
		snaps := spy.all()
		if len(snaps) != 1 {
			t.Fatalf("error path snapshots = %d, want 1 (pre-call only)", len(snaps))
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		spy := &snapSpy{}
		cap := newSqCapture(spy)
		cm := BindCaptureModel(&sqFakeModel{chunks: chunks}, sqTestModel())
		ctx, cancel := context.WithCancel(sidequestion.WithAttempt(context.Background(), cap))
		sr, err := cm.Stream(ctx, []*schema.Message{schema.UserMessage("q")})
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		cancel() // walk away mid-stream
		for {
			if _, err := sr.Recv(); err != nil {
				break
			}
		}
		waitForCond(t, 2*time.Second, func() bool { return len(spy.all()) >= 1 })
		snaps := spy.all()
		if len(snaps) != 1 {
			t.Fatalf("cancelled stream saved %d snapshots, want 1 (pre-call only)", len(snaps))
		}
	})
}

// TestCaptureModelWithToolsSurvivesRebind: the derived model keeps snapshotting
// and the bound tool names ride the snapshot's Tools field.
func TestCaptureModelWithToolsSurvivesRebind(t *testing.T) {
	spy := &snapSpy{}
	cap := newSqCapture(spy)
	cm := BindCaptureModel(&sqFakeModel{}, sqTestModel())
	derived, err := cm.WithTools([]*schema.ToolInfo{{Name: "probe", Desc: "scan a host"}})
	if err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	if _, err := derived.Generate(sidequestion.WithAttempt(context.Background(), cap), []*schema.Message{schema.UserMessage("q")}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snaps := spy.all()
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}
	if len(snaps[0].Request.Tools) != 1 || snaps[0].Request.Tools[0].Name != "probe" {
		t.Fatalf("snapshot tools = %+v", snaps[0].Request.Tools)
	}
}

// --- bounded polling (AGENTS.md: no sleep-timing assertions; poll until a
// condition holds or a generous budget expires) ---

func waitForCond(t *testing.T, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", budget)
}
