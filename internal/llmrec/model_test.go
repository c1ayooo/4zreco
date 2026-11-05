package llmrec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/transcript"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/google/uuid"
)

// fakeChatModel is a configurable model.ToolCallingChatModel.
type fakeChatModel struct {
	mu       sync.Mutex
	calls    int
	generate func(context.Context, []*schema.Message) (*schema.Message, error)
	stream   func(context.Context, []*schema.Message) (*schema.StreamReader[*schema.Message], error)
	// lastTools records the tool set of the most recent call through this model
	// or any WithTools view of it.
	lastTools []*schema.ToolInfo
}

func (f *fakeChatModel) Generate(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.generate(ctx, input)
}

func (f *fakeChatModel) Stream(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.stream(ctx, input)
}

func (f *fakeChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	c := &fakeChatModel{generate: f.generate, stream: f.stream}
	c.lastTools = tools
	return c, nil
}

func (f *fakeChatModel) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// atomicFixture is a complete Generate response: reasoning + text + usage.
func atomicFixture() *schema.Message {
	msg := schema.AssistantMessage("answer", nil)
	msg.ReasoningContent = "reasoning"
	msg.ResponseMeta = &schema.ResponseMeta{FinishReason: "stop", Usage: &schema.TokenUsage{
		PromptTokens: 16, CompletionTokens: 3, TotalTokens: 19,
		PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 4, CacheWriteTokens: 2},
	}}
	return msg
}

// usageChunk is a stream chunk carrying usage (final-chunk-wins contract).
func usageChunk(prompt, completion int) *schema.Message {
	msg := schema.AssistantMessage("", nil)
	msg.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: prompt, CompletionTokens: completion}}
	return msg
}

// TestModelGenerateUsageAndMeteringRows: the Generate path derives usage from
// ResponseMeta through acllm.UsageFromToken and writes both the llm_usage row
// and the llm_records trace (pg nil = inert, must not panic).
func TestModelGenerateUsageAndMeteringRows(t *testing.T) {
	dsn := os.Getenv("ZRECO_PG_DSN")
	if dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	// llm_records（trace 表）同样不在 db.Open 的建表面里，自建一次。
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}

	inner := &fakeChatModel{generate: func(context.Context, []*schema.Message) (*schema.Message, error) {
		return atomicFixture(), nil
	}}
	profile := "rec-model-gen-" + uuid.NewString()
	recorder := WrapModel(inner, pg, "fixture-model", profile, "enabled", "high", func() bool { return true })
	input := []*schema.Message{schema.SystemMessage("sys"), schema.UserMessage("hi")}
	msg, err := recorder.Generate(transcript.WithSessionID(context.Background(), "exp9-worker-i4"), input)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if messageText(msg) != "answer" || messageReasoning(msg) != "reasoning" || finishReason(msg) != "stop" {
		t.Fatalf("Generate response wrong: %+v", msg)
	}

	// usage: PromptTokens 16 = input 10 + cache_read 4 + cache_write 2.
	var count, input_, output, cacheRead, cacheWrite, intentID int
	var worker, status string
	waitFor(t, func() bool {
		return pg.QueryRow(`SELECT count(*),max(input_tokens),max(output_tokens),max(cache_read),max(cache_write),max(worker),max(status),max(intent_id)
FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &input_, &output, &cacheRead, &cacheWrite, &worker, &status, &intentID) == nil && count > 0
	}, "usage row never appeared")
	defer cleanupProfile(t, pg, profile)
	if input_ != 10 || output != 3 || cacheRead != 4 || cacheWrite != 2 {
		t.Fatalf("usage mapping wrong: input=%d output=%d read=%d write=%d, want 10/3/4/2", input_, output, cacheRead, cacheWrite)
	}
	if worker != "worker" || status != "ok" || intentID != 4 {
		t.Fatalf("attribution wrong: worker=%q status=%q intent=%d, want worker/ok/4", worker, status, intentID)
	}

	// Trace row: request body projected to the DTO vocabulary, frozen keys.
	var reqBody, respBody string
	waitFor(t, func() bool {
		return pg.QueryRow(`SELECT max(request_body),max(response_body) FROM llm_records WHERE profile_name=$1`, profile).Scan(&reqBody, &respBody) == nil && reqBody != ""
	}, "trace row never appeared")
	defer cleanupRecords(t, pg, profile)
	var reqMap map[string]any
	if err := json.Unmarshal([]byte(reqBody), &reqMap); err != nil {
		t.Fatalf("request body not JSON: %v (%s)", err, reqBody)
	}
	for _, key := range []string{"messages", "system", "thinking"} {
		if _, ok := reqMap[key]; !ok {
			t.Errorf("request body lost %q key: %s", key, reqBody)
		}
	}
	msgsJSON, _ := json.Marshal(reqMap["messages"])
	if !strings.Contains(string(msgsJSON), `"role":"user"`) || !strings.Contains(string(msgsJSON), `"type":"text"`) {
		t.Errorf("request messages not in DTO shape: %s", msgsJSON)
	}
	if sys, _ := reqMap["system"].([]any); len(sys) != 1 || sys[0] != "sys" {
		t.Errorf("system segment lost: %s", reqBody)
	}
	var respMap map[string]any
	if err := json.Unmarshal([]byte(respBody), &respMap); err != nil {
		t.Fatalf("response body not JSON: %v", err)
	}
	if respMap["text"] != "answer" || respMap["stop_reason"] != "stop" {
		t.Errorf("response body wrong: %s", respBody)
	}
	if u, _ := respMap["usage"].(map[string]any); u["input_tokens"] != float64(10) || u["cache_read_tokens"] != float64(4) {
		t.Errorf("response usage wrong: %s", respBody)
	}
}

// The stream rows are written by the observer goroutine once the tee'd branch
// settles, so the metering test polls instead of asserting synchronously.
func TestModelStreamUsageRecordedOnceOnConsumerCancellation(t *testing.T) {
	dsn := os.Getenv("ZRECO_PG_DSN")
	if dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	for _, early := range []bool{false, true} {
		profile := "rec-model-stream-" + uuid.NewString()
		ctx, cancel := context.WithCancel(transcript.WithSessionID(t.Context(), "exp0-btw-test"))
		// released gates the stream's end, mirroring a real provider whose body
		// only fails once a pending cancellation is delivered — so the healthy
		// run's status is decided while the context is still live.
		released := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(released) }) }
		defer cancel()
		inner := &fakeChatModel{stream: func(callCtx context.Context, _ []*schema.Message) (*schema.StreamReader[*schema.Message], error) {
			sr, sw := schema.Pipe[*schema.Message](3)
			go func() {
				defer sw.Close()
				if sw.Send(usageChunk(23, 0), nil) {
					return
				}
				if sw.Send(usageChunk(23, 5), nil) {
					return
				}
				<-released
				select {
				case <-callCtx.Done():
					sw.Send(nil, callCtx.Err())
				default:
					sw.Send(nil, io.EOF)
				}
			}()
			return sr, nil
		}}
		recorder := WrapModel(inner, pg, "fixture", profile, "", "", func() bool { return false })
		sr, err := recorder.Stream(ctx, []*schema.Message{schema.UserMessage("hi")})
		if err != nil {
			t.Fatal(err)
		}
		chunks := 0
		for {
			_, rerr := sr.Recv()
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				t.Fatal(rerr)
			}
			chunks++
			if early && chunks == 1 {
				cancel() // Consumer exits before the provider surfaces the cancellation.
				break
			}
			if !early && chunks == 2 {
				release() // let the provider end the stream cleanly
			}
		}
		sr.Close()
		release()

		var count, input_, output int
		var worker, status string
		wantStatus := "ok"
		if early {
			wantStatus = "error"
		}
		waitFor(t, func() bool {
			return pg.QueryRow(`SELECT count(*),max(input_tokens),max(output_tokens),max(worker),max(status)
FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &input_, &output, &worker, &status) == nil && count > 0
		}, "usage row never appeared")
		cleanupProfile(t, pg, profile)
		// The status is decided before the row is written, so cancelling only
		// now cannot flip the healthy run to an error row.
		if !early {
			cancel()
		}
		// Exactly one row, folded from the FINAL usage-bearing chunk (23/5),
		// not summed across both usage chunks (which would give 46/5).
		if count != 1 || input_ != 23 || output != 5 || worker != "btw" || status != wantStatus {
			t.Fatalf("early=%v: count=%d usage=%d/%d worker=%q status=%q (want 1 row, 23/5, btw, %s)",
				early, count, input_, output, worker, status, wantStatus)
		}
	}
}

// The Stream path must still surface an inner Stream() failure synchronously and
// record the error row even though no stream ever existed.
func TestModelStreamEstablishmentFailureRecordsError(t *testing.T) {
	dsn := os.Getenv("ZRECO_PG_DSN")
	if dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	inner := &fakeChatModel{stream: func(context.Context, []*schema.Message) (*schema.StreamReader[*schema.Message], error) {
		return nil, errors.New("openai, status code: 401, message: bad key")
	}}
	profile := "rec-model-err-" + uuid.NewString()
	recorder := WrapModel(inner, pg, "fixture", profile, "", "", func() bool { return false })
	if _, err := recorder.Stream(context.Background(), nil); err == nil {
		t.Fatal("inner establishment error must surface")
	}
	var count int
	var status string
	waitFor(t, func() bool {
		return pg.QueryRow(`SELECT count(*),max(status) FROM llm_usage WHERE profile_name=$1`, profile).Scan(&count, &status) == nil && count > 0
	}, "error usage row never appeared")
	cleanupProfile(t, pg, profile)
	if status != "error" {
		t.Fatalf("status=%q, want error", status)
	}
}

// WithTools must re-wrap so recording (and the serialized tool names) survive
// tool binding, without mutating the original recorder.
func TestModelWithToolsRewrapsAndNamesTools(t *testing.T) {
	dsn := os.Getenv("ZRECO_PG_DSN")
	if dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	inner := &fakeChatModel{generate: func(context.Context, []*schema.Message) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	profile := "rec-model-tools-" + uuid.NewString()
	recorder := WrapModel(inner, pg, "fixture", profile, "", "", func() bool { return true })
	tools := []*schema.ToolInfo{{Name: "nmap_scan", Desc: "scan"}}
	bound, err := recorder.WithTools(tools)
	if err != nil {
		t.Fatal(err)
	}
	if bound == model.ToolCallingChatModel(recorder) {
		t.Fatal("WithTools must not return the same recorder")
	}
	if _, err := bound.Generate(context.Background(), []*schema.Message{schema.UserMessage("go")}); err != nil {
		t.Fatal(err)
	}
	var reqBody string
	waitFor(t, func() bool {
		return pg.QueryRow(`SELECT max(request_body) FROM llm_records WHERE profile_name=$1`, profile).Scan(&reqBody) == nil && reqBody != ""
	}, "trace row never appeared")
	cleanupRecords(t, pg, profile)
	if !strings.Contains(reqBody, `"tools":["nmap_scan"]`) {
		t.Errorf("bound tool names not recorded: %s", reqBody)
	}
}

// waitFor polls a condition with a bounded deadline (no fixed sleeps).
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cleanupProfile(t *testing.T, pg *db.DB, profile string) {
	t.Helper()
	if _, err := pg.Exec(`DELETE FROM llm_usage WHERE profile_name=$1`, profile); err != nil {
		t.Fatalf("cleanup llm_usage: %v", err)
	}
}

func cleanupRecords(t *testing.T, pg *db.DB, profile string) {
	t.Helper()
	if _, err := pg.Exec(`DELETE FROM llm_records WHERE profile_name=$1`, profile); err != nil {
		t.Fatalf("cleanup llm_records: %v", err)
	}
}
