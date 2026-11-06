// model.go is the eino-side half of the LLM recorder (方案 §4-P1 第 3 条): a
// model.ToolCallingChatModel decorator with the same metering + body-trace
// semantics the norma-side Recorder (llmrec.go) has always provided, so the P1
// kernel keeps usage ledgers and llm_records when the loop switches over.
//
// Shadow-run status (刀①): the norma loop still consumes llmrec.go's
// llm.Provider Recorder; nothing in it calls anything here. The two halves share
// the context keys, parseSession, Capture (raw wire capture) and the llm_usage /
// llm_records rows — the on-disk/DB shapes do not change.
//
// Usage derivation follows the eino contract: providers attach the WHOLE call's
// usage to the final usage-bearing chunk's ResponseMeta (no norma-style
// message_start/message_delta echo split), and acllm.UsageFromToken maps
// PromptTokens → input + cache_read + cache_write with the cache columns split
// out. Ported from the verified 4zrec implementation
// (internal/platform/llm/llmrec/llmrec.go), with this project's intent-level
// metering (B7) kept.
package llmrec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/c1ayooo/4zreco/internal/norma/transcript"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// ModelRecorder wraps a model.ToolCallingChatModel and records every call made
// through it (and through any model derived from it via WithTools).
type ModelRecorder struct {
	inner model.ToolCallingChatModel
	pg    *db.DB
	model string // model name (from config, not in the call input)
	prof  string // LLM profile name (from llm_profiles)
	// thinkingType / reasoningEffort 是配置级思考参数(思考开关 / 思考强度)。eino 接缝下
	// 它们被烘焙进底层模型,不再随每次调用传参,故 Recorder 在此单独带一份,序列化时
	// 写进录制。
	thinkingType    string
	reasoningEffort string
	boundTools      []*schema.ToolInfo // tools attached via WithTools on this Recorder
	enabled         func() bool        // reports whether recording is currently on; nil = always record
}

// WrapModel returns a ToolCallingChatModel that records calls to pg when
// enabled() reports true. profName is the LLM profile name (e.g. "default"); may
// be empty. thinkingType / reasoningEffort are the config-level thinking params
// baked into the wrapped model (empty = not sent). A nil enabled predicate
// records unconditionally.
func WrapModel(inner model.ToolCallingChatModel, pg *db.DB, modelName, profName, thinkingType, reasoningEffort string, enabled func() bool) *ModelRecorder {
	return &ModelRecorder{
		inner: inner, pg: pg, model: modelName, prof: profName,
		thinkingType: thinkingType, reasoningEffort: reasoningEffort, enabled: enabled,
	}
}

// WithTools re-wraps the derived model so recording survives tool binding. The
// derived Recorder remembers the bound tools so the serialized call trace can
// name them.
func (r *ModelRecorder) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := r.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}
	c := *r
	c.inner = inner
	c.boundTools = append(append([]*schema.ToolInfo{}, r.boundTools...), tools...)
	return &c, nil
}

// modelAttribution is the per-call task/worker/session bookkeeping parsed from ctx.
type modelAttribution struct {
	session  string
	taskID   string
	worker   string
	expID    int64
	intentID int64
}

// attribute derives task id, worker lane, exploration id and intent id from the
// call context. The session identifier (e.g. "exp1-worker-i3") is carried on
// ctx by the runtime via transcript.WithSessionID; reading it per-call is
// race-free even when planner and multiple workers share one Recorder instance.
func (r *ModelRecorder) attribute(ctx context.Context) modelAttribution {
	session := transcript.SessionIDFrom(ctx)
	parsedID, worker, intentID := parseSession(session)
	if ov := workerFrom(ctx); ov != "" {
		worker = ov
	}
	taskID := TaskIDFrom(ctx)
	if taskID == "" {
		// Backward compatibility for non-task callers. For task calls, the task
		// runtime always supplies the registry id explicitly.
		taskID = parsedID
	}
	return modelAttribution{session: session, taskID: taskID, worker: worker, expID: db.ParseExpID(parsedID), intentID: intentID}
}

func (a modelAttribution) status(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	return "error", err.Error()
}

// Generate implements model.ToolCallingChatModel. It delegates to the inner
// model and records the exchange: usage from the response's ResponseMeta, plus
// the full trace when body recording is on.
func (r *ModelRecorder) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	recordBodies := r.enabled == nil || r.enabled()
	start := time.Now()
	attr := r.attribute(ctx)

	// Serialize the call only when storing bodies (this is the expensive part).
	// Alongside it, attach a Capture so the HTTP transport can hand back the
	// untouched wire bodies — the normalized view below cannot reconstruct them
	// (tool schemas are collapsed to names, and the SSE framing is already
	// decoded). See capture.go.
	reqBody := ""
	var capt *Capture
	if recordBodies {
		reqBody = r.serializeCall(input, opts)
		ctx, capt = NewCapture(ctx)
	}

	msg, err := r.inner.Generate(ctx, input, opts...)
	var usage llm.Usage
	if msg != nil && msg.ResponseMeta != nil {
		usage = acllm.UsageFromToken(msg.ResponseMeta.Usage)
	}
	status, errMsg := attr.status(err)
	// Lightweight metering row — always written.
	r.recordUsage(attr, usage, int(time.Since(start).Milliseconds()), status)
	// Heavy trace row — only when body recording is on.
	if recordBodies {
		r.record(attr, reqBody, capt, start, messageText(msg), messageReasoning(msg), finishReason(msg), usage, status, errMsg)
	}
	return msg, err
}

// Stream implements model.ToolCallingChatModel. eino stream readers are
// single-reader, so the inner stream is tee'd with Copy(2): one branch is
// returned to the caller untouched (identical chunks, identical order), the
// other is drained by an observer goroutine that folds the usage from the
// usage-bearing final chunk and writes the metering/trace rows once the stream
// settles. The observer drains even when the consumer abandons its branch
// early, so usage stays complete for interrupted runs; a cancellation that
// reaches the model (or is pending at stream end) records status=error.
func (r *ModelRecorder) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	recordBodies := r.enabled == nil || r.enabled()
	start := time.Now()
	attr := r.attribute(ctx)

	reqBody := ""
	var capt *Capture
	if recordBodies {
		reqBody = r.serializeCall(input, opts)
		ctx, capt = NewCapture(ctx)
	}

	sr, err := r.inner.Stream(ctx, input, opts...)
	if err != nil {
		// The call never produced a stream: record the failure synchronously.
		status, errMsg := attr.status(err)
		r.recordUsage(attr, llm.Usage{}, int(time.Since(start).Milliseconds()), status)
		if recordBodies {
			r.record(attr, reqBody, capt, start, "", "", "", llm.Usage{}, status, errMsg)
		}
		return nil, err
	}

	branches := sr.Copy(2) // tee: [0] for the caller, [1] for the observer
	go r.observe(attr, branches[1], ctx, start, reqBody, capt, recordBodies)
	return branches[0], nil
}

// observe drains the tee'd branch, folds usage from the final usage-bearing
// chunk and writes the llm_usage row (plus the llm_records trace when enabled).
func (r *ModelRecorder) observe(attr modelAttribution, sr *schema.StreamReader[*schema.Message], ctx context.Context, start time.Time, reqBody string, capt *Capture, recordBodies bool) {
	defer sr.Close()

	var (
		chunks     []*schema.Message // accumulated only for the trace
		usage      llm.Usage
		stopReason string
		streamErr  error
	)
	for {
		msg, err := sr.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				streamErr = err
			}
			break
		}
		if msg == nil {
			continue
		}
		// Providers attach the WHOLE call's usage to the final chunk (eino's
		// ResponseMeta contract), so the last usage-bearing chunk wins — there
		// is no norma-style start/delta split to fold with Add.
		if msg.ResponseMeta != nil {
			if msg.ResponseMeta.FinishReason != "" {
				stopReason = msg.ResponseMeta.FinishReason
			}
			if msg.ResponseMeta.Usage != nil {
				usage = acllm.UsageFromToken(msg.ResponseMeta.Usage)
			}
		}
		if recordBodies {
			chunks = append(chunks, msg)
		}
	}

	// A cancellation that was pending when the stream settled means the
	// consumer walked away (or the run was interrupted): mirror the norma
	// recorder's finish(ctx.Err()) and mark the row as an error.
	if streamErr == nil {
		streamErr = ctx.Err()
	}
	status, errMsg := attr.status(streamErr)
	r.recordUsage(attr, usage, int(time.Since(start).Milliseconds()), status)
	if recordBodies {
		final, _ := schema.ConcatMessages(chunks) // nil-safe: only used for text below
		r.record(attr, reqBody, capt, start, messageText(final), messageReasoning(final), stopReason, usage, status, errMsg)
	}
}

func messageText(msg *schema.Message) string {
	if msg == nil {
		return ""
	}
	return msg.Content
}

func messageReasoning(msg *schema.Message) string {
	if msg == nil {
		return ""
	}
	return msg.ReasoningContent
}

func finishReason(msg *schema.Message) string {
	if msg == nil || msg.ResponseMeta == nil {
		return ""
	}
	return msg.ResponseMeta.FinishReason
}

// recordUsage appends one lightweight metering row to llm_usage (no bodies).
// Skips zero-token calls with no model, which carry nothing worth metering.
// intentID (B7) is the intent the session suffix i<n> points at, 0 = not tied to
// one intent (planner / mainagent / compactor / 无意图 worker 调用).
func (r *ModelRecorder) recordUsage(attr modelAttribution, usage llm.Usage, latencyMs int, status string) {
	if r.pg == nil {
		return
	}
	if r.model == "" && usage.InputTokens == 0 && usage.OutputTokens == 0 &&
		usage.CacheReadTokens == 0 && usage.CacheWriteTokens == 0 {
		return
	}
	err := r.pg.InsertLLMUsage(&db.LLMUsage{
		TaskID:        attr.taskID,
		ExplorationID: attr.expID,
		IntentID:      attr.intentID,
		Worker:        attr.worker,
		Model:         r.model,
		ProfileName:   r.prof,
		LatencyMs:     latencyMs,
		InputTokens:   usage.InputTokens,
		OutputTokens:  usage.OutputTokens,
		CacheRead:     usage.CacheReadTokens,
		CacheWrite:    usage.CacheWriteTokens,
		Status:        status,
	})
	if err != nil {
		log.Printf("[llmusage] insert: %v", err)
	}
}

// record persists one LLM call to PostgreSQL. On the Generate path this runs
// inside the calling operation; on the Stream path it runs on the observer
// goroutine once the tee'd branch settles — shortly after stream end rather
// than strictly inside the consumer's loop. (The norma-side Recorder still
// writes strictly inside the owning task operation; that property returns to
// this path when the loop switches and the eino-side caller owns the stream
// lifecycle.)
func (r *ModelRecorder) record(attr modelAttribution, reqBody string, capt *Capture, start time.Time, text, thinking, stopReason string, usage llm.Usage, status, errMsg string) {
	if r.pg == nil {
		return
	}

	// Build response body JSON — the same keys the norma-side Recorder writes.
	resp := map[string]any{
		"text":        text,
		"stop_reason": stopReason,
		"usage": map[string]int{
			"input_tokens":       usage.InputTokens,
			"output_tokens":      usage.OutputTokens,
			"cache_read_tokens":  usage.CacheReadTokens,
			"cache_write_tokens": usage.CacheWriteTokens,
		},
	}
	if thinking != "" {
		resp["thinking"] = thinking
	}
	respBody, _ := json.Marshal(resp)

	rec := &db.LLMRecord{
		SessionID:    attr.session,
		TaskID:       attr.taskID,
		Worker:       attr.worker,
		Model:        r.model,
		ProfileName:  r.prof,
		LatencyMs:    int(time.Since(start).Milliseconds()),
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		CacheRead:    usage.CacheReadTokens,
		CacheWrite:   usage.CacheWriteTokens,
		Status:       status,
		Error:        errMsg,
		RequestBody:  reqBody,
		ResponseBody: string(respBody),
		// Raw wire bodies; empty when the transport did not fill the Capture
		// (e.g. a provider dialing through a client without the capture hook, or
		// a call that failed before any HTTP request went out).
		RawRequest:  capt.RawRequest(),
		RawResponse: capt.RawResponse(),
	}

	if err := r.pg.InsertLLMRecord(rec); err != nil {
		log.Printf("[llmrec] insert: %v", err)
	}
}

// serializeCall builds a JSON representation of the eino model call: the input
// messages projected back to the DTO vocabulary (acllm.FromSchema — the JSON
// shape stays the frozen norma one), the system segments, the bound tool names
// and the effective call options. This replaces the norma-side
// serializeRequest; the per-request thinking override no longer exists under
// the eino seam (thinking params are config-level only).
func (r *ModelRecorder) serializeCall(input []*schema.Message, opts []model.Option) string {
	common := model.GetCommonOptions(&model.Options{}, opts...)
	m := map[string]any{
		"messages": acllm.FromSchema(input),
	}
	if system := systemSegments(input); len(system) > 0 {
		m["system"] = system
	}
	// 记录本次调用生效的思考参数。type/effort 均取配置级值(eino 接缝下思考参数不随
	// 调用传参;norma 时代 compaction 摘要的每请求 disabled 覆盖随接缝消失)。
	if r.thinkingType != "" || r.reasoningEffort != "" {
		m["thinking"] = map[string]string{"type": r.thinkingType, "effort": r.reasoningEffort}
	}
	tools := append(append([]*schema.ToolInfo{}, r.boundTools...), common.Tools...)
	if len(tools) > 0 {
		// Store tool names only (full schemas are huge).
		names := make([]string, len(tools))
		for i, t := range tools {
			names[i] = t.Name
		}
		m["tools"] = names
		m["tools_count"] = len(tools)
	}
	if common.Model != nil {
		m["model"] = *common.Model
	}
	if common.Temperature != nil {
		m["temperature"] = *common.Temperature
	}
	if common.TopP != nil {
		m["top_p"] = *common.TopP
	}
	if common.MaxTokens != nil {
		m["max_tokens"] = *common.MaxTokens
	}
	if len(common.Stop) > 0 {
		m["stop"] = common.Stop
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// systemSegments collects the system-role input messages. eino carries the
// system prompt in the input array (acllm.FromSchema skips it), so it is
// recorded separately to keep the old "system" key recognizable.
func systemSegments(input []*schema.Message) []string {
	var out []string
	for _, m := range input {
		if m != nil && m.Role == schema.System {
			out = append(out, m.Content)
		}
	}
	return out
}
