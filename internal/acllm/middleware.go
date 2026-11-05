// The ChatModelAgent middlewares for kernel assembly (刀③ 中间件装配,
// docs/Eino深度接入方案-2026-11-05.md §3 挂点表 + §4-P1 第 5 条).
//
// Three collaborate around a shared DTO master; the ToolGate (toolgate.go) is
// the fourth and needs none of them:
//
//   - viewMiddleware  — the §3 compaction landing: before every model call it
//     runs Compactor.Pre on the DTO master (预算检查) and projects the master
//     into state.Messages (ContextView 等价: post-boundary working set →
//     MessagesForAPI → ToSchema, system message prepended); after every model
//     call it captures the assistant response back into the master + the
//     transcript recorder; WrapModel installs the MaxTokens cap and the
//     reactive-compaction retry (norma query.go:423-425: one forced AutoCompact
//     on a prompt-too-long failure, then retry the COMPACTED view — unlike the
//     4zrec reference, which retries the stale input array, this wrapper
//     re-projects from the master so the in-run retry actually sees the
//     smaller request, matching norma's `continue`). It covers the open-error
//     half only; pair NewReactiveRetryConfig with ChatModelAgentConfig.
//     ModelRetryConfig for the mid-stream half — both paths share this
//     middleware's one-shot gate, so one overflow episode recovers exactly
//     once whether the retry config is wired or not.
//   - injectionMiddleware — the §3 steer/聊天注入 landing
//     (BeforeModelRewriteState 改写 state.Messages): drains pending injections
//     (engine steer queue, chat follow-ups) and appends them to the master and
//     the projected view. Skill guidance messages (Result.Extra) do NOT go
//     through here — the gate's OnResult reports them to the host, which
//     appends them to the master; the projection then carries them after the
//     tool result, exactly like norma's execOne extras.
//   - deferredMiddleware — the §3/V5 deferred-tool landing: BeforeModelRewriteState
//     withholds locked deferred-tool schemas from state.ToolInfos (unlocked ones
//     are added back). The execution-time hard gate lives in the ToolGate
//     (SetDeferred) — V5 双保险.
//
// Ordering contract for the Handlers list (4zrec askernel/session.go:553-570):
// [viewMiddleware, injectionMiddleware, deferredMiddleware, gate]. BeforeModel
// hooks run in registration order (view projects, injection appends, deferred
// filters tools); WrapModel's first registration is outermost (the reactive
// retry must wrap the MaxTokens cap).
//
// The middlewares are constructed per runner run and must not be reused across
// runs. 4zrec reference: internal/kernel/askernel/middleware.go.
package acllm

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// promptState is the per-run bookkeeping shared between the view middleware and
// its wrappers: the token size the previous model response reported (the
// compactor's preferred gate count) and the turn counter.
type promptState struct {
	mu              sync.Mutex
	lastInputTokens int
	turns           int
}

func (ps *promptState) setInputTokens(n int) {
	ps.mu.Lock()
	ps.lastInputTokens = n
	ps.mu.Unlock()
}

func (ps *promptState) inputTokens() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.lastInputTokens
}

// messageStore is the DTO master — norma loop.messages 的 eino 侧等价物. Full
// history with boundary markers lives here; state.Messages is only the per-call
// projection. All writes copy-on-write under the lock, so a projection that
// took the slice before a concurrent append still sees a consistent prefix.
type messageStore struct {
	mu   sync.Mutex
	msgs []llm.Message
}

// Set replaces the master (resume seeding, reactive compaction result).
func (s *messageStore) Set(msgs []llm.Message) {
	s.mu.Lock()
	s.msgs = msgs
	s.mu.Unlock()
}

// Get returns the current master slice (write via the store methods).
func (s *messageStore) Get() []llm.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgs
}

// Append adds messages to the master's end (assistant capture, tool results via
// the gate's OnResult host wiring, injections, run-input seeding).
func (s *messageStore) Append(msgs ...llm.Message) {
	if len(msgs) == 0 {
		return
	}
	s.mu.Lock()
	s.msgs = append(s.msgs, msgs...)
	s.mu.Unlock()
}

// TranscriptRecorder is the transcript seam (norma harness.Recorder shape):
// message births in order plus compaction boundaries. norma transcript.Writer
// satisfies it structurally; nil = record nothing.
type TranscriptRecorder interface {
	RecordMessage(m llm.Message, usage llm.Usage)
	RecordBoundary(meta llm.BoundaryMeta)
}

// countBoundaryMarkers counts compact-boundary markers in the DTO
// (norma harness countBoundaries).
func countBoundaryMarkers(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		if llm.IsBoundaryMarker(m) {
			n++
		}
	}
	return n
}

// --- view middleware (compaction Pre/Reactive/ContextView + capture) ---

type viewMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	store     *messageStore
	ps        *promptState
	compactor *Compactor         // nil = compaction off (projection only)
	sysMsg    *schema.Message    // joined system prompt; nil when empty
	recorder  TranscriptRecorder // nil = record nothing
	maxTokens int                // 0 = no per-call output cap

	// reactive state: one reactive-compaction attempt per run, re-armed after
	// each successful model turn (norma hasAttemptedReactiveCompact).
	reactiveMu    sync.Mutex
	reactiveTried bool
}

// newViewMiddleware builds the projection/compaction/capture middleware over a
// shared master. system is the run's system-prompt segments (norma
// Options.SystemPrompt); the segments are joined with "\n\n" into one schema
// system message, mirroring how the norma providers concatenate the System
// slice onto the wire.
func newViewMiddleware(store *messageStore, ps *promptState, compactor *Compactor, system []string, maxTokens int, recorder TranscriptRecorder) *viewMiddleware {
	v := &viewMiddleware{store: store, ps: ps, compactor: compactor, maxTokens: maxTokens, recorder: recorder}
	if txt := joinSystemSegments(system); txt != "" {
		v.sysMsg = schema.SystemMessage(txt)
	}
	return v
}

// joinSystemSegments mirrors norma llm.joinSystem verbatim (provider.go:262):
// trim each segment, drop empties, join with "\n\n".
func joinSystemSegments(segments []string) string {
	parts := make([]string, 0, len(segments))
	for _, s := range segments {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n\n")
}

// project builds the request view: post-boundary working set → schema messages,
// system message prepended. This is the ContextView equivalent (norma
// harness/query.go:770-775 — the Compactor's ContextView, when implemented,
// replaces MessagesForAPI; this repo's compactor has none, so the default
// working set applies). Pure: the master is left untouched.
func (v *viewMiddleware) project() []*schema.Message {
	msgs := v.store.Get()
	apiView := llm.MessagesForAPI(msgs)
	projected := ToSchema(apiView)
	if v.sysMsg != nil {
		projected = append([]*schema.Message{v.sysMsg}, projected...)
	}
	return projected
}

// recordNewBoundary mirrors norma loop.recordNewBoundary (query.go:309): when
// compaction introduced a fresh boundary, record the boundary meta and every
// message from the boundary onward (marker + summary + kept tail), so a
// cold-start resume restores the compacted view.
func (v *viewMiddleware) recordNewBoundary(before int, dto []llm.Message) {
	if v.recorder == nil {
		return
	}
	if countBoundaryMarkers(dto) <= before {
		return
	}
	if i := llm.LastBoundaryIndex(dto); i >= 0 {
		if meta, ok := llm.ParseBoundaryMeta(dto[i]); ok {
			v.recorder.RecordBoundary(meta)
		}
		for _, m := range dto[i:] {
			v.recorder.RecordMessage(m, llm.Usage{})
		}
	}
}

// BeforeModelRewriteState: proactive compaction directly on the DTO master
// (non-destructive — boundary + summary inserted, full history retained),
// then the projection into state.Messages.
func (v *viewMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if v.compactor != nil {
		v.store.mu.Lock()
		before := countBoundaryMarkers(v.store.msgs)
		dto := v.compactor.Pre(ctx, v.store.msgs, v.ps.inputTokens())
		v.store.msgs = dto
		v.store.mu.Unlock()
		v.recordNewBoundary(before, dto)
	}
	state.Messages = v.project()
	return ctx, state, nil
}

// AfterModelRewriteState captures the assistant response into the DTO master +
// transcript synchronously with the graph — the projection of the NEXT model
// call must already see it. Also re-arms the reactive recovery (a successful
// model turn resets norma hasAttemptedReactiveCompact) and records the input
// size the model just reported (the compactor's preferred next-turn gate count).
func (v *viewMiddleware) AfterModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	v.reactiveMu.Lock()
	v.reactiveTried = false
	v.reactiveMu.Unlock()

	if len(state.Messages) == 0 {
		return ctx, state, nil
	}
	last := state.Messages[len(state.Messages)-1]
	if last == nil || last.Role != schema.Assistant {
		return ctx, state, nil
	}
	dtoMsgs := FromSchema([]*schema.Message{last})
	if len(dtoMsgs) == 0 {
		return ctx, state, nil
	}
	var u llm.Usage
	if last.ResponseMeta != nil && last.ResponseMeta.Usage != nil {
		u = UsageFromToken(last.ResponseMeta.Usage)
	}
	v.store.Append(dtoMsgs...)
	if v.recorder != nil {
		v.recorder.RecordMessage(dtoMsgs[0], u)
	}
	v.ps.setInputTokens(u.InputTokens + u.OutputTokens)
	return ctx, state, nil
}

// WrapModel installs the MaxTokens cap and the reactive-compaction retry.
// Registration order makes the reactive wrapper outermost (first registered is
// outermost), matching the recovery-before-cap shape.
func (v *viewMiddleware) WrapModel(ctx context.Context, m model.BaseModel[*schema.Message], mc *adk.ModelContext) (model.BaseModel[*schema.Message], error) {
	if v.maxTokens > 0 {
		m = &cappedModel{inner: m, maxTokens: v.maxTokens}
	}
	if v.compactor != nil {
		m = &reactiveModel{inner: m, v: v}
	}
	return m, nil
}

// cappedModel injects model.WithMaxTokens on every call (the ADK runner has no
// per-run output-cap option).
type cappedModel struct {
	inner     model.BaseModel[*schema.Message]
	maxTokens int
}

func (c *cappedModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return c.inner.Generate(ctx, input, append(opts, model.WithMaxTokens(c.maxTokens))...)
}

func (c *cappedModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return c.inner.Stream(ctx, input, append(opts, model.WithMaxTokens(c.maxTokens))...)
}

// reactiveModel implements the 413 recovery (norma query.go:423-425): on a
// prompt-too-long failure, force one Reactive AutoCompact over the master and
// retry ONCE — against the RE-PROJECTED view, not the stale input array, so
// the retry actually sends the smaller request the way norma's `continue`
// does. Exhausted recovery surfaces the overflow error to the agent (which the
// terminal-reason mapping, 刀④, classifies as ReasonPromptTooLong).
type reactiveModel struct {
	inner model.BaseModel[*schema.Message]
	v     *viewMiddleware
}

func (r *reactiveModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	msg, err := r.inner.Generate(ctx, input, opts...)
	if err == nil {
		return msg, nil
	}
	modified, retry := r.v.reactiveRecover(ctx, err)
	if !retry {
		return msg, err
	}
	return r.inner.Generate(ctx, modified, opts...)
}

func (r *reactiveModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	sr, err := r.inner.Stream(ctx, input, opts...)
	if err == nil {
		// 本 wrapper 只恢复 Stream 打开失败的溢出。流中途（Recv 阶段）冒出的
		// PTL 不在这里拦：拦截 reader 内换流重试会把已发出的部分 delta 与重试
		// 流拼接，污染装配消息（norma 历史只留成功整轮）。中途恢复的正解在
		// agent 装配层——NewReactiveRetryConfig 交给 ChatModelAgentConfig.
		// ModelRetryConfig（评审第 2 轮 #1 定案）：ADK 的 retry wrapper 整流
		// 体检后重开一轮，state 只 append 成功结果，宿主侧的「部分块+
		// WillRetryError+完整重试流」与 norma 中途重试的宿主级重复等价。
		return sr, nil
	}
	modified, retry := r.v.reactiveRecover(ctx, err)
	if !retry {
		return nil, err
	}
	return r.inner.Stream(ctx, modified, opts...)
}

// reactiveRecover runs one forced Reactive compaction when err is a
// prompt-too-long failure and no reactive attempt is in flight this run
// (norma hasAttemptedReactiveCompact, re-armed by AfterModelRewriteState on
// each successful model turn). On success it returns the re-projected request
// view over the compacted master — both the reactiveModel wrappers (open-error
// path) and NewReactiveRetryConfig's ShouldRetry (mid-stream path) share this
// single gate, so one overflow episode gets exactly one recovery.
func (v *viewMiddleware) reactiveRecover(ctx context.Context, err error) ([]*schema.Message, bool) {
	if !IsOverflow(err) {
		return nil, false
	}
	v.reactiveMu.Lock()
	if v.reactiveTried {
		v.reactiveMu.Unlock()
		return nil, false
	}
	v.reactiveTried = true
	v.reactiveMu.Unlock()

	msgs, shrank := v.compactor.Reactive(ctx, v.store.Get())
	if !shrank {
		return nil, false
	}
	// New boundary → record it with the post-boundary working set, exactly like
	// the proactive path (norma recordNewBoundary on the reactive branch).
	before := countBoundaryMarkers(v.store.Get())
	v.store.Set(msgs)
	v.recordNewBoundary(before, msgs)
	return v.project(), true
}

// NewReactiveRetryConfig builds the ChatModelAgentConfig.ModelRetryConfig that
// closes the mid-stream half of the reactive recovery (评审第 2 轮 #1):
// eino's retry wrapper consumes the whole attempt stream for inspection
// (chunks still flow to the event pump in real time), calls ShouldRetry with
// the partial concatenation + error, and on Retry re-opens the model with the
// modified input — norma query.go:421-425's `continue`, at the officially
// supported seam. Pair it with the viewMiddleware in the agent config:
//
//	cfg.ModelRetryConfig = acllm.NewReactiveRetryConfig(vm)
//
// Semantics, point by point against norma:
//   - MaxRetries 1 + the shared one-shot gate = one reactive attempt per
//     episode, re-armed after a successful model turn;
//   - ModifiedInputMessages = the compacted projection (norma: l.messages =
//     msgs; the retry call goes out against the smaller request);
//   - PersistModifiedInputMessages = norma's l.messages = msgs persisting the
//     boundary for subsequent turns (state management does not re-run for the
//     retry — the decision itself carries the new history);
//   - Backoff 0 = norma's immediate `continue`;
//   - non-overflow errors and exhausted recovery return nil (accept) so the
//     error surfaces for 刀④'s ReasonPromptTooLong mapping.
func NewReactiveRetryConfig(v *viewMiddleware) *adk.ModelRetryConfig {
	return &adk.ModelRetryConfig{
		MaxRetries: 1,
		BackoffFunc: func(context.Context, int) time.Duration {
			return 0 // norma continue: retry immediately, no backoff ladder
		},
		ShouldRetry: func(ctx context.Context, rc *adk.RetryContext) *adk.RetryDecision {
			if rc.Err == nil {
				return nil // successful output accepted as-is
			}
			modified, retry := v.reactiveRecover(ctx, rc.Err)
			if !retry {
				return nil // non-overflow, already recovered, or nothing shrank
			}
			return &adk.RetryDecision{
				Retry:                        true,
				ModifiedInputMessages:        modified,
				PersistModifiedInputMessages: true,
			}
		},
	}
}

// --- injection middleware (steer / 聊天注入) ---

// InjectionSource drains pending injections for this round — engine steer
// queue (e.drainSteer), chat follow-up nudges, and the like. Return nil when
// nothing is pending. Called once per model call, before the projection delta
// is applied; implementations must be goroutine-safe (the agent loop is
// single-goroutine, but the queue writer is not).
type InjectionSource func(ctx context.Context) []llm.Message

type injectionMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	store   *messageStore
	sources []InjectionSource
}

// newInjectionMiddleware drains the given sources before each model call and
// appends the returned messages to the DTO master AND the projected view.
// Appending to the master keeps injections persistent like norma's
// (steer/聊天注入 live in loop.messages), so subsequent projections and
// compaction boundaries carry them.
func newInjectionMiddleware(store *messageStore, sources ...InjectionSource) *injectionMiddleware {
	return &injectionMiddleware{store: store, sources: sources}
}

func (m *injectionMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	var inject []llm.Message
	for _, src := range m.sources {
		if msgs := src(ctx); len(msgs) > 0 {
			inject = append(inject, msgs...)
		}
	}
	if len(inject) == 0 {
		return ctx, state, nil
	}
	m.store.Append(inject...)
	state.Messages = append(state.Messages, ToSchema(inject)...)
	return ctx, state, nil
}

// --- deferred middleware (V5: schema withholding, per-round) ---

type deferredMiddleware struct {
	adk.TypedBaseChatModelAgentMiddleware[*schema.Message]

	infos    []*schema.ToolInfo // all registry tool infos, registry order
	deferred map[string]bool
	unlock   *actoolUnlockSet
}

// actoolUnlockSet aliases the norma UnlockSet type so the middleware reads like
// 4zrec's (tools.UnlockSet) without importing more than acllm already does.
type actoolUnlockSet = actool.UnlockSet

// newDeferredMiddleware withholds locked deferred-tool schemas from the model's
// tool list; unlocked deferred tools are added back (V5 定案 — per-round
// filtering, unlike norma's run-start static filter: a skill unlock mid-run
// surfaces the tool schema on the next round). The access tools
// (SearchExtraTools/ExecuteExtraTool) are never deferred and always stay.
// The execution-time hard gate lives in the ToolGate (SetDeferred) — 双保险.
func newDeferredMiddleware(infos []*schema.ToolInfo, deferred []string, unlock *actoolUnlockSet) *deferredMiddleware {
	set := make(map[string]bool, len(deferred))
	for _, n := range deferred {
		set[n] = true
	}
	return &deferredMiddleware{infos: infos, deferred: set, unlock: unlock}
}

func (d *deferredMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, mc *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if len(d.deferred) == 0 {
		return ctx, state, nil
	}
	out := make([]*schema.ToolInfo, 0, len(d.infos))
	for _, ti := range d.infos {
		if d.deferred[ti.Name] && d.unlock != nil && !d.unlock.Has(ti.Name) {
			continue
		}
		out = append(out, ti)
	}
	state.ToolInfos = out
	return ctx, state, nil
}
