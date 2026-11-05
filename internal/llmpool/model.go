// model.go is the eino-side half of the failover pool (方案 §4-P1 第 3 条): a
// model.ToolCallingChatModel decorator with the same 轮询/熔断 semantics the
// norma-side Pool (pool.go) has always provided, so the P1 kernel can keep the
// failover chain when the loop switches over.
//
// Shadow-run status (刀①): the norma loop still consumes pool.go's llm.Provider
// Pool; nothing in it calls anything here. The two halves share Registry /
// RankActive / ErrExhausted / trimErr, but each keeps its own status extraction
// and failover classification — pool.go's byte-for-byte, and a wider string
// match here (the eino-ext adapters format statuses as "status code: NNN", which
// the narrow norma regex misses). Ported from the verified 4zrec implementation
// (internal/platform/llm/llmpool/pool.go).
package llmpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"sync/atomic"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// ModelMember is one LLM profile in the chain, already built into an eino chat
// model (wrapped with recording by the caller, so a failed attempt is still
// recorded under its own profile name).
type ModelMember struct {
	ID       int64  // llm_profiles.id
	Name     string // profile name, for logs / UI
	Model    string
	Format   string // "anthropic" | "openai" | "openai-responses"
	Priority int    // the profile's configured priority (display only)
	Active   bool   // is_default (display only)
	// Rank is the ordering key the caller assigned: higher goes first, and members
	// sharing a Rank take turns leading (load-spreading across duplicate keys).
	// The caller encodes "active profile heads the chain" as a Rank above every
	// user-settable priority, so this type needs no policy of its own.
	Rank int
	// WindowTokens is the profile's context window in tokens. A member whose
	// window can't hold the request is skipped rather than made to fail on it.
	WindowTokens int
	Prov         model.ToolCallingChatModel
}

// ModelPool is a model.ToolCallingChatModel that fails over across an ordered
// chain of members. It is safe for concurrent use: members are immutable after
// construction and all mutable state lives in the shared Registry.
type ModelPool struct {
	members []*ModelMember // in chain order (active first, then priority DESC)
	health  *Registry
	rr      atomic.Uint64 // rotates the starting point within an equal-priority group
}

// NewModelPool builds a ModelPool over members (already in chain order). Returns
// nil when the chain is empty. A single-member chain is still a valid pool — it
// just behaves exactly like the bare model.
func NewModelPool(members []*ModelMember, health *Registry) *ModelPool {
	if len(members) == 0 {
		return nil
	}
	if health == nil {
		health = NewRegistry(nil, nil)
	}
	return &ModelPool{members: members, health: health}
}

// Members returns the chain in order (read-only).
func (p *ModelPool) Members() []*ModelMember { return p.members }

// Head returns the first member of the chain.
func (p *ModelPool) Head() *ModelMember { return p.members[0] }

// boundModelPool is the WithTools view of a ModelPool: the same chain, health
// registry and rotation, but every attempt lazily binds the tool set to the
// member's model (member.Prov.WithTools) right before calling it. The original
// pool and its members are never mutated, so unbound callers share the base
// models.
type boundModelPool struct {
	p     *ModelPool
	tools []*schema.ToolInfo
}

func (b *boundModelPool) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return b.p.generate(ctx, input, b.tools, opts...)
}

func (b *boundModelPool) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return b.p.stream(ctx, input, b.tools, opts...)
}

func (b *boundModelPool) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	bp := *b
	bp.tools = tools
	return &bp, nil
}

// WithTools implements model.ToolCallingChatModel by returning a pool view whose
// members bind the tool set lazily (at call time, per attempt). The receiver is
// not mutated — the base models stay shared with unbound callers.
func (p *ModelPool) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return &boundModelPool{p: p, tools: tools}, nil
}

// Compile-time proof that a ModelPool is usable directly as a chat model.
var _ model.ToolCallingChatModel = (*ModelPool)(nil)

// Generate implements model.ToolCallingChatModel with failover.
//
// A non-streaming request is atomic — it never delivers partial output — so
// every failover-eligible failure lands in the safe window and the next member
// can be tried without risk of duplicated output. Mirrors Stream's
// health-tripping and chain-exhaustion behavior.
func (p *ModelPool) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return p.generate(ctx, input, nil, opts...)
}

func (p *ModelPool) generate(ctx context.Context, input []*schema.Message, tools []*schema.ToolInfo, opts ...model.Option) (*schema.Message, error) {
	order := p.order(input, tools)
	var lastErr error
	for i, m := range order {
		prov, err := provOf(m, tools)
		if err != nil {
			// Tool binding is a local, client-side step: nothing was sent, so
			// moving on to the next member is always safe (but health is not
			// tripped — it says nothing about the provider's state).
			log.Printf("[llmpool] 配置 %q(%s) 工具绑定失败：%s", m.Name, m.Model, trimErr(err))
			lastErr = err
			continue
		}
		msg, err := prov.Generate(ctx, input, opts...)
		if err == nil {
			p.health.Pass(m.ID)
			return msg, nil
		}
		if !modelShouldFailover(ctx, err) {
			// Non-failover error (e.g. ctx cancel, deterministic 4xx): surface
			// as-is without tripping health, matching Stream's non-failover path.
			p.health.Pass(m.ID)
			return nil, err
		}
		lastErr = p.fail(m, err, order, i)
	}
	return nil, exhausted(lastErr, len(order))
}

// Stream implements model.ToolCallingChatModel with failover.
//
// The one hard rule: a member may only be abandoned BEFORE it has yielded any
// output. Once text, reasoning or a tool call has reached the caller, re-sending
// the same request to another model would duplicate output and corrupt the
// conversation history — so a mid-stream failure is surfaced as-is and left to
// the agent harness's resume logic. Fortunately the failures this exists for
// (402 no credit, 401 bad key, 429, 5xx) all surface during request
// establishment, before the body is read, so they always land in the safe window.
//
// Under eino the establishment phase is everything up to the first COMMITTING
// chunk (MessageCommitsOutput): the Stream() call itself failing, and a
// StreamReader whose first Recv errors (a gateway that returned 200 then dropped)
// are both still pre-commit — the member is abandoned and the next one tried.
// Non-committing chunks seen before the first committing one (empty keep-alives,
// usage-only frames) are buffered and replayed ahead of it, so the caller sees
// the winning member's chunks in order and nothing from the abandoned ones.
func (p *ModelPool) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return p.stream(ctx, input, nil, opts...)
}

func (p *ModelPool) stream(ctx context.Context, input []*schema.Message, tools []*schema.ToolInfo, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	order := p.order(input, tools)
	var lastErr error
	for i, m := range order {
		prov, err := provOf(m, tools)
		if err != nil {
			// Local tool-binding failure, nothing sent: try the next member
			// (health is not tripped — it says nothing about the provider).
			log.Printf("[llmpool] 配置 %q(%s) 工具绑定失败：%s", m.Name, m.Model, trimErr(err))
			lastErr = err
			continue
		}
		sr, serr := prov.Stream(ctx, input, opts...)
		if serr != nil {
			if !modelShouldFailover(ctx, serr) {
				return nil, serr // ctx cancel / 400: surface as-is
			}
			lastErr = p.fail(m, serr, order, i)
			continue
		}
		out, eerr := p.establish(ctx, m, sr)
		if eerr == nil {
			return out, nil // committed: this member serves the caller
		}
		if !eerr.failover {
			return nil, eerr.err // ctx cancel / 400 mid-establishment
		}
		lastErr = p.fail(m, eerr.err, order, i)
	}
	return nil, exhausted(lastErr, len(order))
}

// establishmentError carries the outcome of one member's establishment phase.
type establishmentError struct {
	err      error
	failover bool // true = eligible to try the next member
}

// establish drains the safe window of a member whose Stream() already succeeded:
// buffer non-committing chunks until one commits output (→ committed, replay
// reader) or the member fails pre-commit (→ failover decision). Committing is
// terminal: from here the member is served to the caller no matter what.
func (p *ModelPool) establish(ctx context.Context, m *ModelMember, sr *schema.StreamReader[*schema.Message]) (*schema.StreamReader[*schema.Message], *establishmentError) {
	var pending []*schema.Message
	for {
		chunk, err := sr.Recv()
		if err == nil {
			if MessageCommitsOutput(chunk) {
				return replay(chunk, pending, sr, m, p.health), nil
			}
			pending = append(pending, chunk)
			continue
		}
		sr.Close()
		if errors.Is(err, io.EOF) {
			// Clean completion before any committing chunk: not a failure — the
			// member served an empty (usage-only) reply. Flush what it did send.
			p.health.Pass(m.ID)
			return schema.StreamReaderFromArray(pending), nil
		}
		if !modelShouldFailover(ctx, err) {
			return nil, &establishmentError{err: err} // ctx cancel / 400
		}
		return nil, &establishmentError{err: err, failover: true}
	}
}

// fail records a member's failure: trips the circuit breaker (logging the trip
// once) and logs the failover hop. Returns the error unchanged for chaining.
func (p *ModelPool) fail(m *ModelMember, err error, order []*ModelMember, i int) error {
	hard := modelIsHardFailure(err)
	if p.health.Trip(m.ID, trimErr(err), hard) {
		log.Printf("[llmpool] 配置 %q(%s) 已熔断：%s", m.Name, m.Model, trimErr(err))
	}
	p.logFailover(order, i, err)
	return err
}

// logFailover emits the hop to the next member (or notes the chain end).
func (p *ModelPool) logFailover(order []*ModelMember, i int, cause error) {
	if i+1 >= len(order) {
		return
	}
	n := order[i+1]
	reason := "无"
	if cause != nil {
		reason = trimErr(cause)
	}
	log.Printf("[llmpool] LLM 故障转移：%q(%s) → %q(%s)，原因：%s",
		order[i].Name, order[i].Model, n.Name, n.Model, reason)
}

// exhausted builds the chain-exhausted error the caller sees when every member
// failed.
func exhausted(lastErr error, n int) error {
	if lastErr == nil {
		lastErr = ErrExhausted
	}
	log.Printf("[llmpool] 轮询链已耗尽(%d 个配置全部失败)，最后错误：%s", n, trimErr(lastErr))
	return fmt.Errorf("%w：%v", ErrExhausted, lastErr)
}

// provOf returns the member's model with the view's tool set bound to it. The
// binding is deliberately per attempt (lazy): member models are shared across
// pools and callers, so WithTools must never mutate them in place.
func provOf(m *ModelMember, tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	if len(tools) == 0 {
		return m.Prov, nil
	}
	return m.Prov.WithTools(tools)
}

// replay hands the committed member's stream to the caller: the buffered
// pre-commit chunks and the committing chunk first (buffer-and-prepend), then
// everything the member still produces. A failure after this point is a
// mid-stream failure and surfaces as-is — it is never failed over. Completion
// (clean EOF) clears the member's breaker counters; an abandoned reader or a
// mid-stream failure records neither a pass nor a trip, matching the historical
// behavior for output the caller has already seen.
func replay(first *schema.Message, pending []*schema.Message, rest *schema.StreamReader[*schema.Message], m *ModelMember, health *Registry) *schema.StreamReader[*schema.Message] {
	out, sw := schema.Pipe[*schema.Message](len(pending) + 1 + 8)
	out.SetAutomaticClose() // an abandoned reader must not leak the pump goroutine
	go func() {
		defer sw.Close()
		defer rest.Close()
		for _, c := range pending {
			if sw.Send(c, nil) {
				return // caller stopped consuming
			}
		}
		if sw.Send(first, nil) {
			return
		}
		for {
			chunk, err := rest.Recv()
			if err == nil {
				if sw.Send(chunk, nil) {
					return
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				health.Pass(m.ID) // completed cleanly
				return
			}
			sw.Send(nil, err) // mid-stream failure: surfaced as-is
			return
		}
	}()
	return out
}

// MessageCommitsOutput is the "event commits output" predicate over eino stream
// chunks: a chunk commits the member's output when it carries anything the
// caller must not receive twice — visible text, reasoning ("thinking") text, or
// a tool call. Usage-only and empty bookkeeping chunks do NOT commit. The pool's
// safe-window probe and (in a later cut) the task router's pre-commit buffering
// need the exact same definition, so it lives on the shared failover layer.
func MessageCommitsOutput(chunk *schema.Message) bool {
	if chunk == nil {
		return false
	}
	return chunk.Content != "" ||
		chunk.ReasoningContent != "" ||
		len(chunk.ToolCalls) > 0 ||
		len(chunk.MultiContent) > 0 ||
		len(chunk.AssistantGenMultiContent) > 0
}

// StatusOf returns the HTTP status carried by err, or 0 if it isn't one.
//
// The string shapes in the eino stack: the eino-ext adapters produce "status
// 402" and the openai client's "error, status code: 402, …"; some gateways
// surface "http status: NNN" prose. The pattern deliberately matches all of
// them. (No typed error exists yet — a self-built provider will add one when a
// later cut ports it; StatusOf gains an errors.As branch then.)
func StatusOf(err error) int {
	m := modelStatusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	code, _ := strconv.Atoi(m[1])
	return code
}

// modelStatusRe pulls the HTTP status out of an error's text. The SDKs expose no
// common typed error, so the string is the portable fallback. Kept separate from
// pool.go's statusRe (norma-side): norma error prose is always "status NNN", so
// the narrow pattern is correct there, while the eino adapters need the wider
// one. Sharing would silently change the norma path's classification.
var modelStatusRe = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(\d{3})`)

// modelShouldFailover reports whether err justifies trying the next profile.
//
// Never fails over on context cancellation — that's the user stopping a task or a
// task-level timeout, and burning a backup key on it would both waste credit and
// pollute the run's termination diagnosis. Never on 400 either: a malformed or
// over-long request fails identically everywhere.
//
// Semantically identical to pool.go's shouldFailover; only the status extraction
// differs (StatusOf's wider string match).
func modelShouldFailover(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch code := StatusOf(err); {
	case code == 0:
		return true // no status → transport-level failure (reset / DNS / timeout)
	case code == 400:
		return false // bad or over-long request: identical everywhere
	case code == 401, code == 402, code == 403, code == 404, code == 408, code == 429:
		return true
	case code >= 500:
		return true
	}
	return false
}

// modelIsHardFailure reports whether the failure is deterministic (the profile
// will keep failing until a human fixes it) rather than transient. Hard failures
// open the breaker on the first occurrence.
func modelIsHardFailure(err error) bool {
	switch StatusOf(err) {
	case 401, 402, 403, 404:
		return true
	}
	return false
}

// estimateModelTokens roughly sizes a request so members whose context window
// clearly can't hold it are skipped. Deliberately crude and biased to
// over-estimate slightly; it only needs to tell "fits" from "nowhere near".
// CJK-aware: Chinese text (this product's dominant prompt language) carries
// ~1.5 tokens per character, far denser than ASCII — a plain bytes/3.5 count
// under-estimates it ~1.75x and would route over-long requests to members that
// then fail with a non-failover 400.
//
// All accumulation happens in token units scaled ×14 (see tokenWeight); the
// single division at the end rounds up, so many small strings cannot each
// truncate their way to a low total.
func estimateModelTokens(input []*schema.Message, tools []*schema.ToolInfo) int {
	n := 0
	for _, m := range input {
		if m == nil {
			continue
		}
		n += tokenWeight(m.Content) + tokenWeight(m.ReasoningContent)
		for _, part := range m.MultiContent {
			n += tokenWeight(part.Text)
		}
		for _, tc := range m.ToolCalls {
			n += tokenWeight(tc.Function.Name) + tokenWeight(tc.Function.Arguments)
		}
	}
	for _, t := range tools {
		if t == nil {
			continue
		}
		// InputSchema is a decoded schema tree, so its serialized size isn't
		// available cheaply — charge a flat ~120 ASCII chars per top-level
		// property instead (the JSON-schema form is what the adapters send;
		// schema JSON is ASCII-dominant, so the ASCII rate applies: 120 chars
		// ×4 units = 480).
		props := 0
		if t.ParamsOneOf != nil {
			if js, err := t.ParamsOneOf.ToJSONSchema(); err == nil && js != nil && js.Properties != nil {
				props = js.Properties.Len()
			}
		}
		n += tokenWeight(t.Name) + tokenWeight(t.Desc) + props*480
	}
	return (n + 13) / 14
}

// tokenWeight estimates the tokens in s, scaled ×14 so per-string integer math
// never truncates to zero: ASCII at ~3.5 bytes per token (English + JSON
// syntax) → 4 units per byte, non-ASCII runes — CJK-dominant here — at ~1.5
// tokens per character → 21 units per rune. rune iteration keeps each
// multibyte character one unit instead of 3 bytes.
func tokenWeight(s string) int {
	units := 0
	for _, r := range s {
		if r < 128 {
			units += 4
		} else {
			units += 21
		}
	}
	return units
}

// order picks the members to try, in order: skip those in a cooling-off window
// and those whose context window can't hold this request, then rotate within each
// equal-priority group so same-priority profiles share the load. Never returns an
// empty slice — if everything is filtered out, the head of the chain is tried
// anyway, since stalling the engine is worse than one more failed request.
func (p *ModelPool) order(input []*schema.Message, tools []*schema.ToolInfo) []*ModelMember {
	est := estimateModelTokens(input, tools)
	var open []*ModelMember
	for _, m := range p.members {
		if p.health.IsOpen(m.ID) {
			continue
		}
		if m.WindowTokens > 0 && est > m.WindowTokens {
			continue // would 400 on length — not a useful failover target
		}
		open = append(open, m)
	}
	if len(open) == 0 {
		return p.members[:1] // last resort: probe the head rather than stall
	}
	return rotateModelGroups(open, p.rr.Add(1)-1)
}

// rotateModelGroups rotates each run of equal-ranked members by n, so profiles
// sharing a priority take turns going first (free load-spreading across
// duplicate keys). The chain head has its own Rank and always stays at the
// front. (Pool.rotateGroups twin — the member types differ.)
func rotateModelGroups(in []*ModelMember, n uint64) []*ModelMember {
	out := make([]*ModelMember, 0, len(in))
	for i := 0; i < len(in); {
		j := i + 1
		for j < len(in) && in[j].Rank == in[i].Rank {
			j++
		}
		g := in[i:j]
		if len(g) > 1 {
			off := int(n % uint64(len(g)))
			for k := range g {
				out = append(out, g[(k+off)%len(g)])
			}
		} else {
			out = append(out, g...)
		}
		i = j
	}
	return out
}
