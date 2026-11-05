// Context compaction, ported verbatim from norma/compaction
// (docs/Eino深度接入方案-2026-11-05.md §2.1.2 / §3 挂点表 / §4-P1 第 5 条; 4zrec
// V6 定案: 自研中间件, 不用 eino summarization).
//
// The three mechanisms keep their norma judgment criteria byte-for-byte — the
// port IS the norma implementation re-homed, operating on the same DTO
// vocabulary (norma llm.Message) the conversion layer already uses:
//
//   - MicroCompact — clear stale COMPACTABLE tool-result bodies (non-destructive:
//     the result can be re-read). Keeps the most recent N compactable results and
//     clears the rest.
//   - AutoCompact  — summarize the working head behind a compact boundary at the
//     token threshold (or predictively). Non-destructive: the full history is
//     retained in the message array; only messages after the last boundary are
//     sent to the model (llm.MessagesForAPI).
//   - Reactive     — on a prompt-too-long (413) error, force one AutoCompact and
//     retry. It reuses AutoCompact; it is not a separate algorithm.
//
// The eino-side landing of the three harness call points (norma
// harness/query.go:407 Pre, :423-425 Reactive, :770-775 ContextView) is the
// middleware in middleware.go; this file only owns the algorithm.
//
// NewModelSummarizer is the summarizer seam for that middleware — 4zrec's
// verified port of norma's ProviderSummarizer onto an eino model
// (internal/kernel/compaction/summarizer.go): same PTL-truncation and transient
// retry ladder, same prompts and post-processing, replayed through
// acllm.ToSchema. One norma behavior is unreachable at this seam: norma's
// per-request Thinking:"disabled" override — eino models carry thinking config
// at construction time, so the host must build the summarizer model with
// thinking off (4zrec ships the same note).
//
// A differential test (compaction_test.go) runs this port against the norma
// package over identical scenarios and asserts identical outputs — the proof
// that the judgment criteria survived the move. When norma is deleted (P4),
// this file and the boundary/skillmsg helpers it calls must stay (re-owned
// into acllm, 4zrec's boundary.go/skillmsg.go precedent).
package acllm

import (
	"context"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/llm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// Summarizer condenses messages into a digest. Injected so the host controls
// which model summarizes (and so tests can mock).
type Summarizer func(ctx context.Context, msgs []llm.Message) (string, error)

// Config tunes the compactor.
type CompactionConfig struct {
	// ContextWindow is the model's total context window in tokens (default 200000).
	ContextWindow int
	// MaxOutputTokens is the model's max output capability; the summary reservation
	// is min(MaxOutputTokens, 20000) (default 8000).
	MaxOutputTokens int
	// KeepRecent is the number of recent messages AutoCompact always preserves as
	// the un-summarized tail (default 8). MicroCompact uses its own microKeepRecent.
	KeepRecent int
}

func (c *CompactionConfig) defaults() {
	if c.ContextWindow == 0 {
		c.ContextWindow = 200000
	}
	if c.MaxOutputTokens == 0 {
		c.MaxOutputTokens = 8000
	}
	if c.KeepRecent == 0 {
		c.KeepRecent = 8
	}
}

// compactableTools — tools whose results MicroCompact may clear. Mirrors
// claude-code COMPACTABLE_TOOLS (file read, shell, grep/glob, web, edit/write);
// deliberately excludes LS/MultiEdit/NotebookEdit.
var compactableTools = map[string]bool{
	"Read": true, "Bash": true, "Grep": true, "Glob": true,
	"WebFetch": true, "WebSearch": true, "Edit": true, "Write": true,
}

const (
	microClearedMessage   = "[Old tool result content cleared]" // == claude-code TIME_BASED_MC_CLEARED_MESSAGE
	microKeepRecent       = 5                                   // == claude-code KEEP_RECENT (compactable results kept)
	toolResultGrowthGuess = 15000                               // == claude-code TOOL_RESULT_GROWTH_ESTIMATE
	maxAutoCompactFails   = 3                                   // == claude-code MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES
)

// Compactor applies the strategy. Construct with NewCompactor.
type Compactor struct {
	cfg       CompactionConfig
	summarize Summarizer
	failures  int
	tripped   bool
}

// NewCompactor builds a Compactor. summarize may be nil to disable AutoCompact.
func NewCompactor(cfg CompactionConfig, summarize Summarizer) *Compactor {
	cfg.defaults()
	return &Compactor{cfg: cfg, summarize: summarize}
}

// --- threshold math ---

// reservedForSummary is min(model max output, 20000). MaxOutputTokens stands in
// for the model's output capability; 0 (unset) reserves the full 20000.
func (c *Compactor) reservedForSummary() int {
	r := c.cfg.MaxOutputTokens
	if r > 20000 || r == 0 {
		r = 20000
	}
	return r
}
func (c *Compactor) effectiveWindow() int { return c.cfg.ContextWindow - c.reservedForSummary() }

// buffer tiers off the EFFECTIVE window (== claude-code getAutocompactBufferTokens).
func (c *Compactor) buffer() int {
	switch ew := c.effectiveWindow(); {
	case ew >= 800000:
		return 50000
	case ew >= 400000:
		return 30000
	default:
		return 13000
	}
}
func (c *Compactor) autoThreshold() int  { return c.effectiveWindow() - c.buffer() }
func (c *Compactor) microThreshold() int { return c.effectiveWindow() * 6 / 10 }

// maxTurnGrowth == claude-code estimateMaxTurnGrowth: min(maxOutput,20000)+15000.
func (c *Compactor) maxTurnGrowth() int { return c.reservedForSummary() + toolResultGrowthGuess }
func (c *Compactor) predictiveOver(tok int) bool {
	return tok+c.maxTurnGrowth() > c.effectiveWindow()
}

// count returns the token count of the API view (post-boundary). When
// lastInputTokens > 0 (the total token size the previous model response
// reported), it is preferred over local estimation — mirroring claude-code's
// tokenCountWithEstimation. After a working-set mutation, callers pass 0 to force
// a fresh per-block estimate.
func (c *Compactor) count(msgs []llm.Message, lastInputTokens int) int {
	if lastInputTokens > 0 {
		return lastInputTokens
	}
	return EstimateTokens(llm.MessagesForAPI(msgs)) * 4 / 3
}

// EstimateTokens approximates the token footprint of messages (~4 chars/token),
// counting each block by type (text, thinking text, tool_use name+input, and
// nested tool_result content). Mirrors claude-code roughTokenCountEstimation
// (without the 4/3 scale, which count applies).
func EstimateTokens(msgs []llm.Message) int {
	chars := 0
	for _, m := range msgs {
		for _, b := range m.Content {
			chars += blockChars(b)
		}
	}
	return chars / 4
}

// blockChars is the per-block character footprint. A Norma ContentBlock has no
// image/document type; if one is added, its fixed 2000-token cost (claude-code
// IMAGE_MAX_TOKEN_SIZE) would be added here.
func blockChars(b llm.ContentBlock) int {
	switch b.Type {
	case llm.BlockText:
		return len(b.Text)
	case llm.BlockThinking:
		return len(b.Thinking)
	case llm.BlockToolUse:
		return len(b.Name) + len(b.Input)
	case llm.BlockToolResult:
		n := 0
		for _, cb := range b.Content {
			n += blockChars(cb)
		}
		return n
	default:
		return len(b.Text)
	}
}

// Pre conditions the history before a model request: MicroCompact to clear stale
// tool results, then AutoCompact at the threshold (or predictively). Both are
// non-destructive. lastInputTokens is the previous response's total token size
// (0 if none yet), used as the initial gate count.
func (c *Compactor) Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message {
	if c.cfg.ContextWindow <= 0 {
		return msgs
	}
	tok := c.count(msgs, lastInputTokens)
	if tok <= c.microThreshold() {
		return msgs
	}
	// MicroCompact: clear old COMPACTABLE tool results (non-destructive). Only
	// re-estimate when it actually changed the array; otherwise the gate count
	// (which prefers the accurate last-response size) still holds.
	if out, changed := c.microCompact(msgs); changed {
		msgs = out
		tok = c.count(msgs, 0)
	}
	// AutoCompact: at the threshold, or predictively if the next turn would overflow.
	if tok >= c.autoThreshold() || c.predictiveOver(tok) {
		if out, ok := c.autoCompact(ctx, msgs, tok, "auto"); ok {
			msgs = out
		}
	}
	return msgs
}

// Reactive force-compacts after a prompt-too-long error by running one
// AutoCompact (mirrors claude-code tryReactiveCompact, which only summarizes —
// no micro/collapse/snip cascade). Returns whether the API view shrank.
func (c *Compactor) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	before := c.count(msgs, 0)
	if out, ok := c.autoCompact(ctx, msgs, before, "reactive"); ok {
		return out, c.count(out, 0) < before
	}
	return msgs, false
}

// IsOverflow is the method form.
func (c *Compactor) IsOverflow(err error) bool { return IsOverflow(err) }

// IsOverflow reports whether err is a context-length / prompt-too-long failure.
func IsOverflow(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "too long") || strings.Contains(s, "context length") ||
		strings.Contains(s, "context_length") || strings.Contains(s, "maximum context") ||
		strings.Contains(s, "status 413")
}

// --- working-set geometry ---

// workingBounds returns [start, tailStart): start is just after the last
// boundary marker (0 if none); tailStart is where the preserved recent tail
// begins. Messages in [start, tailStart) are eligible for summary.
func (c *Compactor) workingBounds(msgs []llm.Message) (start, tailStart int) {
	start = llm.LastBoundaryIndex(msgs) + 1
	tailStart = max(lastNNonMarkerStart(msgs, c.cfg.KeepRecent), start)
	return
}

func lastNNonMarkerStart(msgs []llm.Message, keep int) int {
	count, i := 0, len(msgs)
	for i > 0 && count < keep {
		i--
		if !llm.IsBoundaryMarker(msgs[i]) {
			count++
		}
	}
	return i
}

// --- MicroCompact: keep the most recent N compactable results, clear the rest ---

// microCompact clears the bodies of all COMPACTABLE tool results except the most
// recent microKeepRecent, returning the (possibly new) message slice and whether
// anything changed. It is non-destructive: a cleared result can be re-read.
func (c *Compactor) microCompact(msgs []llm.Message) ([]llm.Message, bool) {
	// Collect compactable tool_use ids in encounter order.
	var ids []string
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolUse && compactableTools[b.Name] {
				ids = append(ids, b.ID)
			}
		}
	}
	if len(ids) <= microKeepRecent {
		return msgs, false // nothing old enough to clear
	}
	clearSet := make(map[string]bool, len(ids)-microKeepRecent)
	for _, id := range ids[:len(ids)-microKeepRecent] {
		clearSet[id] = true
	}
	changed := false
	out := append([]llm.Message(nil), msgs...)
	for i := range out {
		var nc []llm.ContentBlock
		for j, b := range out[i].Content {
			if b.Type == llm.BlockToolResult && clearSet[b.ToolUseID] && !isCleared(b.Content) {
				if nc == nil {
					nc = append([]llm.ContentBlock(nil), out[i].Content...)
				}
				nc[j].Content = []llm.ContentBlock{llm.TextBlock(microClearedMessage)}
				changed = true
			}
		}
		if nc != nil {
			out[i].Content = nc
		}
	}
	if !changed {
		return msgs, false
	}
	return out, true
}

func isCleared(blocks []llm.ContentBlock) bool {
	return len(blocks) == 1 && blocks[0].Type == llm.BlockText && blocks[0].Text == microClearedMessage
}

// --- AutoCompact: non-destructive boundary + summary ---

func (c *Compactor) autoCompact(ctx context.Context, msgs []llm.Message, preTok int, trigger string) ([]llm.Message, bool) {
	if c.summarize == nil || c.tripped {
		return msgs, false
	}
	start, tailStart := c.workingBounds(msgs)
	if tailStart <= start {
		return msgs, false
	}
	toSummarize := contentOnly(msgs[start:tailStart])
	if len(toSummarize) == 0 {
		return msgs, false
	}
	summary, err := c.summarize(ctx, toSummarize)
	if err != nil {
		c.failures++
		if c.failures >= maxAutoCompactFails {
			c.tripped = true
		}
		return msgs, false
	}
	c.failures = 0

	// Skill instructions in the summarized head are lossy in the prose summary, so
	// re-inject the latest invocation of each skill verbatim just after the summary
	// (post-boundary → sent to the model). Retained history keeps the originals; we
	// only re-surface skills that fell behind the new boundary.
	reinjected := reinjectSkills(msgs, tailStart)
	boundary := llm.BoundaryMessage(llm.BoundaryMeta{
		Trigger:            trigger,
		PreTokens:          preTok,
		MessagesSummarized: len(toSummarize),
		ActiveSkills:       skillNames(reinjected),
	})
	summaryMsg := llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
		llm.TextBlock(compactContinuationPreamble + summary),
	}}
	// Retain everything before tailStart (non-destructive); insert the new
	// boundary + summary (+ re-injected skills) just before the preserved recent tail.
	out := make([]llm.Message, 0, len(msgs)+2+len(reinjected))
	out = append(out, msgs[:tailStart]...)
	out = append(out, boundary, summaryMsg)
	out = append(out, reinjected...)
	out = append(out, msgs[tailStart:]...)
	return out, true
}

// compactContinuationPreamble prefixes the inserted summary message, mirroring
// claude-code getCompactUserSummaryMessage. formatCompactSummary already prefixes
// the digest with "Summary:\n".
const compactContinuationPreamble = "This session is being continued from a previous conversation that ran out of context. The conversation is summarized below:\n\n"

// Skill re-injection budget: per-skill and total token caps for verbatim skill
// instructions re-surfaced after a compaction boundary (mirrors claude-code's
// 5K/25K policy). Most-recently-invoked skills win when the total is exceeded.
const (
	maxSkillReinjectTokens      = 5000
	maxSkillReinjectTotalTokens = 25000
)

// skillNames returns the invoked-skill names of the given re-injected messages.
func skillNames(msgs []llm.Message) []string {
	var out []string
	for _, m := range msgs {
		if name, ok := llm.SkillInvocationName(m); ok {
			out = append(out, name)
		}
	}
	return out
}

// reinjectSkills finds the latest invocation of each skill in the history behind
// the new boundary (msgs[:tailStart]) and returns copies to place after the
// summary, newest-first under budget, restored to chronological order. A skill
// whose latest invocation is already in the preserved tail (index >= tailStart)
// is skipped — it is still in the model's view.
func reinjectSkills(msgs []llm.Message, tailStart int) []llm.Message {
	type entry struct {
		msg llm.Message
		idx int
	}
	latest := map[string]*entry{}
	var order []string
	for i, m := range msgs {
		name, ok := llm.SkillInvocationName(m)
		if !ok {
			continue
		}
		if e, seen := latest[name]; seen {
			e.msg, e.idx = m, i
		} else {
			latest[name] = &entry{msg: m, idx: i}
			order = append(order, name)
		}
	}
	if len(latest) == 0 {
		return nil
	}
	// Candidates whose latest invocation fell behind the boundary, newest-first.
	var cands []*entry
	for _, name := range order {
		if e := latest[name]; e.idx < tailStart {
			cands = append(cands, e)
		}
	}
	sort.Slice(cands, func(a, b int) bool { return cands[a].idx > cands[b].idx })

	kept := make([]*entry, 0, len(cands))
	total := 0
	for _, e := range cands {
		m := llm.TruncateSkillMessage(e.msg, maxSkillReinjectTokens*4)
		t := EstimateTokens([]llm.Message{m})
		if total+t > maxSkillReinjectTotalTokens {
			continue // drop this one; a smaller, older skill may still fit
		}
		total += t
		kept = append(kept, &entry{msg: m, idx: e.idx})
	}
	if len(kept) == 0 {
		return nil
	}
	sort.Slice(kept, func(a, b int) bool { return kept[a].idx < kept[b].idx })
	out := make([]llm.Message, 0, len(kept))
	for _, e := range kept {
		out = append(out, e.msg)
	}
	return out
}

func contentOnly(msgs []llm.Message) []llm.Message {
	out := make([]llm.Message, 0, len(msgs))
	for _, m := range msgs {
		if !llm.IsBoundaryMarker(m) {
			out = append(out, m)
		}
	}
	return out
}

// --- summarizer (model-backed, 4zrec internal/kernel/compaction/summarizer.go) ---

// Summary generation constants (== claude-code).
const (
	compactMaxOutputTokens = 20000                                                   // COMPACT_MAX_OUTPUT_TOKENS
	maxPTLRetries          = 3                                                       // MAX_PTL_RETRIES
	maxStreamingRetries    = 2                                                       // MAX_COMPACT_STREAMING_RETRIES
	ptlRetryMarker         = "[earlier conversation truncated for compaction retry]" // PTL_RETRY_MARKER
)

// summarySystemPrompt is the summarizer's system prompt (== claude-code
// streamCompactSummary fallback path). Thinking is disabled and no tools are
// offered; the no-tools guardrails live in the user prompt (§7).
//
// Norma carried "thinking disabled" as a per-request field; eino's
// model.BaseChatModel has no per-request thinking switch, so the summarizer
// model must be constructed with thinking off by the host.
const summarySystemPrompt = "You are a helpful AI assistant tasked with summarizing conversations."

// NewModelSummarizer builds a Summarizer backed by an eino model.BaseChatModel.
// It replays the real conversation messages (not a rendered text transcript)
// followed by the summary-request user message, with output capped at
// min(20000, maxOutputTokens). It retries transient stream failures
// (MAX_COMPACT_STREAMING_RETRIES) and, if the summary request itself overflows,
// drops the oldest API-round groups and retries (MAX_PTL_RETRIES).
func NewModelSummarizer(m model.BaseChatModel, maxOutputTokens int, nonStreaming bool) Summarizer {
	maxOut := compactMaxOutputTokens
	if maxOutputTokens > 0 && maxOutputTokens < maxOut {
		maxOut = maxOutputTokens
	}
	return func(ctx context.Context, msgs []llm.Message) (string, error) {
		work := pairForReplay(msgs)
		var lastErr error
		for attempt := 0; attempt <= maxPTLRetries; attempt++ {
			raw, err := streamSummary(ctx, m, maxOut, work, nonStreaming)
			if err == nil {
				return formatCompactSummary(raw), nil
			}
			if !IsOverflow(err) {
				return "", err
			}
			lastErr = err
			truncated, ok := truncateHeadForPTLRetry(work)
			if !ok {
				break
			}
			work = truncated
		}
		return "", lastErr
	}
}

// streamSummary issues one summary request (system + head + summary-request
// message), retrying transient (non-overflow) failures. Overflow is returned
// immediately so the caller can truncate and retry at a coarser granularity.
func streamSummary(ctx context.Context, m model.BaseChatModel, maxOut int, head []llm.Message, nonStreaming bool) (string, error) {
	reqMsgs := make([]*schema.Message, 0, len(head)+2)
	reqMsgs = append(reqMsgs, schema.SystemMessage(summarySystemPrompt))
	reqMsgs = append(reqMsgs, ToSchema(head)...)
	reqMsgs = append(reqMsgs, schema.UserMessage(compactPrompt))
	opts := []model.Option{model.WithMaxTokens(maxOut)}
	var lastErr error
	for range maxStreamingRetries {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var text string
		var callErr error
		if nonStreaming {
			msg, err := m.Generate(ctx, reqMsgs, opts...)
			if err == nil {
				text = msg.Content
			}
			callErr = err
		} else {
			text, callErr = streamText(ctx, m, reqMsgs, opts)
		}
		if callErr == nil {
			return text, nil
		}
		if IsOverflow(callErr) {
			return "", callErr // PTL — let the caller truncate, don't burn streaming retries
		}
		lastErr = callErr // transient — retry
	}
	return "", lastErr
}

// streamText consumes one streaming response, concatenating the chunks' text
// (the eino analogue of the Accumulator over text deltas). A reader-level
// error discards the partial text; io.EOF completes it.
func streamText(ctx context.Context, m model.BaseChatModel, reqMsgs []*schema.Message, opts []model.Option) (string, error) {
	sr, err := m.Stream(ctx, reqMsgs, opts...)
	if err != nil {
		return "", err
	}
	defer sr.Close()
	var buf strings.Builder
	for {
		chunk, err := sr.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf.String(), nil
			}
			return "", err
		}
		buf.WriteString(chunk.Content)
	}
}

// pairForReplay drops dangling tool_use / tool_result blocks so the replayed head
// is a valid request (the working-set boundary may split a tool_use from its
// result). Mirrors claude-code's ensureToolResultPairing intent (drop, not
// synthesize — summarization only needs the surrounding text). Messages left
// empty are removed.
func pairForReplay(msgs []llm.Message) []llm.Message {
	useIDs := map[string]bool{}
	resIDs := map[string]bool{}
	for _, m := range msgs {
		for _, b := range m.Content {
			switch b.Type {
			case llm.BlockToolUse:
				useIDs[b.ID] = true
			case llm.BlockToolResult:
				resIDs[b.ToolUseID] = true
			}
		}
	}
	out := make([]llm.Message, 0, len(msgs))
	for _, m := range msgs {
		nc := make([]llm.ContentBlock, 0, len(m.Content))
		for _, b := range m.Content {
			switch b.Type {
			case llm.BlockToolUse:
				if !resIDs[b.ID] {
					continue
				}
			case llm.BlockToolResult:
				if !useIDs[b.ToolUseID] {
					continue
				}
			}
			nc = append(nc, b)
		}
		if len(nc) > 0 {
			out = append(out, llm.Message{Role: m.Role, Content: nc})
		}
	}
	return out
}

// truncateHeadForPTLRetry drops the oldest API-round groups when the summary
// request itself overflows (== claude-code truncateHeadForPTLRetry, 20% fallback
// branch — Norma cannot read a precise token gap from the provider error). It
// strips a leading retry marker, groups by API round, drops floor(20%) of the
// oldest groups (≥1, keeping ≥1), and re-prepends the marker if the result would
// start with an assistant message (the API requires a user-first message).
func truncateHeadForPTLRetry(msgs []llm.Message) ([]llm.Message, bool) {
	input := msgs
	if len(input) > 0 && isPTLMarker(input[0]) {
		input = input[1:]
	}
	groups := groupByAPIRound(input)
	if len(groups) < 2 {
		return nil, false
	}
	dropCount := len(groups) / 5 // floor(len * 0.2)
	dropCount = max(dropCount, 1)
	dropCount = min(dropCount, len(groups)-1)
	var sliced []llm.Message
	for _, g := range groups[dropCount:] {
		sliced = append(sliced, g...)
	}
	if len(sliced) == 0 {
		return nil, false
	}
	if sliced[0].Role == llm.RoleAssistant {
		sliced = append([]llm.Message{llm.UserText(ptlRetryMarker)}, sliced...)
	}
	return sliced, true
}

func isPTLMarker(m llm.Message) bool {
	return m.Role == llm.RoleUser && len(m.Content) == 1 &&
		m.Content[0].Type == llm.BlockText && m.Content[0].Text == ptlRetryMarker
}

// groupByAPIRound partitions messages into one group per API round-trip: a new
// group begins at each assistant message. Mirrors claude-code
// groupMessagesByApiRound (Norma has one assistant message per round, so role
// boundaries == message-id boundaries). Group 0 holds any leading preamble.
func groupByAPIRound(msgs []llm.Message) [][]llm.Message {
	var groups [][]llm.Message
	var cur []llm.Message
	for _, m := range msgs {
		if m.Role == llm.RoleAssistant && len(cur) > 0 {
			groups = append(groups, cur)
			cur = nil
		}
		cur = append(cur, m)
	}
	if len(cur) > 0 {
		groups = append(groups, cur)
	}
	return groups
}

var (
	analysisRe = regexp.MustCompile(`(?s)<analysis>.*?</analysis>`)
	summaryRe  = regexp.MustCompile(`(?s)<summary>(.*?)</summary>`)
	blankRe    = regexp.MustCompile(`\n{2,}`)
)

// formatCompactSummary post-processes the model's raw output (== claude-code
// formatCompactSummary): strip the <analysis> scratchpad, unwrap <summary> into a
// "Summary:" header, and collapse blank-line runs.
func formatCompactSummary(raw string) string {
	s := analysisRe.ReplaceAllString(raw, "")
	if m := summaryRe.FindStringSubmatch(s); m != nil {
		s = "Summary:\n" + strings.TrimSpace(m[1])
	}
	s = blankRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// compactPrompt is the full summary-request user message:
// NO_TOOLS_PREAMBLE + BASE_COMPACT_PROMPT + NO_TOOLS_TRAILER (§7).
var compactPrompt = noToolsPreamble + baseCompactPrompt + noToolsTrailer

// noToolsPreamble == claude-code NO_TOOLS_PREAMBLE (prompt.ts:19-26).
const noToolsPreamble = `CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.

- Do NOT use Read, Bash, Grep, Glob, Edit, Write, or ANY other tool.
- You already have all the context you need in the conversation above.
- Tool calls will be REJECTED and will waste your only turn — you will fail the task.
- Your entire response must be plain text: an <analysis> block followed by a <summary> block.

`

// noToolsTrailer == claude-code NO_TOOLS_TRAILER (prompt.ts:269-272).
const noToolsTrailer = `

REMINDER: Do NOT call any tools. Respond with plain text only — an <analysis> block followed by a <summary> block. Tool calls will be rejected and you will fail the task.`

// baseCompactPrompt == claude-code BASE_COMPACT_PROMPT (prompt.ts:61-143), verbatim
// (including the DETAILED_ANALYSIS_INSTRUCTION_BASE it interpolates and the source
// trailing spaces on the "All user messages:" and "...in your response. " lines).
const baseCompactPrompt = `Your task is to create a detailed summary of the conversation so far, paying close attention to the user's explicit requests and your previous actions.
This summary should be thorough in capturing technical details, code patterns, and architectural decisions that would be essential for continuing development work without losing context.

Before providing your final summary, wrap your analysis in <analysis> tags to organize your thoughts and ensure you've covered all necessary points. In your analysis process:

1. Chronologically analyze each message and section of the conversation. For each section thoroughly identify:
   - The user's explicit requests and intents
   - Your approach to addressing the user's requests
   - Key decisions, technical concepts and code patterns
   - Specific details like:
     - file names
     - full code snippets
     - function signatures
     - file edits
   - Errors that you ran into and how you fixed them
   - Pay special attention to specific user feedback that you received, especially if the user told you to do something differently.
2. Double-check for technical accuracy and completeness, addressing each required element thoroughly.

Your summary should include the following sections:

1. Primary Request and Intent: Capture all of the user's explicit requests and intents in detail
2. Key Technical Concepts: List all important technical concepts, technologies, and frameworks discussed.
3. Files and Code Sections: Enumerate specific files and code sections examined, modified, or created. Pay special attention to the most recent messages and include full code snippets where applicable and include a summary of why this file read or edit is important.
4. Errors and fixes: List all errors that you ran into, and how you fixed them. Pay special attention to specific user feedback that you received, especially if the user told you to do something differently.
5. Problem Solving: Document problems solved and any ongoing troubleshooting efforts.
6. All user messages: List ALL user messages that are not tool results. These are critical for understanding the users' feedback and changing intent.
7. Pending Tasks: Outline any pending tasks that you have explicitly been asked to work on.
8. Current Work: Describe in detail precisely what was being worked on immediately before this summary request, paying special attention to the most recent messages from both user and assistant. Include file names and code snippets where applicable.
9. Optional Next Step: List the next step that you will take that is related to the most recent work you were doing. IMPORTANT: ensure that this step is DIRECTLY in line with the user's most recent explicit requests, and the task you were working on immediately before this summary request. If your last task was concluded, then only list next steps if they are explicitly in line with the users request. Do not start on tangential requests or really old requests that were already completed without confirming with the user first.
                       If there is a next step, include direct quotes from the most recent conversation showing exactly what task you were working on and where you left off. This should be verbatim to ensure there's no drift in task interpretation.

Here's an example of how your output should be structured:

<example>
<analysis>
[Your thought process, ensuring all points are covered thoroughly and accurately]
</analysis>

<summary>
1. Primary Request and Intent:
   [Detailed description]

2. Key Technical Concepts:
   - [Concept 1]
   - [Concept 2]
   - [...]

3. Files and Code Sections:
   - [File Name 1]
      - [Summary of why this file is important]
      - [Summary of the changes made to this file, if any]
      - [Important Code Snippet]
   - [File Name 2]
      - [Important Code Snippet]
   - [...]

4. Errors and fixes:
    - [Detailed description of error 1]:
      - [How you fixed the error]
      - [User feedback on the error if any]
    - [...]

5. Problem Solving:
   [Description of solved problems and ongoing troubleshooting]

6. All user messages:
    - [Detailed non tool use user message]
    - [...]

7. Pending Tasks:
   - [Task 1]
   - [Task 2]
   - [...]

8. Current Work:
   [Precise description of current work]

9. Optional Next Step:
   [Optional Next step to take]

</summary>
</example>

Please provide your summary based on the conversation so far, following this structure and ensuring precision and thoroughness in your response.

There may be additional summarization instructions provided in the included context. If so, remember to follow these instructions when creating the above summary. Examples of instructions include:
<example>
## Compact Instructions
When summarizing the conversation focus on typescript code changes and also remember the mistakes you made and how you fixed them.
</example>

<example>
# Summary instructions
When you are using compact - please focus on test output and code changes. Include file reads verbatim.
</example>`
