package agent

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
	"github.com/c1ayooo/4zreco/internal/sidequestion"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// captureRun drives one agent turn-to-completion over the eino kernel and emits
// a coalesced ActivityRecord per execution step (tool_use / tool_result / text /
// thinking / result). 刀④ 切换默认：这是 planner 与目标拆解（goals）的主循环入口
// ——norma agentcore 版本保留不删（P4 删，见 capture_norma.go）。
//
// The emitted records carry only Kind/Tool/ToolUseID/IsError/Summary/Detail; the
// caller's emit fills in IntentID/Worker. Returns the final assistant text +
// terminal reason + error.
func captureRun(ctx context.Context, opts askernel.Options, input string, emit func(db.Activity)) (string, harness.TerminalReason, error) {
	s := askernel.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)
	return captureRunSession(ctx, s, input, emit, kernelDriver{})
}

// captureRunSession is captureRun over an existing session, so a caller can run
// multiple prompts on the SAME conversation (worker 续跑 / chat 多轮 / mainagent
// / 结算复用同一上下文)。driver 的旋钮（Stop 链 / nudge 预算 / settlement /
// checkpoint）由装配层传入——worker 传 engine 接线的一整套；其余按需。
func captureRunSession(ctx context.Context, s *askernel.Session, input string, emit func(db.Activity), d kernelDriver) (string, harness.TerminalReason, error) {
	p := newCapturePump(ctx, input, s.Messages(), emit)
	defer p.finish()
	// 工具调用的同步观测（acllm.ToolGate.OnCallStart/OnResult）：norma 时代
	// tool_use/tool_result 事件都先于下一步同步到达、审计 trace 随事件推进；
	// eino 的 tools node 与事件泵有竞态——下一次工具调用的 judge 必须看到上一
	// 次的结果上下文，所以绑定与结果上下文都在执行端同步落。
	s.OnCallStart = func(callID, name string, inputJSON json.RawMessage) {
		p.auditTrace.Start(callID, name, inputJSON)
	}
	s.OnResult = func(callID, name, text string, isErr bool, extras []llm.Message) {
		p.auditTrace.Complete(callID, text, isErr)
		if !p.traceResults[callID] {
			p.traceResults[callID] = true
			p.auditTrace.Append(db.InterceptContextEntry{Kind: "tool_result", Tool: name, ToolUseID: callID, Text: text, IsError: isErr})
		}
	}
	// p.ctx 携带 intercept 审计 trace（norma 时代的 ctx 重赋值同款）——guard 链的
	// judge/ask 从这个 ctx 取审批上下文，必须传给 runner。
	return runKernel(p.ctx, s, input, d, p)
}

// capturePump is the event → activity conversion shared by every run of one
// conversation: coalesced text/thinking deltas, tool_use/tool_result pairing,
// live usage, and the final result record. The coalescing state and the audit
// trace span the WHOLE conversation (all runs of the route-A loop), not one run.
type capturePump struct {
	ctx       context.Context
	rec       func(db.Activity) // auditTrace.Append + emit
	auditTrace *intercept.Trace

	toolNames map[string]string // tool_use id -> name, to label results
	// traceResults marks results whose audit context entry the gate's OnResult
	// already appended synchronously — the pump skips its own (async) append.
	traceResults map[string]bool

	tbuf  strings.Builder
	tkind string

	lastTool  *runTrace
	lastUsage *llm.Usage

	finalText string
	reason    harness.TerminalReason

	// activities/actMu 记录已发活动（recordedActivities 测试 seam；rec 每条同步记）。
	actMu      sync.Mutex
	activities []db.Activity
}

func newCapturePump(ctx context.Context, input string, msgs []llm.Message, emit func(db.Activity)) *capturePump {
	ctx, auditTrace := intercept.WithTrace(ctx, input, approvalHistory(msgs))
	p := &capturePump{}
	rec := func(r db.Activity) {
		if r.Kind == "text" || r.Kind == "tool_result" {
			auditTrace.Append(db.InterceptContextEntry{Kind: r.Kind, Tool: r.Tool, ToolUseID: r.ToolUseID, Text: r.Detail, IsError: r.IsError})
		}
		p.actMu.Lock()
		p.activities = append(p.activities, r)
		p.actMu.Unlock()
		if emit != nil {
			emit(r)
		}
	}
	p.ctx = ctx
	p.rec = rec
	p.auditTrace = auditTrace
	p.toolNames = map[string]string{}
	p.traceResults = map[string]bool{}
	p.lastTool = &runTrace{startedAt: time.Now()}
	return p
}

// recordedActivities exposes the activities this pump emitted (测试 seam：defensive
// 分支的结果活动断言用).
func (p *capturePump) recordedActivities() []db.Activity {
	p.actMu.Lock()
	defer p.actMu.Unlock()
	return append([]db.Activity(nil), p.activities...)
}

// finish releases the audit trace and flushes any unflushed deltas (safety:
// the stream ended without a final result).
func (p *capturePump) finish() {
	p.flush()
	p.auditTrace.Finish()
}

func (p *capturePump) flush() {
	if p.tbuf.Len() == 0 {
		return
	}
	s := strings.TrimSpace(p.tbuf.String())
	k := p.tkind
	p.tbuf.Reset()
	p.tkind = ""
	if s != "" {
		p.rec(db.Activity{Kind: k, Summary: firstLine(s, 200), Detail: s})
	}
}

func (p *capturePump) addDelta(kind, text string) {
	if text == "" {
		return
	}
	if p.tkind != "" && p.tkind != kind {
		p.flush()
	}
	p.tkind = kind
	p.tbuf.WriteString(text)
}

// drain pumps ONE kernel run's events into activities and returns its terminal.
// The terminal is NOT emitted as an activity here — the route-A driver decides
// whether the run is final (emitResult) or continues the loop (nudge /
// settlement / notifications). err is non-nil on a run error; drained=false
// means the consumer stopped mid-stream (no terminal).
func (p *capturePump) drain(events iter.Seq2[harness.Event, error]) (*harness.Terminal, bool, error) {
	var runErr error
	for ev, err := range events {
		if err != nil {
			runErr = err
			continue
		}
		switch ev.Kind {
		case harness.KindToolUse:
			if ev.ToolUse == nil {
				continue
			}
			p.flush()
			p.toolNames[ev.ToolUse.ID] = ev.ToolUse.Name
			in := string(ev.ToolUse.Input)
			p.lastTool.start(ev.ToolUse.ID, ev.ToolUse.Name, in)
			if !p.auditTrace.HasCall(ev.ToolUse.ID) {
				p.auditTrace.Start(ev.ToolUse.ID, ev.ToolUse.Name, ev.ToolUse.Input)
			}
			p.rec(db.Activity{Kind: "tool_use", Tool: ev.ToolUse.Name, ToolUseID: ev.ToolUse.ID,
				Summary: ev.ToolUse.Name + " " + firstLine(in, 200), Detail: in})
		case harness.KindToolResult:
			if ev.ToolResult == nil {
				continue
			}
			p.flush()
			out := blocksText(ev.ToolResult.Content)
			p.lastTool.done(ev.ToolResult.ToolUseID)
			// Complete/Append 已由 gate 的 OnResult 同步落（幂等：Complete 弹绑
			// 定，二次调用 no-op；Append 由 traceResults 去重）。这里只补 UI 面。
			p.auditTrace.Complete(ev.ToolResult.ToolUseID, out, ev.ToolResult.IsError)
			p.rec(db.Activity{Kind: "tool_result", Tool: p.toolNames[ev.ToolResult.ToolUseID], ToolUseID: ev.ToolResult.ToolUseID,
				IsError: ev.ToolResult.IsError, Summary: firstLine(out, 200), Detail: out})
		case harness.KindText:
			p.addDelta("text", ev.Text)
		case harness.KindThinking:
			p.addDelta("thinking", ev.Text)
		case harness.KindUsage:
			// live cumulative token usage (per model turn). Emitted as a
			// non-rendered "usage" activity carrying only the token fields; the
			// UI uses the latest one for a running session's live token count.
			// Don't flush() here — the buffered final-answer text must stay for
			// the result de-dup.
			if ev.Usage != nil {
				u := *ev.Usage
				p.lastUsage = &u
				p.rec(db.Activity{Kind: "usage",
					InputTokens: &u.InputTokens, OutputTokens: &u.OutputTokens,
					CacheReadTokens: &u.CacheReadTokens, CacheWriteTokens: &u.CacheWriteTokens})
			}
		case harness.KindResult:
			// returned to the driver, not emitted (may not be final)
			return ev.Terminal, true, nil
		}
	}
	if runErr != nil {
		// Run error mid-conversation: mirror the norma-era result rendering —
		// engine/user cancellation renders as an abort, everything else as an
		// execution error. 当前内核契约（runStream 对错误也映射后 yield KindResult、
		// drainEvents 恒 yield nil error）下此分支不可达；保留是为 iter.Seq2 类型
		// 契约的完备性（P2 checkpoint 错误可能经同一 seam 冒错），行为已由
		// TestCapturePumpDrainErrorBranch 钉住（评审第 1 轮 #2）。
		p.flush()
		if p.ctx.Err() != nil {
			sum, detail := terminalText(p.ctx, &harness.Terminal{Reason: p.reason, Err: p.ctx.Err()}, p.lastTool)
			p.rec(activityWithUsage(db.Activity{Kind: "result", Summary: firstLine(sum, 400), Detail: detail}, p.lastUsage))
			return nil, true, p.ctx.Err()
		}
		p.rec(activityWithUsage(db.Activity{Kind: "result", IsError: true, Summary: "执行出错: " + runErr.Error(), Detail: runErr.Error()}, p.lastUsage))
		return nil, true, runErr
	}
	// stream closed without KindResult — treat as consumer stop (norma parity)
	p.flush()
	return nil, false, nil
}

// emitResult renders and records the FINAL terminal as the conversation's
// result activity: sidequestion finish, tail-text de-dup, abort rendering and
// the cumulative usage columns.
func (p *capturePump) emitResult(term *harness.Terminal) {
	if term == nil {
		return
	}
	if term.Reason != harness.ReasonAbortedStreaming {
		sidequestion.Finish(p.ctx, term.Messages)
	}
	p.finalText = term.Text
	p.reason = term.Reason
	// the buffered tail text usually equals Terminal.Text (final answer); drop
	// it to avoid a duplicate record, the result row carries it.
	if p.tkind == "text" && strings.TrimSpace(p.tbuf.String()) == strings.TrimSpace(term.Text) {
		p.tbuf.Reset()
		p.tkind = ""
	}
	p.flush() // flush any trailing thinking / non-final text
	sum, detail := term.Text, term.Text
	if sum == "" || term.Reason == harness.ReasonAbortedTools || term.Reason == harness.ReasonAbortedStreaming {
		sum, detail = terminalText(p.ctx, term, p.lastTool)
	}
	u := term.Usage // cumulative token usage for this session
	p.rec(db.Activity{Kind: "result", IsError: term.Err != nil,
		Summary: firstLine(sum, 400), Detail: detail,
		InputTokens: &u.InputTokens, OutputTokens: &u.OutputTokens,
		CacheReadTokens: &u.CacheReadTokens, CacheWriteTokens: &u.CacheWriteTokens})
}

func activityWithUsage(activity db.Activity, usage *llm.Usage) db.Activity {
	if usage == nil {
		return activity
	}
	u := *usage
	activity.InputTokens = &u.InputTokens
	activity.OutputTokens = &u.OutputTokens
	activity.CacheReadTokens = &u.CacheReadTokens
	activity.CacheWriteTokens = &u.CacheWriteTokens
	return activity
}

// blocksText concatenates the text of a tool-result's content blocks.
func blocksText(blocks []llm.ContentBlock) string {
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Type == llm.BlockText && bl.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(bl.Text)
		}
	}
	return b.String()
}

// firstLine returns a single-line, rune-capped preview for the summary column.
func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if before, _, found := strings.Cut(s, "\n"); found {
		s = before
	}
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return s
}

// Preserve the recorded session's visible messages, excluding thinking blocks.
// This is audit context; the judge receives only bounded, paired execution
// evidence selected from it, never assistant prose or thinking blocks.
func approvalHistory(messages []llm.Message) []db.InterceptContextEntry {
	var entries []db.InterceptContextEntry
	for _, message := range messages {
		for _, block := range message.Content {
			entry := db.InterceptContextEntry{Kind: string(message.Role)}
			switch block.Type {
			case llm.BlockText:
				entry.Text = block.Text
			case llm.BlockToolUse:
				entry.Kind, entry.Tool, entry.ToolUseID, entry.Text = "tool_use", block.Name, block.ID, string(block.Input)
			case llm.BlockToolResult:
				entry.Kind, entry.ToolUseID, entry.Text, entry.IsError = "tool_result", block.ToolUseID, blocksText(block.Content), block.IsError
			default:
				continue
			}
			entries = append(entries, entry)
		}
	}
	return entries
}
