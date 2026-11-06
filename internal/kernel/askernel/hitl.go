package askernel

// hitl.go — 内核侧 HITL（docs/Eino深度接入方案-2026-11-05.md §4-P2）：
// tool.StatefulInterrupt 发出的审批中断经 AgentEvent.Action.Interrupted 浮出，
// Runner 把图状态落 Options.CheckpointStore（PG: runner_checkpoints），run 以
// termmap.AwaitingApproval 终态收场；人工决定落库后宿主用 ResumeApproval 从
// checkpoint 精确续跑（ResumeWithParams 按 interrupt id 定点投递签名决定，
// guard 在中断点核对后才放行/拦截）。
//
// 同轮多工具中断由 ADK 的 CompositeInterrupt 聚合：恢复只投命中的 Targets，
// 未命中的兄弟中断按官方语义以原状态 re-interrupt（gate 端点顶部处理），宿主
// 停靠循环天然承接「决定一个 → 再中断 → 再决定」的链。

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/transcript"
	"github.com/cloudwego/eino/adk"

	"github.com/c1ayooo/4zreco/internal/db"
)

// HitlInterrupt 是一次审批挂起的完整描述，随 AwaitingApproval 终态交付宿主：
// 宿主据此落映射表（db.SaveHitlMapping）、停靠等决定，决定后调 ResumeApproval。
type HitlInterrupt struct {
	CheckpointID string `json:"checkpoint_id"`
	InterruptID  string `json:"interrupt_id"`
	PendingID    int64  `json:"pending_id"`
	Tool         string `json:"tool"`
	Kind         string `json:"kind"`
	Reason       string `json:"reason"`
}

// resumeRequest 是 ResumeApproval 预挂的一次性恢复指令：下一个 run 以
// ResumeWithParams 从 checkpoint 续跑（跑完即清，后续 run 回到普通路径）。
type resumeRequest struct {
	checkpointID string
	interruptID  string
	resume       *db.HitlResumeData
}

// hitlFromEvent 从中断事件提取审批挂起描述：InterruptContexts[0].ID 是 gate
// StatefulInterrupt 的中断点，Info 是 guard 发起中断时的 *db.HitlAskInfo。
// 聚合中断（同轮多工具 ask）各上下文同构——宿主按 interrupt id 逐个投递决定。
func hitlFromEvent(ev *adk.AgentEvent, checkpointID string) *HitlInterrupt {
	out := &HitlInterrupt{CheckpointID: checkpointID}
	info := ev.Action.Interrupted
	if len(info.InterruptContexts) == 0 {
		return out
	}
	ic := info.InterruptContexts[0]
	out.InterruptID = ic.ID
	if ask, ok := ic.Info.(*db.HitlAskInfo); ok && ask != nil {
		out.PendingID = ask.PendingID
		out.Tool = ask.Tool
		out.Kind = ask.Kind
		out.Reason = ask.Reason
	}
	return out
}

// newCheckpointID 生成本次 run 的稳定 checkpoint 标识（Run 带 WithCheckPointID，
// 中断时 Runner 以它落库；ResumeApproval 以同一 id 取回）。
func newCheckpointID(sessionID string) string {
	return fmt.Sprintf("hitl-%s-%d", sessionID, time.Now().UnixNano())
}

// captureInterrupt 记录本次 run 的首个审批中断（聚合中断只留首个可归属上下文
// ——宿主对挂起 pending 逐个决定，未命中的由 re-interrupt 再次浮出）。
func (s *Session) captureInterrupt(hitl *HitlInterrupt) {
	s.hitlMu.Lock()
	if s.hitlPending == nil {
		s.hitlPending = hitl
	}
	s.hitlMu.Unlock()
}

// pendingInterrupt returns the interrupt captured by the last run, if any
// （runStream 用它给终态定 AwaitingApproval；宿主 driver 读它做停靠/续跑）。
func (s *Session) pendingInterrupt() *HitlInterrupt {
	s.hitlMu.Lock()
	defer s.hitlMu.Unlock()
	return s.hitlPending
}

// Interrupt returns the last run's captured approval interrupt (nil = the run
// did not end on an interrupt). The host driver reads it together with the
// AwaitingApproval terminal to park the intent and resume after the decision.
func (s *Session) Interrupt() *HitlInterrupt { return s.pendingInterrupt() }

// clearInterrupt resets per-run interrupt capture（每个 run 开始时调用——上一
// 个 run 的挂起已由宿主消费或放弃）。
func (s *Session) clearInterrupt() {
	s.hitlMu.Lock()
	s.hitlPending = nil
	s.hitlMu.Unlock()
}

// setResume 预挂一次 ResumeApproval 指令（ResumeApproval 调用；driveAgent 取走
// 后清空）。
func (s *Session) setResume(r *resumeRequest) {
	s.hitlMu.Lock()
	s.resumeReq = r
	s.hitlMu.Unlock()
}

// takeResume pops the pending resume request, if any.
func (s *Session) takeResume() *resumeRequest {
	s.hitlMu.Lock()
	r := s.resumeReq
	s.resumeReq = nil
	s.hitlMu.Unlock()
	return r
}

// ResumeForApproval reloads a prior conversation from the transcript store for
// checkpoint resume: unlike Resume it KEEPS the trailing assistant tool_use —
// the interrupted call the checkpoint will re-invoke. 跨进程恢复的装配前提
// （DTO master 与 checkpoint 的图状态对齐到中断点；AfterModelRewriteState 已把
// 中断前的最后一条 assistant 落进 transcript）。Requires Options.Transcript.
func (s *Session) ResumeForApproval(sessionID string) error {
	if s.store == nil {
		return fmt.Errorf("askernel: ResumeForApproval requires Options.Transcript")
	}
	recs, err := s.store.Load(s.store.MainPath(sessionID))
	if err != nil {
		return err
	}
	msgs, usage := transcript.Messages(recs)
	s.dto.Set(msgs) // 不做 cleanResumed：尾部的 assistant tool_use 就是待续跑的调用
	s.mu.Lock()
	s.usage = usage
	s.mu.Unlock()
	s.sessionID = sessionID
	if s.writer != nil {
		s.writer = s.store.ResumeWriter(sessionID, transcript.LastUUID(recs))
	}
	return nil
}

// ResumeDirective 是一次预挂的恢复指令（重领重建用）：checkpointID/interruptID
// 来自映射表，Resume 是宿主签名的决定数据。
type ResumeDirective struct {
	CheckpointID string
	InterruptID  string
	Resume       *db.HitlResumeData
}

// PlanResume 预挂一次恢复指令，下一次 StartPlanned 以 ResumeWithParams 开场
// （P2-3 重领重建：进程重启后 worker 重领该意图，先续跑被中断的调用再回到
// 正常意图流；不追加任何 user 消息——续跑的是原对话）。
func (s *Session) PlanResume(d ResumeDirective) {
	s.setResume(&resumeRequest{checkpointID: d.CheckpointID, interruptID: d.InterruptID, resume: d.Resume})
}

// hasPlannedResume reports whether PlanResume armed a directive.
func (s *Session) hasPlannedResume() bool {
	s.hitlMu.Lock()
	defer s.hitlMu.Unlock()
	return s.resumeReq != nil
}

// StartPlanned opens the run: a planned resume (PlanResume) starts with
// ResumeWithParams (no new user input — 续跑的是原对话); otherwise it is a
// normal Prompt(input). The route-A driver calls this instead of Prompt.
func (s *Session) StartPlanned(ctx context.Context, input string) iter.Seq2[harnessEvent, error] {
	return func(yield func(harnessEvent, error) bool) {
		if s.hasPlannedResume() {
			s.runStream(ctx, nil, s.opts.MaxTurns, yield)
			return
		}
		s.Prompt(ctx, input)(yield)
	}
}

// ResumeApproval 在人工决定落库后续跑一次因审批中断的 run：宿主先行
// db.SignHitlResume 生成签名决定（ResolveIntercept 成功后取决定行 id），内核以
// ResumeWithParams 按 interrupt id 定点投递；gate 在中断点取回并交 guard 核对
// （签名 + 决定行 + 调用绑定），allowed 继续执行工具、denied 以管控文本收场后
// run 继续。跨进程：宿主先 ResumeForApproval 装配出同指纹的 Session 再调本方法。
// checkpointID 必须是中断 run 的 HitlInterrupt.CheckpointID。
func (s *Session) ResumeApproval(ctx context.Context, checkpointID, interruptID string, resume *db.HitlResumeData) iter.Seq2[harnessEvent, error] {
	return func(yield func(harnessEvent, error) bool) {
		s.setResume(&resumeRequest{checkpointID: checkpointID, interruptID: interruptID, resume: resume})
		s.runStream(ctx, nil, s.opts.MaxTurns, yield)
	}
}
