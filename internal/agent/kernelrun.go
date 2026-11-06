package agent

// kernelrun.go — the route-A driver (方案 §3.1 空轮次续跑上移 engine + §4-P1 第 7 条):
// the norma harness main-loop semantics that eino's ReAct runner does not carry,
// re-hosted ABOVE the kernel. eino 终态即停、无 Continue 语义，所以「终态后判定 →
// 注入指令 → 重开 Run」的循环在这里，内核只给单次有界 run（askernel.Session.Prompt
// / Continue / RunSettlement）。
//
// 逐条 norma 对应（harness/query.go:494-541 的自然结束分支）：
//
//   1. Stop 链（idle-stop 写回收手 + guard 转发）只在 !stopHookActive 的自然结束触发；
//      prevent → stop_hook_prevented 收场；blocking → 注入 user 消息、stopHookActive 置位、续跑。
//   2. stopHookActive 在自然结束时复位（norma query.go:496）——注入过的那一轮结束后钩子重新武装。
//   3. 任务通知：自然结束先 drain，有通知就注入再跑一轮（ContinueTaskNotification）。
//   4. 空转续跑（本刀上移）：completed 且末条 assistant 无文本无工具且预算未达 →
//      append 续跑指令 → Continue。预算 = 每条意图总量，落 DB（IncrEmptyTurnNudges，
//      等价 defaultEmptyTurnNudges=2；norma 时代的内存计数重跑即清零，这里持久）。
//   5. 结算（max_turns/timeout）：append 收尾词 → RunSettlement（隐藏 DisabledTools、
//      自带轮数预算）一次；终态保留原预算 reason（结算只是 checkpoint，norma finish(settleReason)）。
//
// 计数语义的边界（engine.go 注释同款）：连续空转只推一次——推完那一轮若还是空转，
// stopHookActive 挡住 Stop 链与 nudge，run 收场；只有真正发生过一次工具回合，钩子
// 才重新武装。预算挡的是「工具→空转→推→工具→空转」的病态循环，别让它耗光意图预算。

import (
	"context"
	"log"
	"strings"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
	"github.com/c1ayooo/4zreco/internal/kernel/termmap"
)

// emptyTurnNudge 是空转回合注入的续跑指令（原 engine.go 常量随路线 A 上移到这里）。
//
// 这种回合在内核眼里是一次自然结束(模型无 tool_call)，五层 LLM 重试一层都不适用
// ——它不是错误，是模型「想完了但没动手」。这里换成追加一条指令，让它带着已经
// 产出的思考继续，输入变了才有理由给出不同的行为。
const emptyTurnNudge = "【空转提醒】你上一轮只输出了思考过程，既没有给出正文回复，也没有调用任何工具，" +
	"这一轮等于没有产出。请直接执行你刚才想好的下一步：要么调用工具，要么给出结论文字。不要重复思考。"

// isThinkingOnlyTurn reports whether the latest assistant turn produced neither
// text nor a tool call — i.e. the model spent the whole round thinking.
// （原 engine.go 函数随路线 A 上移到这里。）
func isThinkingOnlyTurn(messages []llm.Message) bool {
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		return strings.TrimSpace(m.Text()) == "" && len(m.ToolUses()) == 0
	}
	return false
}

// Nudger is the empty-turn nudge budget the engine wires per intent run —
// 落 DB 的「每条意图总量」计数（db.ExplorationStore.IncrEmptyTurnNudges）。
// Increment bumps the persisted counter and returns the new 1-based value.
type Nudger interface {
	Increment(ctx context.Context) (int, error)
	Limit() int
	Label() string
}

// IntentNudger is the DB-backed Nudger over one intent row (engine wires it;
// 单测用内存实现)。Increment 失败按预算未达放行——计数是护栏，不该因持久化
// 故障卡死真实任务（runKernel 统一兜底）。
type IntentNudger struct {
	Store  *db.ExplorationStore // nil = 计数退化为内存语义（放行）
	Intent int64
	LimitN int
	LabelS string
}

func (n *IntentNudger) Increment(ctx context.Context) (int, error) {
	if n.Store == nil {
		return 1, nil
	}
	return n.Store.IncrEmptyTurnNudges(n.Intent)
}

func (n *IntentNudger) Limit() int    { return n.LimitN }
func (n *IntentNudger) Label() string { return n.LabelS }

// kernelDriver carries the route-A loop knobs one agent assembly wires.
// 零值 = 全部不介入（nudge/stop/settlement 都关，纯单 run）。
type kernelDriver struct {
	// stop is the Stop-chain (idleStop → toolLog → guard)，只在自然结束且
	// !stopHookActive 时调用。nil = 无钩子。
	stop harness.HookRunner
	// nudge 是空转续跑预算（worker 由 engine 落 DB 接线；其他 agent nil = 不介入）。
	nudge Nudger
	// settle 是预算终态（max_turns/timeout）的收尾配置；nil 或 Prompt 空 = 不收尾。
	settle *askernel.Settlement
	// checkpoint 观测每次主 run 装配（runner_checkpoints.fingerprint 落库）；
	// P2 起带 checkpointID：装配点把它与指纹绑在同一行上（恢复校验基准），
	// checkpointID 为空 = 该 run 未 armed checkpoint（正常留痕行）。nil = 不落。
	// 指纹六元组现状（评审第 1 轮 #1 后）：agentKey、工具集快照、解锁集种子
	//（fpUnlockSeed 由 worker 从 ToolAugment 的 DeferredInfo.UnlockSeed 接入）
	// 是真实的；promptVersion/mcpDigest/modelProfile 恒空（无仓内来源，两侧
	// 计算一致所以校验语义成立）。
	checkpoint     func(sessionID, checkpointID, fingerprint string)
	fpAgentKey     string
	fpPromptVer    string
	fpUnlockSeed   string
	fpMCPDigest    string
	fpModelProfile string
	// park 是 HITL 停靠钩子（P2-3，engine 注入）：run 以 awaiting_approval 终态
	// 收场后调用——落映射表、注册停靠、等人工决定；返回签名决定数据（内核以
	// ResumeApproval 精确续跑）。ok=false = 停靠被打断（任务终止/ctx 取消），
	// 取消收尾（决定行）由钩子内落库，run 按取消语义交还上层状态机。
	// nil = 不停靠（未接 checkpoint store 的装配，awaiting_approval 不会出现）。
	park func(hitl *askernel.HitlInterrupt) (resume *db.HitlResumeData, ok bool)
}

// runKernel drives one conversation to a final terminal over the kernel session:
// Prompt(input) first, then Continue/RunSettlement per the route-A loop until a
// terminal reason survives. p pumps every run's events into activities; the
// FINAL terminal is emitted once, at the end. Returns the final text, reason
// and error — the worker/planner/chat/mainagent contract, byte-identical to
// the norma era.
func runKernel(ctx context.Context, sess *askernel.Session, input string, d kernelDriver, p *capturePump) (string, harness.TerminalReason, error) {
	fp := sess.FingerprintOnSession(d.fpAgentKey, d.fpPromptVer, d.fpUnlockSeed, d.fpMCPDigest, d.fpModelProfile)
	if d.checkpoint != nil {
		d.checkpoint(sess.SessionID(), "", fp) // 刀④ 语义的装配留痕行（checkpoint_id 空）
	}
	// P2：checkpoint id 与指纹绑同一行（P2-3 恢复校验按该行 fingerprint 比对）。
	if d.checkpoint != nil {
		sess.OnCheckpointID = func(cpID string) {
			d.checkpoint(sess.SessionID(), cpID, fp)
		}
	}

	stopHookActive := false
	reason := harness.ReasonCompleted
	var termErr error

	// P2-3：预挂的恢复指令（重领重建）以 ResumeWithParams 开场——续跑的是原
	// 对话，不追加任何 user 消息；否则普通 Prompt(input)。
	run := sess.StartPlanned(ctx, input)
	for {
		term, drained, rerr := p.drain(run)
		if !drained {
			// consumer stopped mid-stream（norma consumerStopped）：无终态收场。
			return p.finalText, p.reason, rerr
		}
		if rerr != nil {
			// 内核 run 错误（termmap 已映射、pump 已发 result 活动）。
			return p.finalText, p.reason, rerr
		}
		if term == nil {
			return p.finalText, p.reason, nil
		}
		reason = term.Reason
		termErr = term.Err
		// norma「a real turn happened」（query.go:537）：本轮发生过工具回合 →
		// Stop 链与 nudge 重新武装（连续空转只推一次的闸在此复位）。
		if term.Turns > 0 {
			stopHookActive = false
		}

		// P2-3：审批挂起 → 停靠等决定 → 从 checkpoint 精确续跑，循环到真实终态。
		// 同轮多工具先后中断由循环承接（re-interrupt 再次浮出即再停靠）。
		if reason == termmap.AwaitingApproval {
			hitl := sess.Interrupt()
			if d.park == nil || hitl == nil || hitl.CheckpointID == "" {
				// 未接停靠的装配不该出现 awaiting_approval（checkpoint 未 armed
				// 时 guard 走 channel）；防御性收场：按取消语义交还，不停靠。
				p.emitResult(term)
				return term.Text, reason, termErr
			}
			resume, ok := d.park(hitl)
			if !ok || resume == nil {
				// 停靠被打断（任务终止/删除/ctx 取消）：审批的取消收尾（决定行）
				// 已在钩子内落库；run 按取消语义交还上层状态机。
				p.emitResult(&harness.Terminal{
					Reason: harness.ReasonAbortedStreaming, Err: ctx.Err(),
					Usage: term.Usage, Turns: term.Turns, Messages: term.Messages,
				})
				return p.finalText, harness.ReasonAbortedStreaming, ctx.Err()
			}
			// 决定到达（内核在恢复重入点交 guard 验签）：从 checkpoint 精确续跑。
			// denied 的续跑由 guard 以管控文本作 tool_result，run 自然继续。
			run = sess.ResumeApproval(ctx, hitl.CheckpointID, hitl.InterruptID, resume)
			continue
		}

		switch reason {
		case harness.ReasonMaxTurns, harness.ReasonTimeout:
			// 结算同机制（路线 A）：append 收尾词 → 有界重开一次；终态保留原
			// 预算 reason，结算自身的错误吸收（norma settle 分支语义）。
			if prompt := d.settle.PromptFor(reason); prompt != "" {
				maxTurns := d.settle.MaxTurns
				if maxTurns <= 0 {
					maxTurns = 2 // norma settleMaxTurns 默认
				}
				term2, drained2, _ := p.drain(sess.RunSettlement(ctx, prompt, d.settle.DisabledTools, maxTurns))
				if drained2 && term2 != nil {
					// finish(settleReason, nil, asst.Text()) — text from the
					// settle run, error absorbed, reason preserved.
					p.emitResult(&harness.Terminal{
						Reason:   reason,
						Err:      nil,
						Usage:    term.Usage,
						Turns:    term.Turns,
						Messages: term2.Messages,
						Text:     term2.Text,
					})
					return term2.Text, reason, nil
				}
			}
			p.emitResult(term)
			return term.Text, reason, termErr
		}

		if reason != harness.ReasonCompleted {
			// aborted/model_error/…：非自然结束，无 Stop 链、无 nudge、无通知续跑。
			p.emitResult(term)
			return term.Text, reason, termErr
		}

		// 1+2. 自然结束的钩子块（norma query.go:494-496 顺序）：Stop 链（idle-stop
		// 写回收手；guard 无 Stop 钩子，转发为 no-op）与空转 nudge 都只在
		// !stopHookActive 时判定——上一轮刚注入过注入指令的话，本轮空转直接放行收场
		// （连续空转只推一次）；链没决定（prevent/blocking 都没有）才轮到 nudge
		// （norma steerHooks.Stop 的让位顺序）。
		if !stopHookActive {
			if d.stop != nil {
				prevent, blocking, msg := d.stop.Stop(ctx, term.Messages)
				if prevent {
					p.emitResult(&harness.Terminal{
						Reason: harness.ReasonStopHookPrevented, Err: nil,
						Usage: term.Usage, Turns: term.Turns,
						Messages: term.Messages, Text: msg,
					})
					return msg, harness.ReasonStopHookPrevented, nil
				}
				if len(blocking) > 0 {
					for _, b := range blocking {
						sess.AppendUser(b)
					}
					stopHookActive = true
					run = sess.Continue(ctx)
					continue
				}
			}
			// 3. 空转续跑（路线 A 上移）：completed + thinking-only + 预算未达。
			if d.nudge != nil && d.nudge.Limit() > 0 && isThinkingOnlyTurn(term.Messages) {
				n, err := d.nudge.Increment(ctx)
				if err != nil {
					log.Printf("[nudge %s] 计数落库失败，放行续跑（预算护栏不因持久化故障卡任务）: %v", d.nudge.Label(), err)
					n = 1
				}
				if n <= d.nudge.Limit() {
					log.Printf("[nudge %s] 空转回合(仅思考、无正文无工具)，注入续跑指令 (%d/%d)", d.nudge.Label(), n, d.nudge.Limit())
					sess.AppendUser(emptyTurnNudge)
					stopHookActive = true
					run = sess.Continue(ctx)
					continue
				}
				log.Printf("[nudge %s] 空转回合(仅思考、无正文无工具)已达续跑上限 %d，放行收场", d.nudge.Label(), d.nudge.Limit())
			}
		}
		// 4. stopHookActive 复位（norma query.go:496：自然结束即复位，通知续跑的
		//    下一轮钩子重新武装）。
		stopHookActive = false

		// 5. 任务通知：有通知就注入再跑一轮（norma ContinueTaskNotification）。
		if notes := sess.DrainNotifications(); notes != "" {
			sess.AppendUser(notes)
			run = sess.Continue(ctx)
			continue
		}

		// 6. 真正收场（completed）。
		p.emitResult(term)
		return term.Text, reason, termErr
	}
}
