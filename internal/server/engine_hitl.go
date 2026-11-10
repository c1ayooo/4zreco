// engine_hitl.go — P2 HITL 的 engine 半边（docs/Eino深度接入方案-2026-11-05.md
// §4-P2 第 3/4/5/6/7 条）：
//
//   - 停靠注册表（parks，pendingID 为键）：审批中断收场的意图停靠等决定，decide
//     接口经 DeliverHitlDecision 投递签名决定，停靠中的 run 从 checkpoint 精确
//     续跑（内核 ResumeApproval）。决定**先于**停靠注册到达的（同轮多工具乱序
//     决定 / PersistAsk→注册窗口 / 重启前落库）由停靠轮询自查库补投
//     （deliverDecidedHitl）——decide 对已决行 409、reaper 排除已决行，这条自查
//     是那类决定的唯一投递通道。与 channel 模式的差异：等待不在 guard 的工具
//     调用栈里（run 已终态），pause 不 cancel（P2-5 park 语义）。
//   - reaper 扫描器（方案第 4 条）：per-ask goroutine timer 退役；30s 周期扫描
//     仍挂起的审批——到点按 ask 固化策略（audit 快照）落 timeout 决定并投递/
//     清理；孤儿（任务终态、进程硬杀遗留）按 auto_cancel 收尾。
//   - 重领重建（方案第 3 条跨进程半边）：重启后 worker 重领意图，HitlResumeSeed
//     返回至多一条已决定未消费的恢复指令（指纹/版本不匹配按 P2-6 回退并即刻
//     消费钥匙）。
//   - decide 钩子：决定落库 → 按映射表取 checkpoint/interrupt id → 签名投递。
//     无停靠运行（重启后/已收场）= P2-6 劣化：决定照常在库，运行侧重跑可能重审。
package server

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
)

// settingHitlMode 是 hitl_mode 开关的 settings 键（默认 channel 灰度；改动对
// worker 在下一次任务装配时生效、对 chat 在下一次会话装配时生效——与 checkpoint
// 装配同一时点，运行中的 run 不热切）。
const settingHitlMode = "hitl_mode"

// hitlAskDefaultTimeout 是 ask 无固化策略时的平台级等待上限（audit 快照无声明
// 时兜底；judge ask 走自己的配置，规则 ask 带规则自己的 timeout）。0/负值 = 不限。
const hitlAskDefaultTimeout = 6 * time.Hour

// hitlReapInterval 是 reaper 扫描周期（方案第 4 条：goroutine timer → 扫描器）。
const hitlReapInterval = 30 * time.Second

// hitlParkPoll 是停靠循环的任务终态轮询间隔（有界轮询，禁短 sleep 的基线口径：
// 2s 粒度对审批等待是足够低的延迟，CPU 代价可忽略）。
const hitlParkPoll = 2 * time.Second

// hitlPark 是一个审批挂起的停靠点：ch 投递签名决定，done 标记停靠终结。
type hitlPark struct {
	ch   chan *db.HitlResumeData
	done chan struct{}
}

// parks 以 pendingID 为键的停靠注册表。NewEngine 预初始化（任务 worker 与 chat
// 轮两条并发路径都会首次进入）；&Engine{} 字面量（测试）经 sync.Once 兜底——
// 原无锁 check-then-set 在并发首次调用时会各建一个 sync.Map，先 Store 的停靠
// 注册丢失，这里用 Once 消除竞态。
func (e *Engine) parksMap() *sync.Map {
	e.parksOnce.Do(func() {
		if e.parks == nil {
			e.parks = &sync.Map{}
		}
	})
	return e.parks
}

// hitlEnabled 报告平台开关（hitl_mode=eino）。nil db = channel。
func (e *Engine) hitlEnabled() bool {
	if e.m == nil || e.m.pg == nil {
		return false
	}
	v, ok, _ := e.m.pg.GetSetting(settingHitlMode)
	return ok && v == "eino"
}

// deliverDecidedHitl 查库中已有的决定并签名投递（停靠自投递，评审第 1 轮 #1）：
// 决定可以**先于**停靠注册到达——同轮多工具 ask 操作员先决了还没停靠的那个
// （decide 对已决行 409 不会再投递）、PersistAsk 落库到 parksMap.Store 之间的
// decide 窗口、重启前落库的决定。decide/reaper 都不会补投（前者对已决行拒绝、
// 后者的扫描排除已决行），park 侧自查库是唯一通道。返回 (nil,false) = 库中
// 还没有决定。
func (e *Engine) deliverDecidedHitl(pendingID int64, taskID string) (*db.HitlResumeData, bool) {
	pg := e.m.pg
	decisionID, decision, action, ok, err := pg.HitlDecision(pendingID)
	if err != nil || !ok {
		return nil, false
	}
	allowed := db.HitlAllowedFromDecision(decision, action)
	resume := pg.SignHitlResume(pendingID, decisionID, allowed)
	// 钥匙一次性：自投递即消费（重放同一决定被钥匙删除挡住）。
	_ = pg.ConsumeHitlMapping(pendingID)
	log.Printf("[hitl] 审批 #%d 决定已先行落库(%s)，停靠自投递（task %s）", pendingID, decision, taskID)
	return resume, true
}

// hitlParkHook 是注入 worker 的停靠钩子（KernelRunParams.Park）：落映射 → 注册
// 停靠 → 等决定 → 返回签名恢复数据。等待通道有三：decide 的 DeliverHitlDecision
// 投递、轮询自查库中已有决定（评审第 1 轮 #1：决定先于停靠注册到达时永不投递
// 的补口）、任务终态打断。停靠期间任务终止/删除 → (nil,false) 并把审批按取消
// 收尾（决定行）；**暂停不打断**（P2-5 park 语义：审批挂起跨暂停存活，决定后
// 原调用从 checkpoint 续跑）。
func (e *Engine) hitlParkHook(taskID int64, hitl *askernel.HitlInterrupt) (*db.HitlResumeData, bool) {
	pg := e.m.pg
	tid := strconv.FormatInt(taskID, 10)
	if err := pg.SaveHitlMapping(hitl.PendingID, hitl.CheckpointID, hitl.InterruptID, tid); err != nil {
		log.Printf("[hitl] task %s 审批 #%d 映射落库失败: %v", tid, hitl.PendingID, err)
		return nil, false
	}
	park := &hitlPark{ch: make(chan *db.HitlResumeData, 1), done: make(chan struct{})}
	e.parksMap().Store(hitl.PendingID, park)
	defer func() {
		e.parksMap().Delete(hitl.PendingID)
		close(park.done)
	}()
	log.Printf("[hitl] task %s 审批 #%d 已挂起（工具 %s），等待人工决定", tid, hitl.PendingID, hitl.Tool)
	// 注册后先查一次库中已有决定（决定先于停靠注册到达的窗口）。
	if resume, ok := e.deliverDecidedHitl(hitl.PendingID, tid); ok {
		return resume, true
	}
	for {
		select {
		case resume := <-park.ch:
			// 钥匙一次性：投递即消费（重放同一决定被钥匙删除挡住）。
			_ = pg.ConsumeHitlMapping(hitl.PendingID)
			return resume, true
		case <-time.After(hitlParkPoll):
			// 任务终止/删除 → 停靠被打断，审批按取消收尾（决定行）。
			// 暂停不打断（P2-5 park 语义）。
			if e.IsDeleting(tid) || isTerminalStatus(e.m.TaskStatus(tid)) {
				e.settleHitl(db.PendingHitlApproval{
					PendingID: hitl.PendingID, CheckpointID: hitl.CheckpointID,
					InterruptID: hitl.InterruptID, TaskID: tid,
				}, "auto_cancel", false, "工作已取消")
				return nil, false
			}
			// 库中已有决定的补投（乱序决定/重启前落库的决定）。
			if resume, ok := e.deliverDecidedHitl(hitl.PendingID, tid); ok {
				return resume, true
			}
		}
	}
}

// ChatHitlPark 是聊天会话的审批停靠钩子（ChatAgent.SetHitl 接线）：与任务停靠
// 共用同一 pendingID 注册表——decide 的 DeliverHitlDecision 对两种运行一视同仁。
// 聊天运行阻塞在此等待（与 channel 模式同观感），决定后从 checkpoint 精确续跑；
// 请求 ctx 取消（客户端断开）按取消收尾。与任务停靠同样轮询自查库中已有决定
// （评审第 1 轮 #1 同一窗口）。聊天无重领重建：进程重启后的孤儿由 reaper 收尾
// （P2-6 劣化，用户重新提问）。
func (e *Engine) ChatHitlPark(ctx context.Context, hitl *askernel.HitlInterrupt) (*db.HitlResumeData, bool) {
	pg := e.m.pg
	if err := pg.SaveHitlMapping(hitl.PendingID, hitl.CheckpointID, hitl.InterruptID, ""); err != nil {
		log.Printf("[hitl] chat 审批 #%d 映射落库失败: %v", hitl.PendingID, err)
		return nil, false
	}
	park := &hitlPark{ch: make(chan *db.HitlResumeData, 1), done: make(chan struct{})}
	e.parksMap().Store(hitl.PendingID, park)
	defer func() {
		e.parksMap().Delete(hitl.PendingID)
		close(park.done)
	}()
	log.Printf("[hitl] chat 审批 #%d 已挂起（工具 %s），等待人工决定", hitl.PendingID, hitl.Tool)
	if resume, ok := e.deliverDecidedHitl(hitl.PendingID, ""); ok {
		return resume, true
	}
	for {
		select {
		case resume := <-park.ch:
			_ = pg.ConsumeHitlMapping(hitl.PendingID)
			return resume, true
		case <-ctx.Done():
			e.settleHitl(db.PendingHitlApproval{
				PendingID: hitl.PendingID, CheckpointID: hitl.CheckpointID,
				InterruptID: hitl.InterruptID,
			}, "auto_cancel", false, "工作已取消")
			return nil, false
		case <-time.After(hitlParkPoll):
			// 库中已有决定的补投（决定先于停靠注册到达）。
			if resume, ok := e.deliverDecidedHitl(hitl.PendingID, ""); ok {
				return resume, true
			}
		}
	}
}

// DeliverHitlDecision 由 decide 接口在决定落库后调用：按映射表取 checkpoint /
// interrupt id，签名决定数据投递给停靠中的 run。返回 (delivered, requiresRerun)：
// delivered = 停靠运行已接手（内核将从 checkpoint 续跑）；requiresRerun = 无停
// 靠运行（channel 模式旧记录/进程重启后运行已不在/已收场）——决定照常在库，
// 运行侧按 P2-6 劣化（重跑可能重审），不阻塞审批操作。
func (e *Engine) DeliverHitlDecision(pendingID int64, allowed bool) (bool, bool) {
	if e.m == nil || e.m.pg == nil {
		return false, true
	}
	pg := e.m.pg
	checkpointID, interruptID, _, err := pg.HitlMapping(pendingID)
	if err != nil {
		log.Printf("[hitl] 审批 #%d 映射读取失败: %v", pendingID, err)
		return false, true
	}
	if checkpointID == "" || interruptID == "" {
		return false, true // channel 模式或已消费：无恢复路径
	}
	decisionID, ok, err := pg.LastInterceptDecisionID(pendingID)
	if err != nil || !ok {
		log.Printf("[hitl] 审批 #%d 决定行缺失，无法签名投递", pendingID)
		return false, true
	}
	resume := pg.SignHitlResume(pendingID, decisionID, allowed)
	if v, ok := e.parksMap().Load(pendingID); ok {
		park := v.(*hitlPark)
		select {
		case park.ch <- resume:
			return true, false
		case <-park.done:
			return false, true
		}
	}
	// 无停靠运行：进程重启后的孤儿钥匙。保留映射——worker 重领该意图时经
	// HitlResumeSeed 消费（重领重建）；指纹/版本回退在 seed 内即刻消费钥匙，
	// 意图收场由 CheckpointDrop（DeleteCheckpointsBySession）连带清理。
	log.Printf("[hitl] 审批 #%d 无停靠运行（重领重建待命或 P2-6 回退）", pendingID)
	return false, true
}

// hitlResumeSeed 是 worker 重领重建的种子（KernelRunParams.HitlResumeSeed）：
// 返回该会话至多一条可续跑指令（已决定、钥匙未消费、checkpoint 校验通过）。
// 只取第一条且只消费它的钥匙（评审第 1 轮 #1c）：worker 一次只 PlanResume 一条，
// 一次性全消费会把余下指令连同钥匙一起丢弃——其 re-interrupt 再停靠时决定已在
// 库而无人投递。余下挂起由续跑后的停靠自投递承接（deliverDecidedHitl 轮询查库）；
// 钥匙留在原处也维持 pause=park 语义（P2-5）直到被消费或意图收场清理
// （CheckpointDrop → DeleteCheckpointsBySession 连带删映射）。
// 指纹/版本校验在此做（P2-3）——不匹配按 P2-6 回退：立即消费钥匙（决定已在库，
// 运行侧按重跑收尾；钥匙滞留会把该任务的 Pause 短路成空操作），正常重跑可能重审。
func (e *Engine) hitlResumeSeed(sessionID, fingerprint string) []askernel.ResumeDirective {
	pg := e.m.pg
	rows, err := pg.DecidedHitlResumesForSession(sessionID)
	if err != nil {
		log.Printf("[hitl] 会话 %s 待续跑审批查询失败: %v", sessionID, err)
		return nil
	}
	for _, r := range rows {
		// 版本/指纹校验（P2-6）：checkpoint 版本不兼容或装配指纹漂移 → 不续跑，
		// 钥匙即刻消费（决定照常在库，不阻塞审批操作）。
		_, version, ok, err := pg.HitlCheckpointMeta(r.CheckpointID)
		if err != nil || !ok || version != db.CheckpointVersion {
			log.Printf("[hitl] 审批 #%d checkpoint 不可用/版本不匹配(%d)，P2-6 回退（需重跑）", r.PendingID, version)
			_ = pg.ConsumeHitlMapping(r.PendingID)
			continue
		}
		if r.Fingerprint != "" && r.Fingerprint != fingerprint {
			log.Printf("[hitl] 审批 #%d 装配指纹不匹配，P2-6 回退（需重跑）", r.PendingID)
			_ = pg.ConsumeHitlMapping(r.PendingID)
			continue
		}
		allowed := db.HitlAllowedFromDecision(r.Decision, r.Action)
		resume := pg.SignHitlResume(r.PendingID, r.DecisionID, allowed)
		// 钥匙一次性：重领消费。续跑失败（载荷损坏）时 run 按错误收场重跑——
		// 决定已在库，不会被二次消费重放。
		if err := pg.ConsumeHitlMapping(r.PendingID); err != nil {
			log.Printf("[hitl] 审批 #%d 钥匙消费失败: %v", r.PendingID, err)
			continue
		}
		return []askernel.ResumeDirective{{
			CheckpointID: r.CheckpointID, InterruptID: r.InterruptID, Resume: resume,
		}}
	}
	return nil
}

// StartHitlReaper launches the reaper scanner goroutine（进程启动一次）。ctx 取
// 消即退出。channel 模式的挂起（无映射）不归它管——进程内 timer/兜底上限照旧。
func (e *Engine) StartHitlReaper(ctx context.Context) {
	go func() {
		tick := time.NewTicker(hitlReapInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				e.reapHitlOnce()
			}
		}
	}()
}

// reapHitlOnce 扫描一轮：超时未决的 HITL 审批按固化策略落 timeout 决定并投递/
// 清理；孤儿（任务终态）按取消收尾。
func (e *Engine) reapHitlOnce() { e.reapHitlAt(time.Now()) }

// reapHitlAt 是 reapHitlOnce 的时钟注入形态（测试用）。
func (e *Engine) reapHitlAt(now time.Time) {
	if e.m == nil || e.m.pg == nil {
		return
	}
	rows, err := e.m.pg.PendingHitlApprovals()
	if err != nil {
		return
	}
	for _, r := range rows {
		// 孤儿：任务已终态 → 取消收尾（进程硬杀遗留的挂起不再积压）。
		if r.TaskID != "" && isTerminalStatus(e.m.TaskStatus(r.TaskID)) {
			e.settleHitl(r, "auto_cancel", false, "工作已取消")
			continue
		}
		// 超时按 ask 固化值优先（audit 快照），无声明用平台级兜底。
		timeout := hitlAskDefaultTimeout
		if r.AskTimeoutSeconds > 0 {
			timeout = time.Duration(r.AskTimeoutSeconds) * time.Second
		}
		if now.Sub(r.CreatedAt) > timeout {
			allow := r.AskTimeoutAction == "allow"
			e.settleHitl(r, "timeout", allow, "审批超时，按超时策略处理")
		}
	}
}

// settleHitl 落一条自动决定（timeout/auto_cancel）并唤醒停靠运行：恢复数据用
// 真实决定行签名——deny 也经 guard 验签以「人工拒绝」语义拦截（而不是「校验
// 失败」）。无停靠运行时清 checkpoint（P2-6 劣化：审批历史保留，运行侧重跑）。
func (e *Engine) settleHitl(r db.PendingHitlApproval, source string, allow bool, reason string) {
	pg := e.m.pg
	// 与 channel 模式的 timer 收口同形：超时落独立决定值 timeout（allow/deny 由
	// action 承载固化策略），取消落 denied。
	decision := "denied"
	if source == "timeout" {
		decision = "timeout"
	}
	action := "deny"
	if allow {
		action = "allow"
	}
	ok, err := pg.ResolveIntercept(r.PendingID, decision, action, reason, "", source)
	if err != nil || !ok {
		return // 已被人工决定/落库失败
	}
	decisionID, hasID, _ := pg.LastInterceptDecisionID(r.PendingID)
	if !hasID {
		return
	}
	resume := pg.SignHitlResume(r.PendingID, decisionID, allow)
	if v, ok := e.parksMap().Load(r.PendingID); ok {
		select {
		case v.(*hitlPark).ch <- resume:
		case <-time.After(time.Second):
		}
		_ = pg.ConsumeHitlMapping(r.PendingID)
		log.Printf("[hitl] 审批 #%d 已按 %s 收尾并唤醒停靠运行", r.PendingID, source)
		return
	}
	// 无停靠运行（重启孤儿/已收场）：清 checkpoint 与钥匙，审批历史保留。
	if r.CheckpointID != "" {
		_ = pg.DeleteCheckpoint(context.Background(), r.CheckpointID)
	}
	_ = pg.ConsumeHitlMapping(r.PendingID)
	log.Printf("[hitl] 审批 #%d 已按 %s 收尾（无停靠运行，运行侧需重跑）", r.PendingID, source)
}

// HasHitlPendingCheckpoint reports whether a task has unconsumed hitl mappings
// （P2-5 暂停=park 的判定点：审批挂起的 run 不 cancel——interrupt 已 checkpoint，
// 决定后原调用续跑；非审批暂停保持 cancel 语义）。nil db = false。
func (e *Engine) HasHitlPendingCheckpoint(taskID string) bool {
	if e.m == nil || e.m.pg == nil {
		return false
	}
	has, err := e.m.pg.HasHitlPendingCheckpoint(taskID)
	return err == nil && has
}
