package server

// 自主推进（Autopilot，移植自上游 0.4.68）：一键把任务交给系统自己推到完成。
//
// 三条腿：
//  1. 审批照常生效（不自动放行审批/拦截；提示词要求 agent 绕开需要人工审批的动作，
//     用等价的小验证继续推进）；
//  2. 停滞看门狗：autopilotTick 每 60s 扫一次「自主推进中」的任务，长时间无进展就
//     唤醒 planner 重规划，连续无进展则延长 deadline（次数落库、有上限）；
//  3. 完成优先：auto_finish 的 idle/coverage 判据对 autopilot 任务不生效（见
//     suppressAutopilotSettle），只有 goal_met（或续杯后仍有活干时被推回）与
//     硬上限（timeout / A8 no_result）能收尾。
//
// 关键事实（避免踩坑，沿上游注释）：
//   - engine.LastActivity 会被 planner 心跳刷新，不能用来判断停滞；这里用
//     「图上事实/漏洞/资产计数」做进度指纹（与 auto_finish 的 idle 口径一致）。
//   - 停滞唤醒必须用独立的 trigger kind（autopilot_stall），不能复用 hint——
//     hint 会被 freshDirection 当作新方向并重置 idle 计数，反过来污染收尾判定。
//   - 被抑制的收尾原因必须从 Task 上清掉并让本轮继续规划，否则 plannerLoop 会在
//     「有挂起收尾」分支里无条件 return，把整个任务卡死。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

const (
	settingAutopilotDefault       = "autopilot_default"
	settingAutopilotStallMinutes  = "autopilot_stall_minutes"
	settingAutopilotMaxExtensions = "autopilot_max_extensions"
	settingAutopilotExtendWaves   = "autopilot_extend_waves"

	// 新任务默认开自主推进。与上游不同处：上游只回显不生效，这里在
	// Manager.CreateTaskWithOptions 真正按它初始化 tasks.autopilot——
	// 一个改了没效果的设置键比没有更糟。
	defaultAutopilotDefault = false

	defaultAutopilotStallMinutes = 8
	// deadline 延长次数上限（默认 10）。relentless 的语义是「只要还有活就一直干」，
	// 停在 2 会让长任务半路被 timeout 收掉；仍受 ExtendTaskDeadline 守卫、可在设置页调 0–10。
	defaultAutopilotMaxExtensions = 10

	// 延长一次至少 15 分钟；单次上限 6 小时，防止一次拉到天亮。
	autopilotExtendFloor = 15 * time.Minute
	autopilotExtendCap   = 6 * time.Hour

	// 连续多少次停滞唤醒无进展后触发一次预算延长。
	autopilotNudgesBeforeExtend = 2

	// goal_met 续杯：默认最多 10 波；deadline 到点前 5 分钟余量内不再续。
	defaultAutopilotExtendWaves  = 10
	autopilotExtendDeadlineGrace = 5 * time.Minute
)

type autopilotConfig struct {
	Default       bool
	StallMinutes  int
	MaxExtensions int
}

// autopilotConfigFromPG 读全局设置并夹逼到安全范围；读库失败用默认值，
// 绝不能因为设置查询失败让看门狗停摆。
func autopilotConfigFromPG(pg *db.DB) autopilotConfig {
	c := autopilotConfig{
		Default:       defaultAutopilotDefault,
		StallMinutes:  defaultAutopilotStallMinutes,
		MaxExtensions: defaultAutopilotMaxExtensions,
	}
	if pg == nil {
		return c
	}
	c.Default = pg.GetBool(settingAutopilotDefault, defaultAutopilotDefault)
	if n, ok := settingInt(pg, settingAutopilotStallMinutes); ok {
		c.StallMinutes = clampInt(n, 3, 120)
	}
	if n, ok := settingInt(pg, settingAutopilotMaxExtensions); ok {
		c.MaxExtensions = clampInt(n, 0, 10)
	}
	return c
}

// autopilotExtendWavesFromPG 读 goal_met 续杯波次上限（默认 10，0=关闭，>10 夹到 10）。
func autopilotExtendWavesFromPG(pg *db.DB) int {
	if pg == nil {
		return defaultAutopilotExtendWaves
	}
	n, ok := settingInt(pg, settingAutopilotExtendWaves)
	if !ok {
		return defaultAutopilotExtendWaves
	}
	if n < 0 {
		return 0
	}
	if n > 10 {
		return 10
	}
	return n
}

// autopilotTrack 是单任务的看门狗内存状态（重启清零，可接受）。
type autopilotTrack struct {
	lastProgressAt time.Time
	lastNudgeAt    time.Time
	nudges         int
	baseline       int64 // facts+findings+assets 指纹
}

// trackFor 取/建某任务的看门狗状态（仅 tick 协程访问，无需额外加锁）。
func (e *Engine) trackFor(taskID string) *autopilotTrack {
	v, _ := e.autoTrack.LoadOrStore(taskID, &autopilotTrack{})
	return v.(*autopilotTrack)
}

// autopilotTick 是一次完整扫描。now 可注入，便于单测。
// 挂点：Scheduler.Run 的 5s tick（internal/server/scheduler.go），由调用方节流到 60s。
func (e *Engine) autopilotTick(now time.Time) {
	pg := e.m.pg
	if pg == nil {
		return
	}
	states, err := pg.AutopilotTaskStates()
	if err != nil {
		log.Printf("[autopilot] 扫描任务失败: %v", err)
		return
	}
	cfg := autopilotConfigFromPG(pg)
	stall := time.Duration(cfg.StallMinutes) * time.Minute

	for id, st := range states {
		t, ok := e.m.Task(id)
		if !ok || t == nil || !t.AutopilotEnabled() {
			e.autoTrack.Delete(id)
			continue
		}
		// 预算只剩不到一半时**提前**延长：在跑 run 的墙钟预算是启动时快照的，
		// 真到点再延长救不回已把 MaxDuration 夹到接近 0 的那批 worker（它们会照常
		// 进收尾）。提前延长的次数同样受 autopilot_extensions 守卫。
		if st.Unmet() && cfg.MaxExtensions > 0 && t.TimeoutSeconds > 0 {
			if dl := t.lifecycleSnapshot().DeadlineAt; dl > 0 {
				budget := time.Duration(t.TimeoutSeconds) * time.Second
				if now.Sub(time.Unix(int64(dl), 0)) < -budget/2 { // 距 deadline 不足半份预算
					e.tryAutopilotExtend(t, cfg)
				}
			}
		}
		// 有在跑意图/LLM 调用时不再一刀切跳过——慢模型或卡住的 worker 可以长时间
		// 「在跑但零写回」。现在：无在跑时按 stall 窗口判定；有在跑时窗口放宽到 2 倍
		// （尊重长扫描），planner 只读态势补派/纠偏，不打断 worker。
		if !e.Started(id) || e.IsDeleting(id) || e.isSettling(id) {
			continue
		}
		if e.IsPaused(id) {
			continue
		}
		inflight := e.inflightCount(id) > 0 || e.ActiveLLMCalls(id) > 0
		if !st.Unmet() { // 目标已全部达成：看门狗退场（续杯由 goal_met 路径负责）
			e.autoTrack.Delete(id)
			continue
		}
		// 进度指纹 = 事实 + 漏洞 + 资产。纯事实数会被「复述/拆碎」灌水；新资产与
		// 新漏洞才是真实推进。
		progress := st.Facts + st.Findings + st.Assets
		tr := e.trackFor(id)
		if tr.lastProgressAt.IsZero() || progress > tr.baseline {
			tr.baseline = progress
			tr.lastProgressAt = now
			tr.nudges = 0
			continue
		}
		if now.Sub(tr.lastProgressAt) < stall {
			continue
		}
		// 有 worker 在跑时把停滞窗口放宽到 2 倍——正在跑的长扫描不误判；
		// 但「在跑却超过两个窗口零写回」说明它们空转/卡死，必须唤醒 planner。
		if inflight && now.Sub(tr.lastProgressAt) < 2*stall {
			continue
		}
		if !tr.lastNudgeAt.IsZero() && now.Sub(tr.lastNudgeAt) < stall {
			continue // 冷却：一个停滞窗口只唤醒一次
		}

		detail := fmt.Sprintf("已 %d 分钟没有新事实/新漏洞/新资产，目标尚未全部达成（%d/%d）。立即派下一步或换方向；禁止以「探索完毕/信息不足」收场。",
			int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		if inflight {
			detail = fmt.Sprintf("已 %d 分钟没有新事实/新漏洞/新资产（仍有 worker 在跑但没有产出写回），目标尚未全部达成（%d/%d）。检查在跑意图是否空转：立即补充方向/给在跑意图纠偏，或派下一步；禁止以「探索完毕/信息不足」收场。",
				int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		}
		t.NotifyAutopilotStall(detail)
		tr.lastNudgeAt = now
		tr.nudges++
		_ = pg.InsertAutopilotEvent(id, "stall_nudge", detail)
		e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text",
			Summary: "自主推进：检测到停滞，已唤醒 planner 重规划"})
		log.Printf("[autopilot] task %s 停滞 %s 无进展 → 唤醒 planner（第 %d 次）",
			id, now.Sub(tr.lastProgressAt).Round(time.Minute), tr.nudges)

		// 连续唤醒仍无进展 → 延长预算（有上限、次数落库、单次有封顶）。
		if tr.nudges >= autopilotNudgesBeforeExtend {
			if e.tryAutopilotExtend(t, cfg) {
				tr.lastProgressAt = now // 给新预算一个完整窗口
				tr.nudges = 0
			}
		}
	}
}

// tryAutopilotExtend 把任务的绝对 deadline 往后推。返回 true 表示已延长。
//
// 只对「有时间预算且已盖章 deadline」的任务生效：没有 deadline 的任务本来就不会
// 超时，无需延长。次数由 DB 的 autopilot_extensions 守卫，跨重启也不会无限延长。
func (e *Engine) tryAutopilotExtend(t *Task, cfg autopilotConfig) bool {
	if t == nil || cfg.MaxExtensions <= 0 || t.TimeoutSeconds <= 0 {
		return false
	}
	old := t.lifecycleSnapshot().DeadlineAt
	if old <= 0 {
		return false
	}
	// 按整份任务预算延长：半预算只够覆盖一次长链的中段，任务很快再次贴边。
	ext := time.Duration(t.TimeoutSeconds) * time.Second
	if ext < autopilotExtendFloor {
		ext = autopilotExtendFloor
	}
	if ext > autopilotExtendCap {
		ext = autopilotExtendCap
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false
	}
	dl, used, ok, err := e.m.pg.ExtendTaskDeadline(id, int(ext.Seconds()), cfg.MaxExtensions)
	if err != nil {
		log.Printf("[autopilot] task %s 延长 deadline 失败: %v", t.ID, err)
		return false
	}
	if !ok {
		return false
	}
	newDeadline := dl.Unix()
	t.updateLifecycle(func(s *taskLifecycleState) { s.DeadlineAt = newDeadline })
	detail := fmt.Sprintf("目标未达成且连续无进展，deadline 自动延长 %s（第 %d/%d 次）→ %s",
		ext.Round(time.Minute), used, cfg.MaxExtensions, dl.Format("15:04:05"))
	_ = e.m.pg.InsertAutopilotEvent(t.ID, "deadline_extended", detail)
	e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text", Summary: "自主推进：" + detail})
	log.Printf("[autopilot] task %s %s", t.ID, detail)
	return true
}

// suppressAutopilotSettle 判断某收尾原因是否应被自主推进抑制。
// 只抑制「没进展」类判据；goal_met / timeout / no_result（A8 硬上限，与自主推进
// 互补不冲突）照旧。
func suppressAutopilotSettle(t *Task, reason string) bool {
	if t == nil || !t.AutopilotEnabled() {
		return false
	}
	switch reason {
	case "auto_idle", "auto_coverage", "auto_rounds":
		// auto_rounds 是「规划轮数上限」成本硬上限，但在自主推进模式下用户明确要求
		// 一直推进，不该用它收尾；真正的兜底仍是任务 deadline（延长有上限）。
		return true
	}
	return false
}

// autopilotWaveKey 是某任务已用续杯波次的 settings 键。
func autopilotWaveKey(taskID int64) string {
	return fmt.Sprintf("autopilot_wave_%d", taskID)
}

// maybeExtendAutopilot 是 goal_met 续杯（autopilot_extend_waves）。
//
// 现网问题（上游 2026-11-07 任务 #5）：目标被逐个 prove_goal 后 goal_met 触发
// settle，任务就 done——虽然还有范围内资产没测、高危漏洞只做到「验证存在」。
// 自主推进的本意是「一直打到没得打」，而不是「把这批固定目标打完就收」。
//
// 续杯规则（全部满足才续）：
//  1. 任务开着 autopilot，且 autopilot_extend_waves（默认 10，0=关闭）没用完；
//  2. deadline 还没到（留 5 分钟余量）；
//  3. 确有活可干：范围内还有未测资产，或已登记 high/critical 漏洞。
//
// 续杯动作：自动追加 1 条下一层目标（续杯阶梯按已用波次推进），唤醒 planner；
// 本轮不取消在跑 worker、不 settle。返回 true 表示已续杯（调用方应跳过本轮收尾）。
func (e *Engine) maybeExtendAutopilot(t *Task) bool {
	if t == nil || !t.AutopilotEnabled() || e.m.pg == nil {
		return false
	}
	pg := e.m.pg
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false
	}
	waves := autopilotExtendWavesFromPG(pg)
	if waves <= 0 {
		return false
	}
	waveKey := autopilotWaveKey(taskID)
	used, _ := settingInt(pg, waveKey)
	if used >= waves {
		return false
	}
	if dl := t.lifecycleSnapshot().DeadlineAt; dl > 0 && time.Now().Add(autopilotExtendDeadlineGrace).Unix() >= dl {
		return false
	}

	// 未测资产：范围内（含来源任务合并视图）分母减已测。
	untested := 0
	if as := e.m.assets; as != nil {
		if cov, err := as.TaskCoverageWithSources(taskID); err == nil && cov != nil {
			untested = cov.Denominator - cov.Tested
			if untested < 0 {
				untested = 0
			}
		}
	}
	var highFindings int
	_ = pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND severity IN ('critical','high')`, taskID).Scan(&highFindings)
	if untested == 0 && highFindings == 0 {
		return false
	}

	// 进度闸：上一波续杯之后没有新增 fact/finding，说明「续了也没产出」，不再续——
	// 这是「不达目的不罢休」与「无限空转」的分界线。只在「没有未测资产」时启用：
	// 只要范围内还有没测过的资产，就属于「还有一点能做的」——应该换打法而不是收工。
	var facts, findings int64
	_ = pg.QueryRow(`SELECT
	  (SELECT count(*) FROM exploration_nodes WHERE kind='fact' AND exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)),
	  (SELECT count(*) FROM findings WHERE task_id=$1)`, taskID).Scan(&facts, &findings)
	markKey := fmt.Sprintf("autopilot_ext_mark_%d", taskID)
	mark := fmt.Sprintf("f%d|n%d", facts, findings)
	if used > 0 && untested == 0 {
		if prev, ok, _ := pg.GetSetting(markKey); ok && prev == mark {
			return false
		}
	}
	_ = pg.SetSetting(markKey, mark)

	// 续杯阶梯：每次续杯推进一层，避免反复加同一条「高危利用链」目标后又被判完成。
	ladder := []string{
		"对已登记的高危/严重漏洞完成利用链与影响面证明：不破坏业务的前提下做取数/权限提升/横向可达性验证，每条补一份影响证明（请求-响应或命令输出 + 影响描述）",
		"把已撕开的数据面打到最大：对已证明可达的接口做分页/时间窗/导出全量取证（只读、限速、逐批落盘并登记哈希）",
		"同族扩散：把已验证的机理应用到同集群/同框架/同批次的其他资产（同 C 段、同分发域、同后台模板），逐条验证并出报告",
		"未覆盖面清零：对范围内仍未测试的资产按漏洞矩阵逐类补测（未授权/越权/SQLi/XSS/SSRF/上传/命令执行/弱口令/CVE/逻辑）",
		"深挖已确认入口的下一层：从当前权限/凭据出发尝试横向、持久化可达性与更高价值数据（授权边界内，只读优先）",
	}
	stage := ladder[len(ladder)-1]
	if used < len(ladder) {
		stage = ladder[used]
	}
	txt := fmt.Sprintf("%s（续杯第 %d 波：已登记高危 %d 条、未测资产 %d 个）", stage, used+1, highFindings, untested)

	if _, err := t.Store.AddGoal(map[string]any{"text": txt}, "autopilot"); err != nil {
		log.Printf("[autopilot] task %d 续杯目标写入失败: %v", taskID, err)
		return false
	}
	_ = pg.SetSetting(waveKey, fmt.Sprintf("%d", used+1))
	_ = pg.InsertAutopilotEvent(t.ID, "extend_goals",
		fmt.Sprintf("目标达成后续杯第 %d/%d 波：未测资产 %d，高危漏洞 %d，追加 1 条下一层目标",
			used+1, waves, untested, highFindings))
	log.Printf("[autopilot] task %d 目标达成 → 续杯第 %d/%d 波（未测资产 %d，高危 %d，新增目标 1 条）",
		taskID, used+1, waves, untested, highFindings)
	e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text",
		Summary: fmt.Sprintf("自主推进：目标达成后续杯第 %d/%d 波（未测资产 %d、高危漏洞 %d），已追加下一层目标",
			used+1, waves, untested, highFindings)})
	return true
}

// maybePendingSettleAutopilot 在挂起收尾执行前给自主推进一个否决窗口：
// 抑制「没进展」类判据并清掉登记（否则 plannerLoop 的挂起收尾分支会无条件 return，
// 把任务卡死）；goal_met 时先尝试续杯——续上了就撤销收尾继续规划。返回 true 表示
// 本次收尾被否决。暂停/删除/收尾中/终态任务不否决——维持既有语义。
func (e *Engine) maybePendingSettleAutopilot(t *Task, reason string) bool {
	if t == nil || !t.AutopilotEnabled() || e.m.pg == nil || t.Store == nil {
		return false
	}
	if e.IsPaused(t.ID) || e.IsDeleting(t.ID) || e.isSettling(t.ID) || isTerminalStatus(t.lifecycleSnapshot().Status) {
		return false
	}
	if reason == "goal_met" {
		if e.maybeExtendAutopilot(t) {
			t.clearSettle()
			t.Notify() // 新目标已落图，唤醒 planner 立即消化
			log.Printf("[autopilot] task %s 忽略收尾判据 %s，续杯后继续规划", t.ID, reason)
			return true
		}
		return false
	}
	if suppressAutopilotSettle(t, reason) {
		t.clearSettle()
		if err := e.m.pg.ResetTaskProgress(t.ID); err != nil {
			log.Printf("[autopilot] task %s 重置进度失败: %v", t.ID, err)
		}
		t.Notify() // 撤销收尾后唤醒 planner 继续规划
		log.Printf("[autopilot] task %s 忽略收尾判据 %s，继续规划", t.ID, reason)
		return true
	}
	return false
}

// intentQueueLimit helpers —— 派发节流（v0.4.68 移植）。

// settingIntentQueueLimit：本轮新增上限的基准阈值（默认 8），0=关闭节流。
const (
	settingIntentQueueLimit = "intent_queue_limit"
	defaultIntentQueueLimit = 8
)

// intentQueueLimitFromPG 读设置并夹逼 0–200；读失败回落默认 8——设置查询失败
// 绝不能把节流变成硬故障。
func intentQueueLimitFromPG(pg *db.DB) int {
	if pg == nil {
		return defaultIntentQueueLimit
	}
	if v, ok := settingInt(pg, settingIntentQueueLimit); ok {
		return clampInt(v, 0, 200)
	}
	return defaultIntentQueueLimit
}

// effectiveIntentThreshold 把设置值折算成实际阈值 T = max(limit, 2*workers)：
// 保证 open 队列至少能缓冲一轮并发完成；0（关闭）保持 0。
func effectiveIntentThreshold(limit, workers int) int {
	if limit <= 0 {
		return 0
	}
	if 2*workers > limit {
		return 2 * workers
	}
	return limit
}

// intentQueueBudget 返回（生效阈值，当前全局 worker 数），注入给 planner 的派发节流。
func (s *Server) intentQueueBudget() (int, int) {
	workers := s.m.Workers()
	return effectiveIntentThreshold(intentQueueLimitFromPG(s.m.pg), workers), workers
}

// intentBacklogFull 判断单任务未完成意图是否已达派发上限（心跳轮跳过用：
// 积压满时再规划只会被 add_intent 拒绝、白烧 token）。边沿触发不受影响。
func (e *Engine) intentBacklogFull(t *Task) bool {
	if e == nil || e.m == nil || t == nil || t.Store == nil {
		return false
	}
	limit := effectiveIntentThreshold(intentQueueLimitFromPG(e.m.pg), e.m.Workers())
	if limit <= 0 {
		return false
	}
	active, err := t.Store.CountActiveIntents()
	return err == nil && active >= limit
}

// taskAutopilot 开启/关闭单任务的「自主推进」（P4-4，POST /api/tasks/{id}/autopilot）。
//
// enabled=true + resume=true 就是「一键推进」：暂停/排队中的任务会被立即恢复并唤醒
// planner；已经结束的任务拒绝（要先复跑意图或新增目标把它救活），避免界面暗示一个
// 已经收尾的任务还能被这个按钮续命。
func (s *Server) taskAutopilot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.m.Task(id)
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
		Resume  bool  `json:"resume"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
		writeErr(w, 400, "enabled 必填（true|false）")
		return
	}
	ls := t.lifecycleSnapshot()
	if *req.Enabled && req.Resume && isTerminalStatus(ls.Status) {
		writeErr(w, 409, "任务已结束，请先复跑意图或新增目标恢复后再开启自主推进")
		return
	}
	if _, err := s.m.SetTaskAutopilot(id, *req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resumed := false
	status := ls.Status
	if cur := t.lifecycleSnapshot(); *req.Enabled && req.Resume && (cur.Paused || cur.Queued) {
		if _, err := s.applyTaskControl(t, "resume"); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		resumed = true
		status = "running"
	}
	// 已在跑的任务：开关切换后立即唤醒一轮规划/执行，让新语义当场生效。
	if *req.Enabled && !resumed && !isTerminalStatus(t.lifecycleSnapshot().Status) && !t.lifecycleSnapshot().Paused {
		t.Notify()
	}
	writeJSON(w, 200, map[string]any{"id": id, "enabled": *req.Enabled, "resumed": resumed, "status": status})
}
