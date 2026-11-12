package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// A8 无成果止损（移植自 ARTEX 0.3.29 server/engine_timeout.go 的 no-result 半边）。
//
// 判定是纯函数（task_runtime.go 的 noResultRemaining/evaluateNoResultStop），
// 这里只做挂点：deadline 协调器旁挂一次性检查（见 engine_timeout.go），以及
// planner 轮末经 auto_finish 路径复评（auto_finish.go）。两者都汇入
// checkNoResultCheckpoint —— 它以 tasks.no_result_checked_at 做一次性认领，
// 重复调用是安全空操作。

// needsNoResultCoordinator 报告任务是否需要无结果协调（预算>0 且尚未完成一次性
// 检查，或已提交过未收场的止损判定——恢复重启前被打断的收尾）。
func needsNoResultCoordinator(t *Task) bool {
	if t == nil || t.NoResultSeconds <= 0 {
		return false
	}
	state := t.lifecycleSnapshot()
	return state.NoResultCheckedAt == 0 || state.StopReason == db.StopReasonNoResult
}

// checkNoResultCheckpoint 把「活跃运行已满预算」的一次性判定落库并广播结论。
// 返回 stop=true 表示应立即收场。DB 错误绝不能被当成「0 达标漏洞」——由调用方
// 负责降级重试。已终态/已认领/未到时的任务都是 no-op（false, nil）。
func (e *Engine) checkNoResultCheckpoint(t *Task) (bool, error) {
	e.m.taskStateMu.Lock()
	defer e.m.taskStateMu.Unlock()
	state := t.lifecycleSnapshot()
	if state.NoResultCheckedAt > 0 || isTerminalStatus(state.Status) ||
		noResultRemaining(t.NoResultSeconds, state, time.Now().Unix()) > 0 {
		return false, nil
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false, err
	}
	minimum := t.NoResultMinFindings
	if minimum < 1 {
		minimum = 1
	}
	count, stop, checked, err := e.m.pg.CheckNoResultCheckpoint(context.Background(), id, minimum, t.NoResultMinSeverity)
	if err != nil || checked == nil {
		return false, err
	}
	t.updateLifecycle(func(s *taskLifecycleState) {
		s.NoResultCheckedAt = checked.Unix()
		if stop {
			s.StopReason = db.StopReasonNoResult
		}
	})
	severity := t.NoResultMinSeverity
	if severity == "" {
		severity = "不限"
	} else {
		severity += "及以上"
	}
	summary := "无成果检查通过：达标漏洞 " + strconv.Itoa(count) + "/" + strconv.Itoa(minimum) +
		"（等级" + severity + "），任务继续运行，之后不再检查"
	if stop {
		runtime := taskRunSeconds(state.ActiveRunSeconds, state.RunSegmentStartedAt, checked.Unix(), state.Status, state.Paused, state.Queued) - state.NoResultBaseSeconds
		summary = "无成果止损：活跃运行 " + (time.Duration(max(int64(0), runtime)) * time.Second).String() +
			"，达标漏洞 " + strconv.Itoa(count) + "/" + strconv.Itoa(minimum) + "（等级" + severity + "），任务自动停止"
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: summary})
	return stop, nil
}

// evaluateNoResultAutoFinish 是 auto_finish 路径（planner 每轮）的 no-result 旁挂：
// 到时才做一次性 DB 检查；止损成立则登记收尾（真正 settle 由 maybePendingSettle
// 在 inflight 释放后执行，stop_reason 已随检查点落库），检查通过则广播一次并永不
// 复查。
func (e *Engine) evaluateNoResultAutoFinish(t *Task) {
	if t == nil || t.NoResultSeconds <= 0 || e.m.pg == nil {
		return
	}
	state := t.lifecycleSnapshot()
	if state.NoResultCheckedAt > 0 || isTerminalStatus(state.Status) {
		return
	}
	if noResultRemaining(t.NoResultSeconds, state, time.Now().Unix()) > 0 {
		return
	}
	stop, err := e.checkNoResultCheckpoint(t)
	if err != nil {
		// DB 错误绝不当作 0 达标漏洞；等下一轮/协调器复查。
		log.Printf("[no-result] task %s 检查失败: %v", t.ID, err)
		return
	}
	if !stop {
		return
	}
	t.requestSettle("no_result", "活跃运行已满止损预算且达标漏洞不足")
}
