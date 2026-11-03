package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/agent"
	"github.com/c1ayooo/4zreco/db"
)

// 自动收尾设置（v0.5.0）。全局生效；0 表示该判据关闭（coverage/max）。
const (
	settingAutoFinishEnabled    = "auto_finish_enabled"
	settingAutoFinishIdleRounds = "auto_finish_idle_rounds"
	settingAutoFinishMinRounds  = "auto_finish_min_rounds"
	settingAutoFinishCoverage   = "auto_finish_coverage_pct"
	settingAutoFinishMaxRounds  = "auto_finish_max_rounds"

	defaultAutoFinishIdleRounds = 3
	defaultAutoFinishMinRounds  = 5
	defaultAutoFinishCoverage   = 0
	defaultAutoFinishMaxRounds  = 80
)

type autoFinishConfig struct {
	Enabled     bool
	IdleRounds  int
	MinRounds   int
	CoveragePct int
	MaxRounds   int
}

// autoFinishConfigFromPG 读取全局设置并夹逼到安全范围。读库失败时用默认值，
// 绝不能因为设置查询失败把任务卡死在“永不收尾”。
func autoFinishConfigFromPG(pg *db.DB) autoFinishConfig {
	c := autoFinishConfig{
		Enabled:     true,
		IdleRounds:  defaultAutoFinishIdleRounds,
		MinRounds:   defaultAutoFinishMinRounds,
		CoveragePct: defaultAutoFinishCoverage,
		MaxRounds:   defaultAutoFinishMaxRounds,
	}
	if pg == nil {
		return c
	}
	if v, ok, err := pg.GetSetting(settingAutoFinishEnabled); err == nil && ok {
		c.Enabled = v == "true" || v == "1"
	}
	if n, ok := settingInt(pg, settingAutoFinishIdleRounds); ok {
		c.IdleRounds = clampInt(n, 2, 20)
	}
	if n, ok := settingInt(pg, settingAutoFinishMinRounds); ok {
		c.MinRounds = clampInt(n, 1, 50)
	}
	if n, ok := settingInt(pg, settingAutoFinishCoverage); ok {
		c.CoveragePct = clampInt(n, 0, 100)
	}
	if n, ok := settingInt(pg, settingAutoFinishMaxRounds); ok {
		c.MaxRounds = clampInt(n, 0, 500)
	}
	return c
}

func settingInt(pg *db.DB, key string) (int, bool) {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// evaluateAutoFinish 是纯判定函数（便于单测）。active 表示存在 open/running
// 意图；coveragePct 为 0..100，0=覆盖率不可用/关闭。
//
// 判定优先级：最大轮数（硬上限，可在有意图时收）→ 覆盖率 → 连续零新增。
// idle/coverage 都要求 active=false，避免把正在推进的任务误收。
func evaluateAutoFinish(round int64, idle int, active bool, coveragePct int, cfg autoFinishConfig) (reason, detail string, ok bool) {
	if !cfg.Enabled {
		return "", "", false
	}
	if cfg.MaxRounds > 0 && round >= int64(cfg.MaxRounds) {
		return "auto_rounds", fmt.Sprintf("达到最大规划轮数 %d", cfg.MaxRounds), true
	}
	if round < int64(cfg.MinRounds) {
		return "", "", false
	}
	if active {
		return "", "", false
	}
	if cfg.CoveragePct > 0 && idle >= 1 && coveragePct >= cfg.CoveragePct {
		return "auto_coverage", fmt.Sprintf("资产覆盖率 %d%% ≥ %d%%（且连续 %d 轮无新增）", coveragePct, cfg.CoveragePct, idle), true
	}
	if idle >= cfg.IdleRounds {
		return "auto_idle", fmt.Sprintf("连续 %d 轮无新增（第 %d 轮）", idle, round), true
	}
	return "", "", false
}

// freshDirection 判断本轮 trigger 是否包含用户新增目标/提示；是则收尾计数归零，
// 避免刚加目标就因旧 idle 计数被收掉。
func freshDirection(triggers []agent.TriggerEvent) bool {
	for _, ev := range triggers {
		switch ev.Kind {
		case "goal", "goal_edited", "goal_deleted", "hint":
			return true
		}
	}
	return false
}

// recordAndEvaluateAutoFinish 在一个常规规划轮结束后记录进度并登记收尾原因。
// 只登记，不执行 settle：调用方（plannerLoop）在本轮 inflight 释放后再收尾。
func (e *Engine) recordAndEvaluateAutoFinish(t *Task, round int64, triggers []agent.TriggerEvent) {
	pg := e.m.pg
	if pg == nil || t.ExpID <= 0 || t.Store == nil {
		return
	}
	cfg := autoFinishConfigFromPG(pg)
	if !cfg.Enabled {
		return
	}
	facts, findings, err := pg.CountExplorationProgress(t.ExpID)
	if err != nil {
		log.Printf("[auto-finish] task %s 读取进度失败: %v", t.ID, err)
		return
	}
	tested := int64(0)
	coveragePct := 0
	if t.CoverageEnabled {
		if taskID, err := strconv.ParseInt(t.ID, 10, 64); err == nil && e.m.assets != nil {
			if cov, err := e.m.assets.TaskCoverageWithSources(taskID); err == nil && cov != nil {
				tested = int64(cov.Tested)
				if cov.Pct != nil {
					coveragePct = clampInt(int(*cov.Pct*100+0.5), 0, 100)
				}
			}
		}
	}
	idle, err := pg.RecordTaskProgress(t.ID, round, facts, findings, tested)
	if err != nil {
		log.Printf("[auto-finish] task %s 记录进度失败: %v", t.ID, err)
		return
	}
	if freshDirection(triggers) {
		if err := pg.ResetTaskProgress(t.ID); err == nil {
			idle = 0
		}
	}
	active := true
	if a, err := t.Store.HasActiveIntent(); err == nil {
		active = a
	} else {
		log.Printf("[auto-finish] task %s 读取 frontier 失败，暂不判定: %v", t.ID, err)
		return
	}
	reason, detail, ok := evaluateAutoFinish(round, idle, active, coveragePct, cfg)
	if !ok {
		return
	}
	log.Printf("[auto-finish] task %s 触发收尾：%s（round=%d idle=%d active=%v coverage=%d%%）",
		t.ID, detail, round, idle, active, coveragePct)
	t.requestSettle(reason, detail)
}

// maybePendingSettle 在 plannerLoop 中执行挂起的收尾。返回 true 表示已进入收尾。
// goal_met / auto_rounds 可在有在跑意图时收（先 drain）；idle/coverage 已由
// 判定保证 active=false，这里再校验一次以防并发新增意图。
func (e *Engine) maybePendingSettle(ctx context.Context, t *Task) bool {
	reason, detail := t.peekSettle()
	if reason == "" {
		return false
	}
	if e.IsPaused(t.ID) || e.IsDeleting(t.ID) || e.isSettling(t.ID) || t.Store == nil {
		return false
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		return false
	}
	if reason != "auto_rounds" {
		active, err := t.Store.HasActiveIntent()
		if err != nil || active {
			return false
		}
	}
	e.settleTaskWithReason(ctx, t, reason, detail)
	return true
}
