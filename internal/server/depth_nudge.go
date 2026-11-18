package server

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

// 纵深缺口提醒（U5，上游 v0.4.63 / 红队版 v0.6.10/0.6.17）。
//
// 上游现网复盘（任务 #8）：两小时内资产从 34 涨到 241，但 high/critical finding
// 仍是 0——planner 在「铺面」上很勤奋，在「把已验证线索打穿成 L3 证据」上不足。
// 目标里写的是「控制服务器 / 拖数据 / 拿权限」，只铺面永远达不成。
//
// 这不是提示词能完全约束的（弱模型仍会偏侦察），所以在引擎侧补一层确定性检查：
// 资产已经很多、高危 finding 为 0 时，直接给 planner 发一条「停止铺新面、选 1-2
// 条已验证线索打穿」的触发。每任务 3 小时内最多一次，避免刷屏。
const (
	depthNudgeMinAssets = 50
	depthNudgeThrottle  = 3 * time.Hour
)

// needsDepthNudge 是纯判据：资产多而高危产出为 0（表驱动测试的判定面）。
func needsDepthNudge(assets, highFindings int) bool {
	return assets >= depthNudgeMinAssets && highFindings == 0
}

// nudgeDepthGaps 在 planner 一轮结束后调用（与覆盖提醒同一时机）。
func (e *Engine) nudgeDepthGaps(t *Task) {
	if e.m == nil || e.m.pg == nil || t == nil || t.Store == nil {
		return
	}
	if !e.m.pg.GetBool("depth_nudge_enabled", true) {
		return
	}
	var assets int
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1`, t.ID).Scan(&assets)
	var high int
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND severity IN ('critical','high')`, t.ID).Scan(&high)
	if !needsDepthNudge(assets, high) {
		return
	}
	if _, err := t.Store.ListByKind(db.KindGoal, 1); err != nil {
		return
	}
	key := fmt.Sprintf("depth_nudge_%s", t.ID)
	if v, ok, _ := e.m.pg.GetSetting(key); ok {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < depthNudgeThrottle {
			return
		}
	}
	_ = e.m.pg.SetSetting(key, strconv.FormatInt(time.Now().Unix(), 10))
	msg := fmt.Sprintf("纵深缺口：本任务已登记 %d 个资产，但 high/critical 漏洞仍为 0，目标里的控制/拖数据/拿权限都还没有实质证据。"+
		"本轮**停止铺新面**（新方向最多留 1 条），从已有的未授权访问、配置泄露、弱口令、对象存储、调试/管理接口线索里选 1–2 条打穿："+
		"拿到取数样本 / 后台登录成功 / 命令回显 / 可访问上传文件之一，写成 finding（附请求-响应或命令输出证据）；"+
		"只有已确认线索都确实打不动时，才允许继续扩面，并先派 fact 说明每条为什么打不动。", assets)
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "depth_gap", Detail: msg})
	t.trigMu.Unlock()
	log.Printf("[depth] task %s 纵深缺口提醒：资产 %d、高危 0，要求收敛打穿", t.ID, assets)
	t.Notify()
}
