package server

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"
)

// 补写空报告（U5，上游 v0.4.63 / 红队版 v0.6.10 启动扫描，v0.6.12 改为常驻巡检）。
//
// 现网两次踩到：reporter 正在写报告时后端重启（一键更新/部署），会话被中断，
// finding 的报告留空。触发式 reporter 只在 report_finding 那一刻排队，重启后没有
// 任何人记得这个漏洞还缺报告；运行中 reporter 崩溃/模型空回答同样会留空。
//
// 启动 45 秒后先扫一遍，之后每 15 分钟一轮；「报告为空且任务未删除、创建超过 20
// 分钟」的 finding 逐个用新会话重新唤起 reporter；同一个 finding 按指数退避
// （1/2/4/8h）唤起、最多 reportRecoverMaxTries 次（settings 里记次数与上次时间），
// 避免重启风暴刷屏；超限后停止自动重试并告警一次。

// reportRecoverMaxTries 是单个 finding 自动补写的尝试上限。
const reportRecoverMaxTries = 6

func (s *Server) recoverEmptyFindingReports() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	time.Sleep(45 * time.Second) // 等引擎恢复任务、调度器就绪，别和启动抢资源
	for {
		s.recoverEmptyReportsOnce()
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(15 * time.Minute):
			// 常驻巡检：不只启动时补——reporter 可能运行中崩溃、模型空回答、用户删了
			// 报告，15 分钟一轮兜底（同一 finding 按退避间隔不重复唤起）。
		}
	}
}

// reportRecoverDue 判定一个空报告 finding 本轮是否要唤起补写（纯判定面，表驱动
// 测试用）：tries 达上限 → 不再补（最后一次达到上限时 atLimit=true，调用方告警
// 一次）；距上次唤起不足退避间隔（1h→2h→4h→8h 封顶）→ 跳过；其余 → 唤起。
func reportRecoverDue(tries int, lastTS int64, now time.Time) (due, atLimit bool) {
	if tries >= reportRecoverMaxTries {
		return false, tries == reportRecoverMaxTries
	}
	backoff := time.Hour << uint(min(tries, 3)) // 1h → 2h → 4h → 8h 封顶
	if lastTS > 0 && now.Sub(time.Unix(lastTS, 0)) < backoff {
		return false, false
	}
	return true, false
}

func (s *Server) recoverEmptyReportsOnce() {
	rows, err := s.m.pg.Query(`
SELECT f.id, f.node_id, f.severity, left(f.name, 80), f.task_id
FROM findings f JOIN tasks t ON t.id = f.task_id
WHERE length(f.report) = 0 AND t.deleted_at IS NULL
  AND f.created_at > now() - interval '7 days'
  -- 只补「确实断掉」的：20 分钟内的新漏洞，触发式 reporter 可能正在写，别重复唤起
  AND f.created_at < now() - interval '20 minutes'
ORDER BY f.created_at DESC LIMIT 20`)
	if err != nil {
		log.Printf("[reporter] 补写空报告：查询失败: %v", err)
		return
	}
	type item struct {
		findingID int64
		// nodeID 可能是 NULL：探索节点被删时 findings.node_id 会被置空
		// （ON DELETE SET NULL）。这类漏洞照样要补报告，只是唤起时不带节点 ID。
		nodeID   sql.NullInt64
		taskID   int64
		severity string
		name     string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.findingID, &it.nodeID, &it.severity, &it.name, &it.taskID); err != nil {
			log.Printf("[reporter] 补写空报告：扫描行失败: %v", err)
			continue
		}
		items = append(items, it)
	}
	_ = rows.Close()
	triggered := 0
	for _, it := range items {
		nodeID := it.nodeID.Int64
		key := fmt.Sprintf("report_recover_%d", it.findingID)
		triesKey := fmt.Sprintf("report_recover_tries_%d", it.findingID)
		tries := 0
		if v, ok, _ := s.m.pg.GetSetting(triesKey); ok {
			tries, _ = strconv.Atoi(v)
		}
		// 尝试上限 + 指数退避。上游现网实测（finding#143）：坏 LLM 配置期间每小时
		// 被拉起一次、连续 ~20 次全是白烧 token，模型修好后自己就补上了。6 次上限 +
		// 1/2/4/8h 退避；超限后停止自动补写并告警一次，交人工。
		lastTS := int64(0)
		if v, ok, _ := s.m.pg.GetSetting(key); ok {
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
				lastTS = ts
			}
		}
		due, atLimit := reportRecoverDue(tries, lastTS, time.Now())
		if atLimit {
			log.Printf("[reporter] finding #%d 自动补写已达 %d 次上限，停止自动重试（报告仍为空，请人工检查模型配置或手动补写）", it.findingID, tries)
			_ = s.m.pg.SetSetting(triesKey, strconv.Itoa(tries+1)) // 只告警一次
			continue
		}
		if !due {
			continue
		}
		_ = s.m.pg.SetSetting(key, strconv.FormatInt(time.Now().Unix(), 10))
		_ = s.m.pg.SetSetting(triesKey, strconv.Itoa(tries+1))
		// 本地 finding_workflow 约定：update_finding_report 的 finding_id 参数仍传
		// 探索节点 ID（finding_node_id），独立编号只用于上下文指认。
		where := fmt.Sprintf("finding #%d", it.findingID)
		reportArg := it.findingID
		if nodeID > 0 {
			where = fmt.Sprintf("finding #%d，探索节点 %d", it.findingID, nodeID)
			reportArg = nodeID
		}
		msg := fmt.Sprintf("【报告补写】漏洞 %s（%s）的报告仍为空——上次撰写被中断（后端重启/会话崩溃）。"+
			"请核对已有证据/流量，调用 update_finding_report(finding_id=%d, report=<完整 Markdown>) 写完；"+
			"证据不足也要写完并在「未验证范围」如实标注。",
			it.severity, where, reportArg)
		triggered++
		log.Printf("[reporter] 补写空报告：finding #%d（node %d）", it.findingID, nodeID)
		s.StartTriggeredRun("reporter", fmt.Sprintf("报告补写 · finding#%d", it.findingID), msg, it.taskID, false, "", "")
	}
	if len(items) > 0 {
		log.Printf("[reporter] 空报告巡检：候选 %d 条，本次唤起 %d 条", len(items), triggered)
	}
}
