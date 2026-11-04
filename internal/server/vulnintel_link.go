// 资产图联动的 server 侧接线:vulnintel 同步完成后,把新 CVE 对资产指纹的命中
// 以 hint 形式挂进受影响任务的探索图。放独立文件,不混进 manager.go。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/vulnintel"
)

// linkVulnIntelAssets runs after each vulnintel sync pass: newly synced CVEs
// are matched against service assets' technology fingerprints; every affected
// task gets ONE hint per asset (aggregated CVE list), linked (anchored) to the
// asset so the planner reads it next round and the lineage is explicit.
// Best-effort: errors are logged, never fatal to the sync.
func (m *Manager) linkVulnIntelAssets() {
	m.mu.RLock()
	vi := m.vulnintel
	m.mu.RUnlock()
	if vi == nil {
		return
	}
	ctx := context.Background()
	since := time.Now().Add(-7 * 24 * time.Hour) // 与增量窗口重叠,防漏
	res, err := vi.LinkAssetsToVulns(ctx, since)
	if err != nil {
		log.Printf("[vulnintel] 资产联动查询失败: %v", err)
		return
	}
	if len(res.Matches) == 0 {
		return
	}
	// task → asset → matches 聚合;exploration id 批量取。
	perTask := map[int64]map[int64][]vulnintel.AssetVulnMatch{}
	taskIDs := []int64{}
	seenTask := map[int64]bool{}
	for _, mt := range res.Matches {
		if mt.TaskID <= 0 {
			continue
		}
		if !seenTask[mt.TaskID] {
			seenTask[mt.TaskID] = true
			taskIDs = append(taskIDs, mt.TaskID)
		}
		if perTask[mt.TaskID] == nil {
			perTask[mt.TaskID] = map[int64][]vulnintel.AssetVulnMatch{}
		}
		perTask[mt.TaskID][mt.AssetID] = append(perTask[mt.TaskID][mt.AssetID], mt)
	}
	expOf := map[int64]int64{}
	rows, err := m.pg.Query(`SELECT id, exploration_id FROM tasks WHERE id = ANY($1)`, taskIDs)
	if err != nil {
		log.Printf("[vulnintel] 资产联动取任务失败: %v", err)
		return
	}
	for rows.Next() {
		var id, exp int64
		if err := rows.Scan(&id, &exp); err == nil {
			expOf[id] = exp
		}
	}
	rows.Close()

	added := 0
	for taskID, perAsset := range perTask {
		exp, ok := expOf[taskID]
		if !ok || exp <= 0 {
			continue
		}
		ts := m.pg.Exploration(exp)
		// 防抖:每 6h 同步一轮都会重复命中同一资产——最近 24h 的 hint 里已含
		// 同资产段("资产(id=N)")的不再挂。hint 数量按任务可控(上限 500)。
		recent, err := ts.ListByKind(db.KindHint, 500)
		if err != nil {
			log.Printf("[vulnintel] 任务 %d 读 hint 失败(跳过防抖): %v", taskID, err)
			recent = nil
		}
		alerted := map[int64]bool{}
		day := time.Now().Add(-24 * time.Hour)
		for _, n := range recent {
			var p struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			if !strings.HasPrefix(p.Text, intelHintPrefix) {
				continue
			}
			if !n.CreatedAt.IsZero() && n.CreatedAt.Before(day) {
				continue
			}
			for _, mt := range res.Matches {
				if strings.Contains(p.Text, assetTag(mt.AssetID)) {
					alerted[mt.AssetID] = true
				}
			}
		}
		for assetID, ms := range perAsset {
			if alerted[assetID] {
				continue
			}
			text := intelHintPrefix + vulnintel.FormatHint(ms, assetID)
			// "human" 作者位 = 平台注入的提示,与 UI 手工 add_hint 同源可见。
			if _, err := ts.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "human", []int64{assetID}); err != nil {
				log.Printf("[vulnintel] 任务 %d 挂情报 hint 失败: %v", taskID, err)
				continue
			}
			added++
		}
	}
	log.Printf("[vulnintel] 资产联动:命中资产 %d,挂 hint %d 条(任务 %d 个)",
		res.MatchedAssets, added, len(perTask))
}

// intelHintPrefix 是联动 hint 的判重前缀(FormatHint 正文以 "[情报联动]" 开头,
// 前缀加在同一处,防抖匹配走它)。
const intelHintPrefix = "[情报联动]"

// assetTag returns the substring FormatHint writes for one asset, used for
// dedup matching against existing hints' text.
func assetTag(assetID int64) string {
	return fmt.Sprintf("资产(id=%d)", assetID)
}
