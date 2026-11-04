package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// 「近期高危快通道」：专门把**刚披露的高危漏洞**尽快送进情报库。
//
// ## 为什么需要它
//
// 主同步走 NVD 的 lastModifiedDate 窗口（≤120 天），游标按窗口推进、一轮
// MaxRuntime 翻不完。这个结构对「补全历史目录」是对的，对「刚爆出来的
// 漏洞」是错的——一条昨天披露的 CRITICAL，要等主同步的游标爬到它那个窗口
// 才进库。
//
// 2026-10-22 的实测印证了这点，也暴露了第二个问题：
//
//	CVE-2026-109618（2026-10-21 披露，CRITICAL，PHP → RCE）
//	CVE-2026-109619（2026-10-21 披露，CRITICAL，PHP → RCE）
//
// 两条都是**昨天**披露的，NVD 上已有完整记录（描述、参考链接、GHSA advisory、
// Wiz 的分析博客都在），但：主同步还没爬到那个窗口 → 库里没有；而且它们的
// **受影响版本区间是空的**（cpe:2.3:a:php:php:*:*:*:*:*:*:*:*:*）——NVD 还没
// 填，意味着即使同步到了，也无法判断目标 PHP 版本是否受影响。
//
// 快通道解决两件事：
//  1. **时效**：按 publishedDate 小窗口拉「刚披露的」，只留 CVSS≥9.0 或
//     CISA KEV，几十分钟进库；
//  2. **版本待定可见**：版本区间缺失时**不能判成「不受影响」**——要显式标出
//     「版本待定」，让模型知道这个组件值得试（见 VersionRangeUndetermined）。
//
// ## 与主同步的关系
//
// - **共用 vuln_cves 表**：agent 查同一个库，不需要第二个查询入口。
// - **游标独立**（fastLaneSyncSource ≠ "nvd"）：快通道推的是 publishedDate
//   游标，不能把主同步的 lastModified 游标推走。
// - **窗口重叠**（fastLaneOverlapHours）：NVD 侧对新记录的索引有延迟，不重叠
//   会漏。
// - **分页上限**：单轮拉不完就下轮续（游标按窗口推进），不硬撑。

const (
	// fastLaneSyncSource 是快通道的游标 key（存在 vuln_sync_state.source）。
	//
	// 必须是独立值：主同步用 "nvd" 记 lastModified 游标，两者语义不同
	// （一个是「什么时候被改过」，一个是「什么时候被公开」），共用一个游标
	// 会把其中一条链路的进度搅乱。
	fastLaneSyncSource = "nvd_fastlane"

	// fastLaneMinWindowDays 是快通道窗口的下限（天）。
	//
	// 7 不是拍脑袋：实测（2026-10-22，走代理）**1~3 天的 publishedDate 窗口
	// 会超时**（NVD 对刚发布的记录还在索引，查询慢），7 天窗口 24513 条
	// 17 秒拉完。窗口更小 → 拉不动；窗口更大 → 慢且数据冗余。
	fastLaneMinWindowDays = 7

	// fastLaneOverlapHours 是相邻两轮窗口的重叠小时数。
	//
	// NVD 对刚公开的记录有索引延迟——刚披露的 CVE 在第一次拉的时候可能还查
	// 不到。重叠 24 小时是实测里 NVD 自己的 lastModified 增量窗口用的值，
	// 这里取它的下限 12 小时：漏一条 CRITICAL 的代价远大于多拉一点。
	fastLaneOverlapHours = 12

	// fastLanePageSize 是快通道每页条数。
	//
	// 实测：publishedDate 维度上单页 2000 条会超时（60s 客户端超时），
	// 1000 更稳。主同步用 2000 是因为它按 lastModified 窗口、数据分布不同。
	fastLanePageSize = 1000

	// fastLaneMaxPagesPerRun 是单轮最多的页数。
	//
	// 上限是为了「不占满一整轮」：快通道的价值在及时性，不该跟主同步抢
	// 时间预算。拉不完就留着游标下轮续。
	fastLaneMaxPagesPerRun = 20
)

// VersionRangeUndetermined 判断一条 CVE 的受影响版本区间是否「未确认」。
//
// 现象（2026-10-22 实测）：新披露的 CVE，NVD 常常只给
// `cpe:2.3:a:php:php:*:*:*:*:*:*:*:*`——版本位是 `*`，也没有任何
// versionStart/versionEnd 字段。此时**不能**判成「目标版本不受影响」。
//
// 判定「已确认」的两种形态：
//  1. criteria 里版本位是具体版本（固定版本的产品，如 1.2.3）；
//  2. Ranges 里有明确的起止边界（如 2.4.49 ~ <2.4.50）。
func VersionRangeUndetermined(c CVE) bool {
	// 有结构化区间 → 已确认。
	for _, r := range c.Ranges {
		if r.StartIncluding != "" || r.StartExcluding != "" ||
			r.EndIncluding != "" || r.EndExcluding != "" {
			return false
		}
	}
	// criteria 里出现非 * 的版本位 → 已确认（固定版本）。
	for _, crit := range c.Criteria {
		if cpeVersionPinned(crit) {
			return false
		}
	}
	// 没有任何 criteria → 也不知道受影响范围。
	if len(c.Criteria) == 0 {
		return true
	}
	return true
}

// cpeVersionPinned 判断一条 CPE 的版本位是不是具体版本（不是 * 或 -）。
func cpeVersionPinned(criteria string) bool {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return false
	}
	parts := splitUnescapedColons(criteria)
	// cpe:2.3:<part>:<vendor>:<product>:<version>:...
	// 切分后：parts[0]=cpe, [1]=2.3, [2]=part, [3]=vendor, [4]=product,
	// [5]=version（与 cpeVendorProduct 的索引约定一致）。
	if len(parts) < 6 {
		return false
	}
	v := parts[5]
	return v != "" && v != "*" && v != "-"
}

// VersionUndeterminedNote 是「版本待定」时的提示文案。
//
// 措辞很关键：必须说清「**不代表不受影响**」。否则模型会把「版本区间未知」
// 读成「版本不在影响范围」，直接跳过——而这正是新披露 CVE 最容易丢的地方。
func VersionUndeterminedNote() string {
	return "受影响版本区间未确认（NVD 尚未填写）：这不代表目标版本不受影响，" +
		"请按「该组件近期有高危漏洞」处理——查厂商 advisory（refs 里的 GHSA/" +
		"安全公告）确认受影响版本与修复版本，再决定是否验证。"
}

// FastLaneConfig 是快通道的配置。
type FastLaneConfig struct {
	// ProxyURL 是出网代理（空 = 直连）。
	ProxyURL string
	// NvdAPIKey 提升 NVD 限速额度（可选）。
	NvdAPIKey string
	// WindowDays 是回看窗口（天）。小于 fastLaneMinWindowDays 会被抬到下限。
	WindowDays int
	// MaxRuntime 是单轮墙钟上限。
	MaxRuntime time.Duration
	// PageDelay 是页间隔（NVD 匿名访问限速约 5 次/30s）。
	PageDelay time.Duration
}

// FastLaneResult 是一轮快通道的结果。
type FastLaneResult struct {
	// Scanned 是本轮扫过的记录数（拉回来的全部，不只是入库的）。
	Scanned int
	// Stored 是本轮入库存的条数（通过高危判定的）。
	Stored int
	// KEVStored 是其中 CISA KEV 的条数。
	KEVStored int
	// VersionUndetermined 是入库记录里「版本待定」的条数。
	VersionUndetermined int
	// Cursor 是本轮结束时的游标（下次从这里续）。
	Cursor string
	// Truncated 为 true 表示本轮因页数/时间上限没拉完（游标已保留）。
	Truncated bool
}

// RunFastLane pulls recently-published critical CVEs and stores them.
//
// 流程：按 publishedDate 小窗口分页拉 → 高危筛选 → 落库（复用 UpsertCVE，
// 走同一张表与同一套 CPE 索引）→ 推进游标。
//
// 与主同步的差别只有两点：查询维度（publishedDate vs lastModifiedDate）与
// 筛选（只要高危 vs 全收）。**不新增表、不新增 agent 工具入口**——agent 侧
// 查的还是同一个库，只是多了一条「近期高危」的查询。
func RunFastLane(ctx context.Context, st *Store, cfg FastLaneConfig) (FastLaneResult, error) {
	var res FastLaneResult
	client, err := NewNvdClient(cfg.NvdAPIKey, cfg.ProxyURL)
	if err != nil {
		return res, err
	}
	state, err := st.GetSyncState(ctx, fastLaneSyncSource)
	if err != nil {
		return res, err
	}

	now := time.Now()
	windowDays := cfg.WindowDays
	if windowDays < fastLaneMinWindowDays {
		windowDays = fastLaneMinWindowDays
	}
	// 游标是「上次拉到哪」。没有游标 → 从 windowDays 前开始；有游标 → 从
	// 游标往前推 overlap 小时（重叠，防 NVD 索引延迟漏记录）。
	from := now.AddDate(0, 0, -windowDays)
	if state.Cursor != "" {
		if t, e := time.Parse(time.RFC3339, state.Cursor); e == nil {
			from = t.Add(-time.Duration(fastLaneOverlapHours) * time.Hour)
		}
	}

	deadline := time.Now().Add(cfg.MaxRuntime)
	pages := 0
	for winStart := from; winStart.Before(now); {
		winEnd := winStart.AddDate(0, 0, windowDays)
		if winEnd.After(now) {
			winEnd = now
		}
		startIndex := 0
		for {
			if pages >= fastLaneMaxPagesPerRun {
				res.Truncated = true
				break
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				res.Truncated = true
				break
			}
			page, err := client.FetchPublished(ctx, startIndex, fastLanePageSize, winStart, winEnd)
			if err != nil {
				// 窗口拉不动（NVD 侧偶发超时）不算失败：游标保留，下轮重试。
				log.Printf("[vulnintel] 快通道窗口 %s 第 %d 页失败: %v",
					winStart.Format("2006-01-02"), startIndex, err)
				break
			}
			if len(page.Vulnerabilities) == 0 {
				break
			}
			pages++
			for _, w := range page.Vulnerabilities {
				res.Scanned++
				c, ok := ToCVE(w)
				if !ok {
					continue
				}
				score, _, _ := pickScore(w.CVE.Metrics)
				// KEV 标记这一轮不查（KEV 有独立的同步源），只看分数。
				if !isRecentCritical(score, false) {
					continue
				}
				if err := st.UpsertCVE(ctx, c); err != nil {
					log.Printf("[vulnintel] 快通道落库 %s 失败: %v", c.ID, err)
					continue
				}
				res.Stored++
				// 「版本待定」按**两源合并**判定：NVD 没填区间不算待定，
				// 如果 GHSA 已经补了区间（HasVersionRange 查的是落库后的
				// 实际状态，含 GHSA 补进来的），那这条的版本范围是已知的。
				//
				// 只看 NVD 的 VersionRangeUndetermined(c) 会把「GHSA 已经
				// 补上区间」的漏洞也算成待定——那正是 M10 要治的病。
				if VersionRangeUndetermined(c) && !st.HasVersionRange(ctx, c.ID) {
					res.VersionUndetermined++
				}
			}
			startIndex += fastLanePageSize
			if startIndex >= page.TotalResults {
				break
			}
			// 页间隔不在这里等——NvdClient.fetch 里的**共享限速闸门**已经
			// 统一控制（主同步与快通道共用额度，见 ratelimit.go）。这里再等
			// 一次等于把速率砍半。
		}
		if res.Truncated {
			break
		}
		// 窗口完成 → 游标推进到窗口末尾。
		state.Cursor = winEnd.UTC().Format(time.RFC3339)
		state.TotalSynced += int64(res.Stored)
		state.LastError = ""
		if err := st.SaveSyncState(ctx, state); err != nil {
			return res, err
		}
		res.Cursor = state.Cursor
		winStart = winEnd
	}
	if res.Cursor == "" {
		res.Cursor = state.Cursor
	}
	if res.Truncated {
		// 没拉完：游标留在当前窗口起点，下轮从那儿续（加重叠）。
		state.Cursor = from.UTC().Format(time.RFC3339)
		state.LastError = "快通道本轮未拉完（页数或时间上限），游标已保留"
		if err := st.SaveSyncState(ctx, state); err != nil {
			return res, err
		}
		res.Cursor = state.Cursor
	}
	return res, nil
}

// RecentCriticalHits 是「近期高危漏洞」的查询结果。
type RecentCriticalHits struct {
	CVEID    string  `json:"cve_id"`
	Severity string  `json:"severity"`
	Score    float64 `json:"cvss_score"`
	KEV      bool    `json:"kev"`
	Title    string  `json:"title"`
	// Published 是 ISO 日期串。
	Published string `json:"published"`
	// VersionUndetermined 为 true 表示 NVD 还没填受影响版本区间。
	VersionUndetermined bool `json:"version_undetermined"`
	// Products 是受影响产品（vendor/product 形态）。
	Products []string `json:"products"`
}

// SearchRecentCritical returns recently published critical CVEs.
//
// 与 SearchVulns 的区别：SearchVulns 按**组件**查（产品名 → CVE），这条按
// **时间**查（最近披露的高危），所以 worker 在「刚扫到一个 PHP 资产」时可以
// 直接问「最近 PHP 出了什么高危」，而不必先知道该查哪些 CVE 号。
//
// days 限制回看天数（默认 7 天，0 = 用默认）。limit 上限 100。
func (s *Store) SearchRecentCritical(ctx context.Context, days, limit int) ([]RecentCriticalHits, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, COALESCE(c.cvss_score,0), c.kev,
       COALESCE(c.published_at::text,''), COALESCE(c.title,''),
       COALESCE(c.cpe_criteria::text,'[]')
  FROM vuln_cves c
 WHERE c.published_at > now() - ($1 || ' days')::interval
   AND (c.kev = true OR COALESCE(c.cvss_score,0) >= $2)
 ORDER BY c.kev DESC, c.cvss_score DESC NULLS LAST, c.published_at DESC
 LIMIT $3`, fmt.Sprint(days), recentCriticalScoreThreshold, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentCriticalHits{}
	for rows.Next() {
		var h RecentCriticalHits
		var criteria string
		if err := rows.Scan(&h.CVEID, &h.Severity, &h.Score, &h.KEV,
			&h.Published, &h.Title, &criteria); err != nil {
			return nil, err
		}
		h.Products = productsFromCriteria(criteria)
		h.VersionUndetermined = len(h.Products) > 0 && allCriteriaUnpinned(criteria)
		out = append(out, h)
	}
	return out, rows.Err()
}

// productsFromCriteria 从 cpe_criteria JSON 数组里提取 vendor/product 形态。
func productsFromCriteria(criteriaJSON string) []string {
	var crits []string
	if err := json.Unmarshal([]byte(criteriaJSON), &crits); err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range crits {
		v, p, ok := cpeVendorProduct(c)
		if !ok || p == "" {
			continue
		}
		key := p
		if v != "" {
			key = v + "/" + p
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// allCriteriaUnpinned 判断 criteria 数组里的版本位是否全是 *（版本待定）。
func allCriteriaUnpinned(criteriaJSON string) bool {
	var crits []string
	if err := json.Unmarshal([]byte(criteriaJSON), &crits); err != nil {
		return true
	}
	if len(crits) == 0 {
		return true
	}
	for _, c := range crits {
		if cpeVersionPinned(c) {
			return false
		}
	}
	return true
}
