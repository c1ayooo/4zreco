package vulnintel

// 资产图联动:同步进来的 CVE 反向匹配资产(service 类型 technologies 指纹),
// 产出命中清单,调用方(server)拿去给相关任务挂 hint。本文件刻意不依赖
// agent 包(避免 pkg 循环):hint 的落库由 server 侧的回调完成。
//
// 匹配是刻意的宽匹配:technologies("Apache httpd 2.4.49")与 CPE product
// ("http_server")命名差异靠 token 归一(小写/去版本/拆词/连词形态)取交集;
// 宁可多报由 planner 判读,不静默漏报。批量按 任务×组件 聚合,防 hint 风暴。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// AssetVulnMatch 记一条资产-CVE 命中。
type AssetVulnMatch struct {
	CVEID    string   `json:"cve_id"`
	AssetID  int64    `json:"asset_id"`
	TaskID   int64    `json:"task_id"`
	Severity string   `json:"severity"`
	KEV      bool     `json:"kev"`
	Score    *float64 `json:"cvss_score,omitempty"`
	Product  string   `json:"product"`
}

// AssetLinkResult 是一次联动的统计。
type AssetLinkResult struct {
	ScannedAssets int
	MatchedAssets int
	Matches       []AssetVulnMatch
}

// techTokens 把技术指纹串归一成词干:去版本号、拆空格与常见分隔符(斜杠/括号/
// 下划线,但保留连字符先)、补连字符合并形态。 "Apache httpd 2.4.49" →
// [apache httpd]; "nginx/1.24" → [nginx]; "http-server" → [http-server http server httpserver]。
func techTokens(s string) []string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("/", " ", "_", " ", "(", " ", ")", " ").Replace(s)
	raw := strings.Fields(s)
	toks := make([]string, 0, len(raw)*3)
	for _, f := range raw {
		f = strings.Trim(f, ".,:;!?")
		if len(f) < 2 || f == "v" || isVersionish(f) {
			continue
		}
		toks = append(toks, f)
	}
	// 连字符形态三重命名:原样 + 空 (http server) + 合并 (httpserver)。
	for _, f := range append([]string{}, toks...) {
		if strings.Contains(f, "-") {
			if spaced := strings.ReplaceAll(f, "-", " "); len(strings.TrimSpace(spaced)) > 0 {
				toks = append(toks, spaced)
			}
			if alt := strings.ReplaceAll(f, "-", ""); len(alt) >= 2 {
				toks = append(toks, alt)
			}
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		for _, sub := range strings.Fields(t) { // spaced 别名再切一次
			if !seen[sub] {
				seen[sub] = true
				out = append(out, sub)
			}
		}
	}
	// 别名表:tech 侧的每个 token 也带上常见 CPE product 形态(带下划线的
	// product 整串入集,不带下划线的按词切)。
	for _, tok := range append([]string{}, out...) {
		for _, alt := range techAliases[tok] {
			alts := []string{strings.ToLower(alt)}
			if !strings.Contains(alt, "_") {
				alts = strings.Fields(strings.ToLower(alt))
			}
			for _, sub := range alts {
				if !seen[sub] {
					seen[sub] = true
					out = append(out, sub)
				}
			}
		}
	}
	return out
}

// isVersionish:俩数字 + 有点或 v 前缀 → "1.24"、"v12"、"2.4.49"。
func isVersionish(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 2 && (strings.Contains(s, ".") || strings.HasPrefix(s, "v"))
}

// cpeTokens:product 段 + 下划线合并形态 + 常见缩写别名。
// 缩写映射是必须的:真实世界的资产指纹写 "httpd",而 CPE product 是
// "http_server"——纯 token 交集永远空。积累自真实资产清单,增量维护。
var techAliases = map[string][]string{
	"httpd":     {"http_server"},
	"http":      {"http_server"},
	"iis":       {"internet_information_services"},
	"exchange":  {"exchange_server"},
	"sqlserver": {"sql_server"},
	"activedirectory": {"active_directory"},
	"win":    {"windows"},
	"winserver": {"windows"},
	"cent":   {"centos"},
	"ubuntu": {"ubuntu_linux"},
	"debian": {"debian_linux"},
	"vmwareesxi": {"esxi"},
	"tomcat": {"apache_tomcat"},
	"struts": {"apache_struts"},
	"log4j":  {"apache_log4j"},
	"spring": {"vmware_Spring", "pivotal_Spring", "spring_framework"},
	"nginx":  {"nginx"},
}

// cpeTokens:product 段 + 下划线合并形态 + 常见缩写别名。
func cpeTokens(product string) []string {
	product = strings.ToLower(product)
	toks := []string{product}
	if compact := strings.ReplaceAll(product, "_", ""); compact != product && len(compact) >= 2 {
		toks = append(toks, compact)
	}
	for _, alt := range techAliases[product] {
		toks = append(toks, strings.ToLower(alt))
	}
	// 反向:product 命中某别名的 value 时带上 key("http_server" → "httpd"/"http"),
	// 让 tech 侧写 "httpd" 与 CPE 侧 "http_server" 能相等命中。
	for key, vals := range techAliases {
		for _, v := range vals {
			if v == product {
				toks = append(toks, key)
			}
		}
	}
	// 反向:product 的首段(token before _)若是某别名的值,带上该别名键
	// ("apache_tomcat" → "tomcat")。防 tech 写 "tomcat"、CPE 写 "apache_tomcat"。
	if head, _, ok := strings.Cut(product, "_"); ok {
		if alts, found := techAliases[head]; found {
			for _, alt := range alts {
				toks = append(toks, strings.ToLower(alt))
			}
			toks = append(toks, head)
		}
	}
	return toks
}

// LinkAssetsToVulns joins candidates against service assets' technologies and
// returns per-task matches. The caller (server) owns hint creation via its own
// exploration stores.
func (s *Store) LinkAssetsToVulns(ctx context.Context, since time.Time) (*AssetLinkResult, error) {
	// 候选 CVE:新同步的;KEV 优先、分数次之。数量锚在可跑完的量级。
	cveRows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, c.cvss_score, c.kev, p.product
FROM vuln_cves c
JOIN vuln_cpe_products p ON p.cve_id = c.cve_id
WHERE c.kev = true OR c.modified_at > $1 OR c.kev_date_added > $1
ORDER BY c.kev DESC, COALESCE(c.cvss_score, 0) DESC
LIMIT 500`, since)
	if err != nil {
		return nil, fmt.Errorf("query candidate cves: %w", err)
	}
	type cveRow struct {
		CVEID, Severity string
		Score           *float64
		KEV             bool
		Product         string
	}
	cves := []cveRow{}
	for cveRows.Next() {
		var c cveRow
		if err := cveRows.Scan(&c.CVEID, &c.Severity, &c.Score, &c.KEV, &c.Product); err == nil {
			cves = append(cves, c)
		}
	}
	cveRows.Close()
	if len(cves) == 0 {
		return &AssetLinkResult{Matches: []AssetVulnMatch{}}, nil
	}

	// assets 一次拉齐(全库 service 行数有限,fingerprint match 在 Go 做)。
	type assetRow struct {
		ID    int64
		Techs []string
		Tasks []int64
	}
	aRows, err := s.db.QueryContext(ctx, `
SELECT a.id, COALESCE(array_to_json(a.technologies)::text, '[]'),
       COALESCE((SELECT array_to_json(array_agg(DISTINCT l.task_id)) FROM task_asset_links l WHERE l.asset_id = a.id), '[]')
FROM assets a WHERE a.type='service'`)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	assets := []assetRow{}
	for aRows.Next() {
		var r assetRow
		var techs, tasks []byte
		if err := aRows.Scan(&r.ID, &techs, &tasks); err == nil {
			_ = json.Unmarshal(techs, &r.Techs)
			_ = json.Unmarshal(tasks, &r.Tasks)
			assets = append(assets, r)
		}
	}
	aRows.Close()

	res := &AssetLinkResult{ScannedAssets: len(assets), Matches: []AssetVulnMatch{}}
	// token → 命中该 token 的 CVE 行。一次建索引,资产匹配时 O(1) 查表。
	//
	// 此前这里是 O(资产 × tech × product) 的三重嵌套扫描,而且 cpeTokens(product)
	// 对每个 product 每轮都要重算一遍。实测全库 4966 条资产时,这一段跑了 28 秒、
	// 往 journal 写了 3.2 万行 debug 日志——把 agent 的日志信号整个淹掉(见
	// [[4zreco-obs-loop]])。倒排索引把它降到 O(CVE × token + 资产 × token)。
	tokIndex := map[string][]cveRow{}
	for _, c := range cves {
		for _, pt := range cpeTokens(c.Product) {
			tokIndex[pt] = append(tokIndex[pt], c)
		}
	}
	// 一个 product 可能有多个 cpeToken,同一个 CVE 会通过多个 token 命中同一资产 →
	// 按资产去重(按 CVEID),否则 res.Matches 里会出现重复行、浪费写库。
	// 注意 seenCVE 必须在【每个资产内】新建:CVE 是「资产×CVE」的关系,
	// 跨资产去重会让第二个资产匹配不到同一个 CVE。
	for _, a := range assets {
		var hitCVEs []cveRow
		seenCVE := map[string]bool{}
		for _, tech := range a.Techs {
			for _, tok := range techTokens(tech) {
				for _, c := range tokIndex[tok] {
					if seenCVE[c.CVEID] {
						continue
					}
					seenCVE[c.CVEID] = true
					hitCVEs = append(hitCVEs, c)
				}
			}
		}
		if len(hitCVEs) == 0 {
			continue
		}
		res.MatchedAssets++
		for _, c := range hitCVEs {
			for _, taskID := range a.Tasks {
				res.Matches = append(res.Matches, AssetVulnMatch{
					CVEID: c.CVEID, AssetID: a.ID, TaskID: taskID,
					Severity: c.Severity, KEV: c.KEV, Score: c.Score, Product: c.Product,
				})
			}
		}
	}
	log.Printf("[vulnintel] asset link: scanned=%d matched=%d matches=%d cve=%d",
		res.ScannedAssets, res.MatchedAssets, len(res.Matches), len(cves))
	return res, nil
}

// FormatHint 组装一条 hint 文本(同一资产多个 CVE 聚合为一条,kev 在前)。
func FormatHint(m []AssetVulnMatch, assetID int64) string {
	// dedup cves(同资产可能命中多个 cve)
	seen := map[string]bool{}
	list := []AssetVulnMatch{}
	for _, x := range m {
		if !seen[x.CVEID] {
			seen[x.CVEID] = true
			list = append(list, x)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[情报联动] 资产(id=%d)的组件指纹命中已知漏洞 %d 条:", assetID, len(list))
	for i, x := range list {
		if i >= 8 { // 上下文预算:再多让 planner 用 search_vulns 追查
			fmt.Fprintf(&b, " 等 %d 条(其余用 search_vulns(product) 自查)", len(list))
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s(%s", x.CVEID, x.Severity)
		if x.Score != nil {
			fmt.Fprintf(&b, " %.1f", *x.Score)
		}
		if x.KEV {
			b.WriteString(",KEV 已在野利用")
		}
		fmt.Fprintf(&b, ")")
	}
	b.WriteString("。用 get_vuln(cve_id) 看影响区间、get_poc(cve_id) 找现成利用,再决定是否值得派意图验证。")
	return b.String()
}
