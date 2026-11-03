// Package vulnintel 维护定期同步的公开漏洞情报（NVD / CISA KEV），供 agent 在
// 识别目标组件后直接检索已知漏洞与现成利用，而不是每次靠模型现想。
// 数据全部来自公开源；同步出网走全局出口代理。表结构见 db/schema.sql 的
// vuln_cves / vuln_cpe_products / vuln_pocs / vuln_sync_state。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/db"
)

// Store 提供漏洞情报的写入（同步器）与检索（agent 工具）。
type Store struct {
	db *db.DB
}

// New wraps an opened database. Tables live in db/schema.sql and are created
// by the idempotent startup migration, so there is no separate Ensure here.
func New(d *db.DB) *Store { return &Store{db: d} }

// CVE 是一次同步写入的最小记录。
type CVE struct {
	ID          string
	Title       string
	Description string
	Severity    string // CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN
	Score       *float64
	Vector      string
	Published   time.Time
	Modified    time.Time
	Criteria    []string // cpe:2.3:... 原文（含版本区间语法）
	Refs        []string
	Ranges      []CPERange // 结构化版本区间(versionStart/End 字段),供精确版本判断
	Cwes        []string   // 弱点编号（NVD weaknesses / GHSA cwes），skill 联动用
}

// CPERange 是一条 cpeMatch 的版本区间(空串=该边界不存在)。
type CPERange struct {
	Criteria       string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// UpsertCVE writes one record: the row itself plus a rebuilt (vendor, product)
// inverted index. KEV columns are owned by the KEV sync and are NOT touched.
func (s *Store) UpsertCVE(ctx context.Context, c CVE) error {
	if c.ID == "" {
		return fmt.Errorf("vulnintel: empty cve id")
	}
	criteria := marshalJSONB(c.Criteria)
	refs := marshalJSONB(c.Refs)
	cwes := marshalTextArray(c.Cwes)
	rangesByCriteria := map[string]CPERange{}
	for _, r := range c.Ranges {
		rangesByCriteria[r.Criteria] = r
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cves
		(cve_id, source, title, description, severity, cvss_score, cvss_vector,
		 published_at, modified_at, cpe_criteria, refs, cwes, synced_at)
		VALUES ($1,'nvd',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text[],now())
		ON CONFLICT (cve_id) DO UPDATE SET
		  title=EXCLUDED.title, description=EXCLUDED.description,
		  severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score,
		  cvss_vector=EXCLUDED.cvss_vector, published_at=EXCLUDED.published_at,
		  modified_at=EXCLUDED.modified_at, cpe_criteria=EXCLUDED.cpe_criteria,
		  refs=EXCLUDED.refs,
		  -- cwes 两源都有：合并去重（NVD weaknesses 与 GHSA cwes 对同一 CVE
		  -- 的分类可能互补，谁后写都不该抹掉先写的）。
		  cwes=(SELECT ARRAY(SELECT DISTINCT unnest(vuln_cves.cwes || EXCLUDED.cwes))),
		  synced_at=now()`,
		c.ID, c.Title, c.Description, c.Severity, c.Score, c.Vector,
		nullTime(c.Published), nullTime(c.Modified), criteria, refs, cwes); err != nil {
		return fmt.Errorf("upsert vuln_cves %s: %w", c.ID, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_cpe_products WHERE cve_id=$1`, c.ID); err != nil {
		return fmt.Errorf("clear cpe index %s: %w", c.ID, err)
	}
	seen := map[string]bool{}
	for _, cr := range c.Criteria {
		vendor, product, ok := cpeVendorProduct(cr)
		if !ok {
			continue
		}
		// 同 (cve,vendor,product) 的多条 cpeMatch 区间取并:每个边界字段
		// 收集所有非空值,查询时任一边界命中即算匹配。
		key := vendor + "\x00" + product
		if seen[key] {
			// 已有行:合并区间字段(不同 cpeMatch 可能给不同区间)。
			s.mergeRange(ctx, c.ID, vendor, product, rangesByCriteria[cr])
			continue
		}
		seen[key] = true
		r := rangesByCriteria[cr]
		if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
			(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
			VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
			ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
			  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
			  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
			  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
			  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
			c.ID, vendor, product, r.StartIncluding, r.StartExcluding, r.EndIncluding, r.EndExcluding); err != nil {
			return fmt.Errorf("index cpe %s: %w", c.ID, err)
		}
	}
	return nil
}

// MarkKEV sets the in-the-wild exploitation flag. Rows unknown to the NVD sync
// (KEV moves faster than NVD sometimes) get a stub row so the flag is visible.
func (s *Store) MarkKEV(ctx context.Context, cveID string, added time.Time) error {
	tag := "KEV: " + added.Format("2006-01-02")
	res, err := s.db.ExecContext(ctx, `UPDATE vuln_cves SET kev=true, kev_date_added=$2 WHERE cve_id=$1`, cveID, nullTime(added))
	if err != nil {
		return fmt.Errorf("mark kev %s: %w", cveID, err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO vuln_cves (cve_id, source, title, severity, kev, kev_date_added)
		VALUES ($1,'kev',$2,'UNKNOWN',true,$3) ON CONFLICT (cve_id) DO UPDATE SET kev=true, kev_date_added=$3`,
		cveID, tag, nullTime(added))
	if err != nil {
		return fmt.Errorf("insert kev stub %s: %w", cveID, err)
	}
	return nil
}

// VulnHit 是 search_vulns 的单条结果（详情字段刻意精简，让 LLM 先看摘要）。
type VulnHit struct {
	CVEID     string   `json:"cve_id"`
	Severity  string   `json:"severity"`
	Score     *float64 `json:"cvss_score,omitempty"`
	KEV       bool     `json:"kev"`
	Published string   `json:"published,omitempty"`
	Title     string   `json:"title"`
	// 命中的 (vendor, product) 对，LLM 用它确认检索词与目标组件对得上。
	Matched []string `json:"matched,omitempty"`
	// version 非空且出现在某条 criteria 的版本字段里时置位——粗筛信号，
	// 版本是否真正落在影响区间由 LLM 结合 criteria 判断。
	VersionSeen bool `json:"version_seen_in_criteria"`
	// VersionInRange 三态:nil=无法判断(无结构化区间);true/false=结构化区间
	// 判定结果(任一 cpeMatch 区间命中即 true)。
	VersionInRange *bool `json:"version_in_range,omitempty"`
	// Source 是这条记录的数据来源:nvd / ghsa。
	//
	// 为什么要标：GHSA 的版本区间是**必填**的（NVD 常留空），两边对同一条
	// CVE 的判定可能不同——模型需要知道"这个区间是哪个源给的"才能权衡。
	Source string `json:"source,omitempty"`
	// Cwes 是弱点编号（CWE-79 这类）。get_vuln/search_vulns 把它交给模型，
	// server 装配时注入的 CWE→skill 映射据此提示对应的方法论 skill。
	Cwes []string `json:"cwes,omitempty"`
}

// SearchVulns 按组件名（可带厂商限定）检索已知漏洞。product 匹配 CPE product
// 段（大小写不敏感，支持 % 通配交给 ILIKE）；KEV 优先、分数次之。
func (s *Store) SearchVulns(ctx context.Context, vendor, product, version string, limit int) ([]VulnHit, error) {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil, fmt.Errorf("product is required")
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	pattern := strings.ToLower(product)
	if !strings.ContainsAny(pattern, "%_") {
		pattern = "%" + pattern + "%"
	}
	// Fixed placeholders: optional filters are always passed (empty = no filter).
	// Conditionally appended $N breaks PostgreSQL when the numbers skip a slot.
	args := []any{pattern, strings.TrimSpace(vendor), strings.TrimSpace(version), limit}
	rows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, c.cvss_score, c.kev, COALESCE(c.published_at::text,''),
       COALESCE(c.title,''), c.kev_date_added IS NOT NULL AS kev_row,
       COALESCE(array_to_json(c.cwes)::text,'[]'),
       COALESCE((
         SELECT string_agg(DISTINCT p.vendor || '/' || p.product, ', ')
         FROM vuln_cpe_products p WHERE p.cve_id = c.cve_id AND p.product ILIKE $1
       ), '') AS matched,
       MIN(p.product) AS hit_product,
       c.source
FROM vuln_cves c
JOIN vuln_cpe_products p ON p.cve_id = c.cve_id AND p.product ILIKE $1
                        AND ($2 = '' OR p.vendor ILIKE '%' || $2 || '%')
GROUP BY c.id
ORDER BY c.kev DESC,
         (CASE WHEN $3 <> '' AND c.cpe_criteria::text LIKE '%' || $3 || '%' THEN 1 ELSE 0 END) DESC,
         c.cvss_score DESC NULLS LAST, c.published_at DESC
LIMIT $4`, args...)
	if err != nil {
		return nil, fmt.Errorf("search vulns: %w", err)
	}
	defer rows.Close()
	version = strings.TrimSpace(version)
	out := []VulnHit{}
	for rows.Next() {
		var h VulnHit
		var kevRow bool
		var matched, hitProduct, cwesJSON string
		if err := rows.Scan(&h.CVEID, &h.Severity, &h.Score, &h.KEV, &h.Published, &h.Title, &kevRow, &cwesJSON, &matched, &hitProduct, &h.Source); err != nil {
			return nil, err
		}
		h.Cwes = unmarshalStringArray([]byte(cwesJSON))
		if kevRow {
			h.KEV = true
		}
		if matched != "" {
			h.Matched = strings.Split(matched, ", ")
		}
		if version != "" && s.criteriaContains(ctx, h.CVEID, version) {
			h.VersionSeen = true
		}
		if version != "" {
			if in, comparable := s.VersionInRange(ctx, h.CVEID, hitProduct, version); comparable {
				h.VersionInRange = &in
			}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// criteriaContains reads the stored criteria array and reports whether the
// version string appears as an exact CPE field. Deliberately exact-token
// semantics (e.g. "2.4.49" matching the version slot) — precision filtering is
// the LLM's job on the returned criteria; this only boosts ordering.
func (s *Store) criteriaContains(ctx context.Context, cveID, version string) bool {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT cpe_criteria FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&raw); err != nil || len(raw) == 0 {
		return false
	}
	var items []string
	if json.Unmarshal(raw, &items) != nil {
		return false
	}
	for _, it := range items {
		for _, part := range strings.Split(it, ":") {
			if part == version {
				return true
			}
		}
	}
	return false
}

// VulnDetail 是 get_vuln 的返回：完整描述、评分与原始 criteria/refs。
type VulnDetail struct {
	CVEID       string   `json:"cve_id"`
	Severity    string   `json:"severity"`
	Score       *float64 `json:"cvss_score,omitempty"`
	Vector      string   `json:"cvss_vector,omitempty"`
	KEV         bool     `json:"kev"`
	Published   string   `json:"published,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Criteria    []string `json:"cpe_criteria,omitempty"`
	Refs        []string `json:"references,omitempty"`
	// Source 是数据来源:nvd / ghsa。
	Source string `json:"source,omitempty"`
	// Cwes 是弱点编号（CWE-79 这类）——agent 侧据此提示对应方法论 skill。
	Cwes []string `json:"cwes,omitempty"`
	// VersionRanges 是结构化的受影响版本区间（每条对应一个组件）。
	//
	// 为什么单列出来:cpe_criteria 里 NVD 给的是 CPE 字符串（要模型自己读
	// versionEndExcluding 语法），GHSA 给的是 "ghsa:composer/xxx < 3.10.0"
	// ——两种形态模型都得再解析一遍。这里给出**归一后的**区间:
	// VersionInRange 为 true 表示该组件受影响。
	VersionRanges []VulnVersionRange `json:"version_ranges,omitempty"`
}

// VulnVersionRange 是一条归一后的受影响版本区间。
type VulnVersionRange struct {
	// Vendor / Product 是组件标识。
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	// StartIncluding / StartExcluding / EndIncluding / EndExcluding 是边界
	// （空串 = 该边界不存在）。语义与 NVD 的 cpeMatch 区间字段一致。
	StartIncluding string `json:"start_including,omitempty"`
	StartExcluding string `json:"start_excluding,omitempty"`
	EndIncluding   string `json:"end_including,omitempty"`
	EndExcluding   string `json:"end_excluding,omitempty"`
	// Source 是这条区间的来源（nvd / ghsa）——同一条 CVE 可能两边都给了区间。
	Source string `json:"source,omitempty"`
	// Raw 是原始区间文本（展示用）。
	Raw string `json:"raw,omitempty"`
}

// HasVersionRange 判断库里是否已有这条 CVE 的**结构化版本区间**。
//
// 与 VersionRangeUndetermined 的区别：那个只看 CVE 记录自带的 NVD 信息，
// 这个查的是**落库后的实际状态**——GHSA 补进来的区间也算数。
//
// 用途：快通道统计「版本待定」时要用这个（合并判定），而不是只看 NVD。
func (s *Store) HasVersionRange(ctx context.Context, cveID string) bool {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vuln_cpe_products
		WHERE cve_id=$1
		  AND (version_start_incl IS NOT NULL OR version_start_excl IS NOT NULL
		    OR version_end_incl IS NOT NULL OR version_end_excl IS NOT NULL)
		LIMIT 1`, strings.ToUpper(strings.TrimSpace(cveID))).Scan(&n)
	return err == nil && n > 0
}

// GetVuln returns the full record for one CVE (nil, nil when absent).
func (s *Store) GetVuln(ctx context.Context, cveID string) (*VulnDetail, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	var d VulnDetail
	var criteria, refs, cwes []byte
	var pub, mod *time.Time
	err := s.db.QueryRowContext(ctx, `SELECT cve_id, severity, cvss_score, COALESCE(cvss_vector,''),
		kev, published_at, modified_at, title, description, cpe_criteria, refs, source,
		COALESCE(array_to_json(cwes)::text,'[]')
		FROM vuln_cves WHERE cve_id=$1`, cveID).
		Scan(&d.CVEID, &d.Severity, &d.Score, &d.Vector, &d.KEV, &pub, &mod, &d.Title, &d.Description, &criteria, &refs, &d.Source, &cwes)
	if err == nil {
		if pub != nil {
			d.Published = pub.UTC().Format(time.RFC3339)
		}
		if mod != nil {
			d.Modified = mod.UTC().Format(time.RFC3339)
		}
		d.Criteria = unmarshalStringArray(criteria)
		d.Refs = unmarshalStringArray(refs)
		d.Cwes = unmarshalStringArray(cwes)
		d.VersionRanges = s.versionRanges(ctx, cveID)
		return &d, nil
	}
	if !isNoRows(err) {
		return nil, fmt.Errorf("get vuln %s: %w", cveID, err)
	}
	// KEV stub rows may live in vuln_pocs-adjacent state before NVD catches up;
	// currently there is nothing else to read, so report absence plainly.
	return nil, nil
}

// versionRanges 读某条 CVE 的结构化版本区间（归一后的）。
func (s *Store) versionRanges(ctx context.Context, cveID string) []VulnVersionRange {
	rows, err := s.db.QueryContext(ctx, `SELECT vendor, product,
		COALESCE(version_start_incl,''), COALESCE(version_start_excl,''),
		COALESCE(version_end_incl,''), COALESCE(version_end_excl,'')
		FROM vuln_cpe_products WHERE cve_id=$1
		ORDER BY vendor, product`, cveID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []VulnVersionRange{}
	for rows.Next() {
		var r VulnVersionRange
		if err := rows.Scan(&r.Vendor, &r.Product, &r.StartIncluding, &r.StartExcluding,
			&r.EndIncluding, &r.EndExcluding); err != nil {
			continue
		}
		if r.StartIncluding == "" && r.StartExcluding == "" &&
			r.EndIncluding == "" && r.EndExcluding == "" {
			continue // 没区间的索引行（只有 product 命中）
		}
		r.Raw = r.StartIncluding
		if r.StartExcluding != "" {
			r.Raw = r.StartExcluding
		}
		if r.EndIncluding != "" {
			r.Raw = ">=" + r.StartIncluding + ", <=" + r.EndIncluding
		}
		if r.EndExcluding != "" {
			r.Raw = "<" + r.EndExcluding
		}
		out = append(out, r)
	}
	return out
}

// SyncState mirrors one vuln_sync_state row.
type SyncState struct {
	Source      string     `json:"source"`
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	Cursor      string     `json:"cursor"`
	TotalSynced int64      `json:"total_synced"`
	LastError   string     `json:"last_error"`
	Enabled     bool       `json:"enabled"`
	// PageCursor 存窗口内的分页进度（"<窗口起>|<startIndex>"），让中断的窗口
	// 从断掉的那一页续跑，而不是整窗重跑。
	PageCursor string `json:"page_cursor"`
}

// GetSyncState returns the row for source, zero-value (enabled=true mirrors the
// column default) when absent — callers decide their own enabled semantics.
func (s *Store) GetSyncState(ctx context.Context, source string) (SyncState, error) {
	st := SyncState{Source: source, Enabled: true}
	// to_char forces ISO-8601 on the way out; the ::text cast would return
	// Postgres's own "2024-05-06 07:08:09+00" which nothing here parses.
	var lastSync string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(to_char(last_sync_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),''), cursor, total_synced, last_error, enabled, page_cursor
		FROM vuln_sync_state WHERE source=$1`, source).
		Scan(&lastSync, &st.Cursor, &st.TotalSynced, &st.LastError, &st.Enabled, &st.PageCursor)
	if err != nil {
		if isNoRows(err) {
			return st, nil
		}
		return st, err
	}
	if t, e := time.Parse(time.RFC3339, lastSync); e == nil {
		st.LastSyncAt = &t
	}
	return st, nil
}

// SaveSyncState upserts the watermark row.
func (s *Store) SaveSyncState(ctx context.Context, st SyncState) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_sync_state (source, last_sync_at, cursor, total_synced, last_error, enabled, page_cursor)
		VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4, $5, $6, $7)
		ON CONFLICT (source) DO UPDATE SET
		  last_sync_at=COALESCE($2::timestamptz, now()), cursor=EXCLUDED.cursor,
		  total_synced=EXCLUDED.total_synced, last_error=EXCLUDED.last_error, enabled=EXCLUDED.enabled,
		  page_cursor=EXCLUDED.page_cursor`,
		st.Source, st.LastSyncAt, st.Cursor, st.TotalSynced, st.LastError, st.Enabled, st.PageCursor)
	return err
}

// ---- helpers ----

// marshalTextArray 把 []string 编成 Postgres text[] 字面量（{"a","b"}），
// 配合 `$N::text[]` 占位符使用——与 db.marshalStringArray 同一形态。
func marshalTextArray(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	escaped := make([]string, len(items))
	for i, s := range items {
		escaped[i] = `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "{" + strings.Join(escaped, ",") + "}"
}

func marshalJSONB(items []string) any {
	if len(items) == 0 {
		return nil
	}
	b, err := json.Marshal(items)
	if err != nil {
		return nil
	}
	return string(b)
}

func unmarshalStringArray(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func isNoRows(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no rows in result set")
}

// cpeVendorProduct extracts (vendor, product) from a CPE 2.3 criteria string:
// cpe:2.3:part:vendor:product:version:...  Escaped colons (\:) are tolerated by
// splitting on unescaped colons only. part must be a/app/o/h (device classes we
// care about); "cpe:2.3" prefixed rows only.
func cpeVendorProduct(criteria string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return "", "", false
	}
	parts := splitUnescapedColons(criteria)
	// cpe:2.3:<part>:<vendor>:<product>:... → indices 2,3,4
	if len(parts) < 5 {
		return "", "", false
	}
	return unescape(parts[3]), unescape(parts[4]), true
}

// splitUnescapedColons splits on ':' not preceded by '\'.
func splitUnescapedColons(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			i++
			cur.WriteByte(s[i])
			continue
		}
		if s[i] == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	out = append(out, cur.String())
	return out
}

func unescape(s string) string {
	return strings.ReplaceAll(s, `\`, "")
}

// mergeRange folds another cpeMatch's range bounds into an existing index row
// (different cpeMatch entries for the same product may carry different bounds;
// query semantics are "any bound set matches").
func (s *Store) mergeRange(ctx context.Context, cveID, vendor, product string, r CPERange) {
	if r == (CPERange{}) {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE vuln_cpe_products SET
		  version_start_incl = COALESCE(version_start_incl, NULLIF($4,'')),
		  version_start_excl = COALESCE(version_start_excl, NULLIF($5,'')),
		  version_end_incl   = COALESCE(version_end_incl,   NULLIF($6,'')),
		  version_end_excl   = COALESCE(version_end_excl,   NULLIF($7,''))
		WHERE cve_id=$1 AND vendor=$2 AND product=$3`,
		cveID, vendor, product, r.StartIncluding, r.StartExcluding, r.EndIncluding, r.EndExcluding)
}

// VersionInRange reports whether version falls inside ANY stored range for
// (cve, product). Returns (false, false) when no comparable range exists —
// "not applicable" is distinct from "not in range".
func (s *Store) VersionInRange(ctx context.Context, cveID, product, version string) (in, comparable bool) {
	rows, err := s.db.QueryContext(ctx, `SELECT version_start_incl, version_start_excl,
		version_end_incl, version_end_excl FROM vuln_cpe_products
		WHERE cve_id=$1 AND product=$2
		  AND (version_start_incl IS NOT NULL OR version_start_excl IS NOT NULL
		    OR version_end_incl IS NOT NULL OR version_end_excl IS NOT NULL)`,
		strings.ToUpper(strings.TrimSpace(cveID)), strings.ToLower(strings.TrimSpace(product)))
	if err != nil {
		return false, false
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		var si, se, ei, ee *string
		if err := rows.Scan(&si, &se, &ei, &ee); err != nil {
			continue
		}
		any = true
		ok := true
		for _, b := range []struct {
			bound *string
			cmp   int // -1: version must be > bound (excl) / >= (incl) → flip
		}{} {
			_ = b
		}
		if si != nil && cmpVersions(version, *si) < 0 {
			ok = false
		}
		if se != nil && cmpVersions(version, *se) <= 0 {
			ok = false
		}
		if ei != nil && cmpVersions(version, *ei) > 0 {
			ok = false
		}
		if ee != nil && cmpVersions(version, *ee) >= 0 {
			ok = false
		}
		if ok {
			return true, true
		}
	}
	return false, any
}

// cmpVersions compares dotted version strings leniently: numeric segments
// numerically, others lexically; missing segments count as 0 ("1.2" == "1.2.0").
// Returns -1/0/1. Non-numeric trailing suffixes ("1.0b3") sort below the bare
// number ("1.0"), matching common pre-release semantics closely enough for
// advisory ranges.
func cmpVersions(a, b string) int {
	a = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(a), "v"))
	b = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(b), "v"))
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := "0", "0" // missing segments count as 0 ("1.2" == "1.2.0")
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if c := cmpSegment(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

func cmpSegment(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	aNum, bNum := aErr == nil, bErr == nil
	switch {
	case aNum && bNum:
		return cmpInt(an, bn)
	case aNum:
		return 1 // numeric segment outranks suffixed ("1" > "1b3" handled per-field)
	case bNum:
		return -1
	default:
		// both non-numeric: strip trailing alpha for numeric compare then lex
		an2, aErr2 := strconv.Atoi(strings.TrimRight(a, "abcdefghijklmnopqrstuvwxyz"))
		bn2, bErr2 := strconv.Atoi(strings.TrimRight(b, "abcdefghijklmnopqrstuvwxyz"))
		if aErr2 == nil && bErr2 == nil && an2 != bn2 {
			return cmpInt(an2, bn2)
		}
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
