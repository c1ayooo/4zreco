package vulnintel

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// GHSA 条目入库。
//
// ## 落哪张表
//
// 复用 `vuln_cves` + `vuln_cpe_products`——**不建新表**。
//
// 理由：search_vulns 的检索与版本判定（VersionInRange）已经建在这两张表上，
// 新建表就意味着要写第二套查询、第二套版本判定、第二套 UI 呈现——而且
// 两套逻辑会不一致（这正是我们这次踩过的坑：两份实现不同步）。
//
// `vuln_cves.source` 列本来就为「后续 OSV 等第二来源合并」预留了（见
// db/schema.sql 的注释）——这一列就是 GHSA 的落点。
//
// ## 冲突怎么办
//
// 同一个 CVE 可能同时有 NVD 记录与 GHSA 记录。主键是 cve_id，
// **后写的会覆盖先写的**。所以：
//   - GHSA 同步只在 NVD 同步**之后**跑，且只写 NVD 没写过的 CVE；
//   - 真正需要合并时（GHSA 有 NVD 没有的版本区间），走 MergeGhsaVersion
//     ——只补版本区间，不覆盖 NVD 的标题/描述/评分。

// GhsaSyncResult 是一轮 GHSA 同步的结果。
type GhsaSyncResult struct {
	// Fetched 是本轮拉到的 advisory 数。
	Fetched int `json:"fetched"`
	// Upserted 是成功入库的条数。
	Upserted int `json:"upserted"`
	// Skipped 是因为 NVD 已有该 CVE 而跳过的条数。
	Skipped int `json:"skipped"`
	// Merged 是给已有 CVE 补上版本区间的条数。
	Merged int `json:"merged"`
	// Errors 是本轮的错误（按源聚合，不含 token）。
	Errors []string `json:"errors,omitempty"`
}

// UpsertGhsa 把一条 GHSA finding 写入库。
//
// 返回 "merged" 表示该 CVE 已在库（NVD 写的），这次只补了版本区间。
func (s *Store) UpsertGhsa(ctx context.Context, f GhsaFinding) (string, error) {
	if f.ID == "" {
		return "", fmt.Errorf("vulnintel: empty ghsa id")
	}
	exists, err := s.cveExists(ctx, f.ID)
	if err != nil {
		return "", err
	}
	if exists {
		// NVD 已经写过这条 CVE ——只补 GHSA 的版本区间，不覆盖 NVD 的内容。
		// NVD 的描述/评分/标题质量更高，不能被 GHSA 的摘要盖掉。
		if err := s.mergeGhsaVersion(ctx, f); err != nil {
			return "", err
		}
		// CWE 同理是补充语义：NVD weaknesses 常缺（尤其新披露），GHSA 的
		// cwes 并进去做 skill 联动；已有值不被抹掉。
		if err := s.mergeGhsaCWEs(ctx, f); err != nil {
			return "", err
		}
		return "merged", nil
	}

	// cpe_criteria 存 GHSA 的包+区间描述（不是 CPE 串）——展示用。
	criteria := ghsaCriteria(f)
	refs := marshalJSONB(f.Refs)
	cwes := marshalTextArray(f.Cwes)
	published := nullTime(f.Published)
	modified := nullTime(f.Updated)

	if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cves
		(cve_id, source, title, description, severity, cvss_score, cvss_vector,
		 published_at, modified_at, cpe_criteria, refs, cwes, synced_at)
		VALUES ($1,'ghsa',$2,$3,$4,$5,'',$6,$7,$8,$9,$10::text[],now())
		ON CONFLICT (cve_id) DO UPDATE SET
		  source='ghsa',
		  title=EXCLUDED.title, description=EXCLUDED.description,
		  severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score,
		  published_at=EXCLUDED.published_at, modified_at=EXCLUDED.modified_at,
		  cpe_criteria=EXCLUDED.cpe_criteria, refs=EXCLUDED.refs,
		  cwes=(SELECT ARRAY(SELECT DISTINCT unnest(vuln_cves.cwes || EXCLUDED.cwes))),
		  synced_at=now()`,
		f.ID, f.Title, "", f.Severity, f.Score, published, modified, criteria, refs, cwes); err != nil {
		return "", fmt.Errorf("upsert ghsa %s: %w", f.ID, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_cpe_products WHERE cve_id=$1`, f.ID); err != nil {
		return "", fmt.Errorf("clear ghsa index %s: %w", f.ID, err)
	}
	for _, p := range f.Packages {
		for _, idx := range ghsaIndexRows(p) {
			r := ghsaRangeToCPERange(p.Range)
			if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
				(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
				VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
				ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
				  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
				  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
				  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
				  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
				f.ID, idx.vendor, idx.product, r.StartIncluding, r.StartExcluding,
				r.EndIncluding, r.EndExcluding); err != nil {
				return "", fmt.Errorf("index ghsa %s: %w", f.ID, err)
			}
		}
	}
	return "upserted", nil
}

// mergeGhsaVersion 给已有的 CVE 补 GHSA 的版本区间。
//
// 只补 `vuln_cpe_products` 的区间列——**不动 vuln_cves 的内容**。
// 若已有同 product 的行且区间列已填，就不覆盖（NVD 的区间更可信）。
func (s *Store) mergeGhsaVersion(ctx context.Context, f GhsaFinding) error {
	for _, p := range f.Packages {
		r := ghsaRangeToCPERange(p.Range)
		for _, idx := range ghsaIndexRows(p) {
			if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
				(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
				VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
				ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
				  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
				  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
				  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
				  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
				f.ID, idx.vendor, idx.product, r.StartIncluding, r.StartExcluding,
				r.EndIncluding, r.EndExcluding); err != nil {
				return fmt.Errorf("merge ghsa %s: %w", f.ID, err)
			}
		}
	}
	return nil
}

// mergeGhsaCWEs 把 GHSA 的弱点编号并进已有行的 cwes 数组（并集去重）。
// GHSA 没给 CWE 时不动行。
func (s *Store) mergeGhsaCWEs(ctx context.Context, f GhsaFinding) error {
	if len(f.Cwes) == 0 {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE vuln_cves SET
		cwes=(SELECT ARRAY(SELECT DISTINCT unnest(cwes || $1::text[])))
		WHERE cve_id=$2`,
		marshalTextArray(f.Cwes), f.ID); err != nil {
		return fmt.Errorf("merge ghsa cwes %s: %w", f.ID, err)
	}
	return nil
}

// cveExists 判断 CVE 是否已在库。
func (s *Store) cveExists(ctx context.Context, cveID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&one)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false, nil
		}
		return false, fmt.Errorf("check cve %s: %w", cveID, err)
	}
	return true, nil
}

// ghsaProductIndex 是 GHSA 包在倒排索引里的一个 (vendor, product) 形态。
type ghsaIdxRow struct {
	vendor  string
	product string
}

// ghsaProductIndex 把一个 GHSA 包转成倒排索引里的候选形态。
//
// 问题：GHSA 的包名是 `vendor/package`（composer）形态，而 CPE product 是
// 单段（`contao`、`core_bundle`）。资产的技术指纹写的是 `Contao 5.3`
// 这种形态。直接存 `contao/core-bundle` 永远匹配不上。
//
// 折中：存**两个**形态——
//  1. vendor=斜杠前那段，product=斜杠后那段（`contao` / `core_bundle`）
//  2. vendor=空，product=斜杠后那段去掉连字符（`corebundle`）
//
// 形态 2 覆盖「厂商名与技术指纹不同」的情况（如包名 `symfony/http-kernel`
// 对应技术指纹 `Symfony`——symfony 那部分其实在形态 1 的 vendor 里）。
func ghsaIndexRows(p GhsaPackage) []ghsaIdxRow {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	if name == "" {
		return nil
	}
	out := []ghsaIdxRow{}
	vendor, product := "", name
	if i := strings.Index(name, "/"); i >= 0 {
		vendor = name[:i]
		product = name[i+1:]
	}
	// 连字符 → 下划线：GHSA 包名是 `core-bundle`，CPE product 是 `core_bundle`。
	// 不转的话这条索引永远匹配不上资产的技术指纹。
	underscored := strings.ReplaceAll(product, "-", "_")
	if underscored != "" {
		out = append(out, ghsaIdxRow{vendor: vendor, product: underscored})
	}
	if underscored != product && len(underscored) >= 2 {
		// 去连字符形态：core_bundle → corebundle。
		out = append(out, ghsaIdxRow{vendor: "", product: strings.ReplaceAll(product, "-", "")})
	}
	// 完整包名也存一份（vendor/package 形态的精确匹配）。
	if vendor != "" {
		out = append(out, ghsaIdxRow{vendor: vendor, product: name})
		// **vendor 段单独作为 product 存一行**。
		//
		// 理由：composer 包名 `contao/core-bundle` 里，资产技术指纹写的是
		// "Contao" ——只有 vendor 段对得上（package 段是 bundle/component，
		// 指纹里不会出现）。存这一行才让 GHSA 能匹配上「Contao 5.3」这类资产。
		if len(vendor) >= 2 {
			out = append(out, ghsaIdxRow{vendor: "", product: vendor})
		}
	}
	return out
}

// ghsaRangeToCPERange 把 GHSA 的 semver 区间转成现有的 CPE 区间列。
//
// 映射：`< X` → end_excl=X；`<= X` → end_incl=X；`> X` → start_excl=X；
// `>= X` → start_incl=X；`= X` → 两端都设成 X（闭区间单点）。
//
// 复合区间（AND）只能取**最紧的下界与最紧的上界**——多条件取交集，
// 交集的上下界就是各条件里最严的那个。取不到就留空。
func ghsaRangeToCPERange(expr string) CPERange {
	conds, unknown := ParseGhsaRange(expr)
	if len(conds) == 0 || len(unknown) > 0 {
		// 有解析不了的片段 → 整条区间不可信，不设边界（让上层判「无法比较」）。
		return CPERange{}
	}
	var r CPERange
	setStart := func(incl, excl string) {
		if incl != "" {
			if r.StartIncluding == "" || cmpVersions(incl, r.StartIncluding) > 0 {
				r.StartIncluding = incl
			}
			if r.StartExcluding != "" {
				if cmpVersions(incl, r.StartExcluding) >= 0 {
					r.StartIncluding, r.StartExcluding = incl, ""
				}
			}
		}
		if excl != "" {
			if r.StartExcluding == "" || cmpVersions(excl, r.StartExcluding) > 0 {
				r.StartExcluding = excl
			}
			if r.StartIncluding != "" {
				if cmpVersions(excl, r.StartIncluding) <= 0 {
					r.StartExcluding, r.StartIncluding = excl, ""
				}
			}
		}
	}
	setEnd := func(incl, excl string) {
		if incl != "" {
			if r.EndIncluding == "" || cmpVersions(incl, r.EndIncluding) < 0 {
				r.EndIncluding = incl
			}
			if r.EndExcluding != "" {
				if cmpVersions(incl, r.EndExcluding) <= 0 {
					r.EndIncluding, r.EndExcluding = incl, ""
				}
			}
		}
		if excl != "" {
			if r.EndExcluding == "" || cmpVersions(excl, r.EndExcluding) < 0 {
				r.EndExcluding = excl
			}
			if r.EndIncluding != "" {
				if cmpVersions(excl, r.EndIncluding) >= 0 {
					r.EndExcluding, r.EndIncluding = excl, ""
				}
			}
		}
	}
	for _, c := range conds {
		v := c.Ver
		switch c.Op {
		case ">":
			setStart("", v.String())
		case ">=":
			setStart(v.String(), "")
		case "<":
			setEnd("", v.String())
		case "<=":
			setEnd(v.String(), "")
		case "=":
			setStart(v.String(), "")
			setEnd(v.String(), "")
		}
	}
	return r
}

// ghsaCriteria 生成 GHSA 条目的 cpe_criteria 描述（展示用，不是真 CPE）。
func ghsaCriteria(f GhsaFinding) any {
	out := make([]string, 0, len(f.Packages))
	for _, p := range f.Packages {
		s := fmt.Sprintf("ghsa:%s/%s %s", p.Ecosystem, p.Name, p.Range)
		if p.PatchedVersion != "" {
			s += " (patched: " + p.PatchedVersion + ")"
		}
		out = append(out, s)
	}
	return marshalJSONB(out)
}

// SyncGhsa 跑一轮 GHSA 同步。
//
// 增量：since 之后 updated 的 advisory。since 为零值时只拉第一页
// （调用方决定要不要全量）。
func (s *Store) SyncGhsa(ctx context.Context, c *GhsaClient, since time.Time, maxPages int) (*GhsaSyncResult, error) {
	if c == nil {
		return nil, fmt.Errorf("vulnintel: nil ghsa client")
	}
	if maxPages <= 0 {
		maxPages = 3
	}
	res := &GhsaSyncResult{}
	for page := 1; page <= maxPages; page++ {
		advs, err := c.FetchAdvisories(ctx, since, page)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("ghsa page %d: %v", page, err))
			break
		}
		res.Fetched += len(advs)
		if len(advs) == 0 {
			break
		}
		for _, a := range advs {
			f := ParseGhsa(a)
			outcome, err := s.UpsertGhsa(ctx, f)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", f.ID, err))
				continue
			}
			switch outcome {
			case "merged":
				res.Merged++
			default:
				res.Upserted++
			}
		}
	}
	return res, nil
}

// GhsaVersionNote 是 GHSA 补充版本信息后的提示文案。
//
// 用于把「GHSA 补到了 NVD 没有的受影响版本区间」这件事告诉模型。
func GhsaVersionNote(f GhsaFinding) string {
	if len(f.Packages) == 0 {
		return ""
	}
	parts := make([]string, 0, len(f.Packages))
	for _, p := range f.Packages {
		s := p.Name
		if p.Range != "" {
			s += " " + p.Range
		}
		if p.PatchedVersion != "" {
			s += "（修复于 " + p.PatchedVersion + "）"
		}
		parts = append(parts, s)
	}
	return fmt.Sprintf("GitHub Advisory Database 补充的受影响版本：%s（GHSA %s）",
		strings.Join(parts, "；"), f.GHSID)
}
