package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHub Advisory Database 客户端。
//
// ## 为什么要有第二个来源
//
// NVD 对**新披露**的 CVE 常常不填版本区间——实测 2026-10-22 的 PHP
// CVE-2026-109618/109619，NVD 里的 CPE 是 `cpe:2.3:a:php:php:*:*:*:*:*:*:*:*`，
// 版本位是 `*`。我们只能标「版本待定」（见 fastlane.go 的
// VersionRangeUndetermined）——**那是止损，不是解法**。
//
// GitHub Advisory Database 走的是另一条录入路径（维护者自己提 advisory，
// 或由 GitHub 的安全团队收录），**版本区间是必填的**，且带
// `first_patched_version`（修复版本）——这正是 NVD 缺的那块。
//
// ## 覆盖边界（重要，别高估它）
//
// GHSA 覆盖的是**有包生态的组件**：composer（PHP 应用层框架）、npm、pip、
// maven、nuget、go、rust…
//
// **PHP 核心本身的 CVE 不在 GHSA 里**——实测 CVE-2026-109618/109619 在
// GHSA API 上返回空数组。所以 GHSA 是**补充**不是**替代**：它补的是
// 「有包生态的组件」（占我们资产的大头），核心语言的 CVE 仍要靠 NVD +
// 厂商 advisory。
//
// 这也是本文件里没有任何「GHSA 能解决 PHP 那两个 CVE」之类承诺的原因。

// GhsaClient  talks to the GitHub Advisory Database REST API.
//
// 无需 token 即可读公开 advisory（限速较松）；配置 token 后限速更宽。
// token 只写在配置里，不进日志、不进报告。
type GhsaClient struct {
	Base   string // override for tests; default api.github.com
	Token  string
	HTTP   *http.Client
	PerPag int
}

// NewGhsaClient 建一个 GHSA 客户端。
func NewGhsaClient(token string, proxyURL string) (*GhsaClient, error) {
	transport, err := newFallbackTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &GhsaClient{
		Base:   "https://api.github.com",
		Token:  strings.TrimSpace(token),
		HTTP:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
		PerPag: 100,
	}, nil
}

// GhsaAdvisory 是 GHSA API 返回的 advisory 子集。
type GhsaAdvisory struct {
	GHSID      string   `json:"ghsa_id"`
	CVEID      string   `json:"cve_id"`
	URL        string   `json:"html_url"`
	Summary    string   `json:"summary"`
	Description string  `json:"description"`
	Severity   string   `json:"severity"`
	CVSS       *GhsaCVSS `json:"cvss"`
	CVSSSeverity *GhsaCVSSSeverity `json:"cvss_severity"`
	Published  string   `json:"published_at"`
	Updated    string   `json:"updated_at"`
	Withdrawn  string   `json:"withdrawn_at"`
	// Vulnerabilities 是受影响的包与版本区间。
	Vulnerabilities []GhsaVulnerability `json:"vulnerabilities"`
	// References 是厂商公告等外部链接——模型据此去确认影响范围。
	//
	// 实测 GitHub API 返回的是**字符串数组**（"https://..."），
	// 不是对象数组。用 json.RawMessage 收两种形态。
	References []json.RawMessage `json:"references"`
	// Cwes 是弱点分类。
	Cwes []GhsaCWE `json:"cwes"`
}

// GhsaCVSS 是 advisory 自带的 CVSS 向量（无向量的 advisory 也有 severity 文本）。
type GhsaCVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// GhsaCVSSSeverity 是 CVSS v3/v4 的分项。
type GhsaCVSSSeverity struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

// GhsaVulnerability 描述一个受影响的包。
type GhsaVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	// VulnerableVersionRange 是 semver 区间表达式，如 "< 3.10.0"、
	// ">= 1.0.0, <= 1.11.0"。
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	// FirstPatchedVersion 是修复版本。
	//
	// 实测 2026-10-22 的 GitHub API 返回的是**字符串**（"3.10.0"），
	// 但 OSV 生态里同一字段有时是 {"identifier": "..."} 对象。
	// 这里用 json.RawMessage 两种形态都收。
	FirstPatchedVersion json.RawMessage `json:"first_patched_version"`
}

// patchedVersionFromRaw 从 first_patched_version 提取版本号。
//
// 兼容两种形态：字符串 "3.10.0" 与对象 {"identifier": "3.10.0"}。
func patchedVersionFromRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.Identifier)
	}
	return ""
}

// referenceURL 从一条 reference 里取出 URL。
//
// GitHub API 实际返回字符串；对象形态（{"url": "..."}）也收——
// 别的来源（如内部镜像）可能用对象。
func referenceURL(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.URL)
	}
	return ""
}

// GhsaCWE 是弱点编号。
type GhsaCWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// GhsaAdvisory 的语义化解析结果。
type GhsaFinding struct {
	// ID 是主键：CVE 号优先（能与 NVD 合并），没有则用 GHSA 号。
	ID string
	// GHSID 是 GHSA 自己的编号（总是有）。
	GHSID string
	Title string
	// Severity 是归一化严重度（CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN）。
	Severity string
	// Score 是 CVSS 分数（无则 nil）。
	Score *float64
	// Published / Updated 是时间。
	Published time.Time
	Updated   time.Time
	// Refs 是外部引用。
	Refs []string
	// Packages 是受影响的包与版本区间。
	Packages []GhsaPackage
	// Cwes 是弱点编号列表。
	Cwes []string
}

// GhsaPackage 是一个受影响包及其版本区间。
type GhsaPackage struct {
	// Ecosystem 是 GHSA 的生态名（composer/npm/pip/…）。
	Ecosystem string
	// Name 是包名（如 "contao/core-bundle"）。
	Name string
	// Range 是 semver 区间表达式原文。
	Range string
	// PatchedVersion 是修复版本（空 = 尚未修复）。
	PatchedVersion string
}

// GhsaAffected 描述「该包的这个版本受影响」的判定结果。
type GhsaAffected struct {
	Package GhsaPackage
	// Affected 为 true 表示目标版本落在区间内。
	Affected bool
	// Reason 说明判定依据（给模型看的）。
	Reason string
}

// FetchAdvisories 拉 GHSA advisory 列表。
//
// 游标语义：sort=updated&direction=desc 时按 updated_at 倒序返回，
// 调用方用 since 过滤 updated_at > since 即可做增量。
func (c *GhsaClient) FetchAdvisories(ctx context.Context, since time.Time, page int) ([]GhsaAdvisory, error) {
	perPage := c.PerPag
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	q.Set("sort", "updated")
	q.Set("direction", "desc")

	u := c.Base + "/advisories?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghsa: status %d: %s", resp.StatusCode, snippet(body))
	}
	var out []GhsaAdvisory
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ghsa: decode: %w", err)
	}
	// 增量过滤：只留 updated_at 在 since 之后的。
	if !since.IsZero() {
		kept := out[:0]
		for _, a := range out {
			if t, err := time.Parse(time.RFC3339, a.Updated); err == nil && t.After(since) {
				kept = append(kept, a)
			}
		}
		out = kept
	}
	return out, nil
}

// FetchByCVEID 按 CVE 号精确查 GHSA。
//
// 用途：NVD 同步到的 CVE 若版本区间未定，用它去 GHSA 补一次。
// GHSA 没有收录时返回空切片（不是错误）——「查不到」是常态。
func (c *GhsaClient) FetchByCVEID(ctx context.Context, cveID string) ([]GhsaAdvisory, error) {
	q := url.Values{}
	q.Set("cve_id", cveID)
	q.Set("per_page", "10")
	u := c.Base + "/advisories?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghsa: status %d: %s", resp.StatusCode, snippet(body))
	}
	var out []GhsaAdvisory
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ghsa: decode: %w", err)
	}
	return out, nil
}

func (c *GhsaClient) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "4zreco-vulnintel")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// snippet 截短错误正文（不要把整页 HTML 塞进日志）。
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// ParseGhsa 把一条 advisory 解析成 Finding。
//
// 关键取舍：**没有 CVE 号的 advisory 也要留**（ID 用 GHSA 号）——
// 因为版本区间才是我们要的东西，不能因为「它没映射到 CVE」就丢掉。
func ParseGhsa(a GhsaAdvisory) GhsaFinding {
	f := GhsaFinding{
		GHSID: a.GHSID,
		Title: strings.TrimSpace(a.Summary),
		Refs:  []string{},
		Cwes:  []string{},
	}
	if f.Title == "" {
		f.Title = a.Description
	}
	if len(f.Title) > 300 {
		f.Title = f.Title[:300]
	}
	// 主键：CVE 优先（能与 NVD 的记录合并成一条）。
	f.ID = strings.TrimSpace(a.CVEID)
	if f.ID == "" {
		f.ID = a.GHSID
	}
	// 严重度：先看 CVSS 分数，再看文本。
	if a.CVSS != nil && a.CVSS.Score > 0 {
		s := a.CVSS.Score
		f.Score = &s
		f.Severity = severityFromScore(s)
	} else if a.CVSSSeverity != nil && a.CVSSSeverity.Score > 0 {
		s := a.CVSSSeverity.Score
		f.Score = &s
		f.Severity = severityFromScore(s)
	} else {
		f.Severity = severityFromText(a.Severity)
	}
	if t, err := time.Parse(time.RFC3339, a.Published); err == nil {
		f.Published = t
	}
	if t, err := time.Parse(time.RFC3339, a.Updated); err == nil {
		f.Updated = t
	}
	for _, r := range a.References {
		if u := referenceURL(r); u != "" {
			f.Refs = append(f.Refs, u)
		}
	}
	for _, cw := range a.Cwes {
		if cw.CWEID != "" {
			f.Cwes = append(f.Cwes, cw.CWEID)
		}
	}
	for _, v := range a.Vulnerabilities {
		p := GhsaPackage{
			Ecosystem: v.Package.Ecosystem,
			Name:      v.Package.Name,
			Range:     strings.TrimSpace(v.VulnerableVersionRange),
		}
		if p.Name == "" {
			continue
		}
		p.PatchedVersion = patchedVersionFromRaw(v.FirstPatchedVersion)
		f.Packages = append(f.Packages, p)
	}
	return f
}

// severityFromScore 按 CVSS 分数归一化严重度。
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// severityFromText 按文本严重度归一化（无 CVSS 分数时用）。
func severityFromText(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
