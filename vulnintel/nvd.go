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

// NvdClient talks to the NVD CVE API 2.0. Anonymous access is rate limited to
// ~5 requests / 30s (the client honors 429 Retry-After); an apiKey lifts it to
// 50 / 30s and is optional — configured in the UI, never logged.
type NvdClient struct {
	Base   string // override for tests; default services.nvd.nist.gov
	APIKey string
	HTTP   *http.Client
}

func NewNvdClient(apiKey string, proxyURL string) (*NvdClient, error) {
	// 代理传输层失败时自动回退直连——代理对某些源不通时不该整轮失败。
	transport, err := newFallbackTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &NvdClient{
		Base:   "https://services.nvd.nist.gov",
		APIKey: strings.TrimSpace(apiKey),
		HTTP:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}
// nvdResponse is the subset of the CVE API 2.0 envelope we consume.
type nvdResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Vulnerabilities []nvdWrapper `json:"vulnerabilities"`
}

type nvdWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string               `json:"id"`
	Published      string               `json:"published"`
	LastModified   string               `json:"lastModified"`
	Descriptions   []nvdDescription     `json:"descriptions"`
	Metrics        map[string]json.RawMessage `json:"metrics"`
	Weaknesses     []nvdWeakness        `json:"weaknesses"`
	Configurations []nvdConfiguration   `json:"configurations"`
	References     []nvdReference       `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore  float64 `json:"baseScore"`
		BaseSeverity string `json:"baseSeverity"`
		VectorString string `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdConfiguration struct {
	Nodes []struct {
		CPEMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionStartExcluding string `json:"versionStartExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}

type nvdReference struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// nvdWeakness 是 weaknesses 数组的一项（lang=en 的 value 形如 "CWE-79"）。
type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

// nvdTime parses NVD timestamps ("2024-01-02T03:04:05.678").
func nvdTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000", s)
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

// FetchPage fetches one page. modStart/modEnd bound the lastModified window
// (≤120 days per API contract, enforced by the caller); both empty = unfiltered.
func (c *NvdClient) FetchPage(ctx context.Context, startIndex, resultsPerPage int, modStart, modEnd time.Time) (*nvdResponse, error) {
	q := url.Values{}
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if !modStart.IsZero() {
		q.Set("lastModStartDate", modStart.UTC().Format("2006-01-02T15:04:05.000"))
	}
	if !modEnd.IsZero() {
		q.Set("lastModEndDate", modEnd.UTC().Format("2006-01-02T15:04:05.000"))
	}
	return c.fetch(ctx, q)
}

// FetchByCVEID fetches one CVE by its exact ID.
//
// 为什么需要（2026-10-22 实测）：FetchPage 只能按 lastModifiedDate 划窗口，
// 确认某个具体 CVE 是否存在只能扫几百天的窗口——实测 200 天扫描跑了 40 分钟
// 还因代理 TLS 抖动中断。cveId 参数是一次精确查询，成本是窗口查询的零头。
//
// 不存在的 CVE 返回 0 条而不是错误（NVD 对未知 ID 返回 totalResults=0）。
func (c *NvdClient) FetchByCVEID(ctx context.Context, cveID string) (*nvdResponse, error) {
	id := strings.TrimSpace(cveID)
	if id == "" {
		return nil, fmt.Errorf("cve id 不能为空")
	}
	return c.fetch(ctx, url.Values{"cveId": {id}})
}

// FetchPublished fetches one page of CVEs **by publication date**.
//
// 与 FetchPage 的区别：FetchPage 按 lastModifiedDate 划窗口（≤120 天），
// 那条路上「老 CVE 的元数据被更新」也会被算进来，且游标按 120 天窗口推进、
// 一轮 MaxRuntime 翻不完——「刚披露的高危漏洞」因此进库很慢。
//
// 按发布时间划的是一个小窗口，只含「新披露的」——这正是近期快通道要的。
//
// 实测（2026-10-22）：7 天窗口 24513 条、17 秒拉完；反而 1~3 天的窗口会
// 超时（NVD 对刚发布的记录还在索引，查询慢）。所以快通道的窗口不应小于
// 7 天。
func (c *NvdClient) FetchPublished(ctx context.Context, startIndex, resultsPerPage int, pubStart, pubEnd time.Time) (*nvdResponse, error) {
	q := url.Values{}
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if !pubStart.IsZero() {
		q.Set("pubStartDate", pubStart.UTC().Format("2006-01-02T15:04:05.000"))
	}
	if !pubEnd.IsZero() {
		q.Set("pubEndDate", pubEnd.UTC().Format("2006-01-02T15:04:05.000"))
	}
	return c.fetch(ctx, q)
}

// fetch 执行一次 NVD 查询并解码。
func (c *NvdClient) fetch(ctx context.Context, q url.Values) (*nvdResponse, error) {
	base := c.Base
	if base == "" {
		base = "https://services.nvd.nist.gov"
	}
	// 共享限速闸门：主同步与快通道打的是同一个 NVD，额度是共享的。
	// 不在这里排队，两条链路会各自按自己的节奏超限（实测快通道第一页就
	// rate limited）。
	if err := c.waitNvdSlot(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/json/cves/2.0?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		// Honor Retry-After when present; the sync loop re-calls at its own pace.
		ra := resp.Header.Get("Retry-After")
		return nil, &RateLimited{RetryAfter: parseSeconds(ra)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("nvd api decode: %w", err)
	}
	return &out, nil
}

// recentCriticalScoreThreshold 是近期快通道的 CVSS 分数门槛。
//
// 取 9.0：NVD 的 CRITICAL 档起点。低于它的不进快通道——每天新披露的 CVE
// 上万条，不筛的话库和 hint 都会被中低危淹没，worker 也就不会真的去看。
const recentCriticalScoreThreshold = 9.0

// isRecentCritical 判断一条 CVE 是否够格进「近期快通道」。
//
// 判据：CVSS≥9.0，**或** CISA KEV 标记（已在野利用——分数可能不高但危害
// 极大，KEV 优先于分数）。
//
// score 为 nil（metrics 空或解析不出）时**不**因为 severity 字符串是
// CRITICAL 就放行：severity 是 NVD 从分数映射来的，没有分数却写着
// CRITICAL 是数据异常，按「判不准不放行」处理更稳（宁可晚点进库，也不要
// 错标一批）。
func isRecentCritical(score *float64, kev bool) bool {
	if kev {
		return true
	}
	return score != nil && *score >= recentCriticalScoreThreshold
}

// RateLimited signals a 429 so the sync loop can back off without treating it
// as a source failure.
type RateLimited struct{ RetryAfter time.Duration }
func (e *RateLimited) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("nvd rate limited, retry after %s", e.RetryAfter)
	}
	return "nvd rate limited"
}

func parseSeconds(s string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// parseNVDCWEs 提取 weaknesses 里的 CWE 编号（lang=en），去重、归一成
// "CWE-79" 大写形态、封顶 10 个。NVD 对同一个 CWE 常给多条（不同 source），
// 不去重的话 cwes 数组会被撑成十几项重复值。
func parseNVDCWEs(ws []nvdWeakness) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, w := range ws {
		for _, d := range w.Description {
			if d.Lang != "en" {
				continue
			}
			id := strings.ToUpper(strings.TrimSpace(d.Value))
			if id == "" || seen[id] {
				continue
			}
			// 只收标准编号形态；NVD 的内部占位（NVD-CWE-OTHER / NVD-CWE-NOINFO /
			// CWE-OTHER 这类）不进库。
			if !strings.HasPrefix(id, "CWE-") ||
				strings.Contains(id, "NVD-CWE") ||
				id == "CWE-OTHER" {
				continue
			}
			seen[id] = true
			out = append(out, id)
			if len(out) >= 10 {
				return out
			}
		}
	}
	return out
}

// ToCVE converts an API record into the store shape. Scoring picks the first
// Primary V31, then any V31, then V30, then V2 — mirroring NVD's own precedence.
func ToCVE(w nvdWrapper) (CVE, bool) {
	c := w.CVE
	if c.ID == "" {
		return CVE{}, false
	}
	out := CVE{
		ID:        c.ID,
		Published: nvdTime(c.Published),
		Modified:  nvdTime(c.LastModified),
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			out.Description = d.Value
			break
		}
	}
	out.Title = firstSentence(out.Description)
	score, vector, severity := pickScore(c.Metrics)
	out.Score, out.Vector, out.Severity = score, vector, severity
	out.Cwes = parseNVDCWEs(c.Weaknesses)
	seen := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable || m.Criteria == "" || seen[m.Criteria] {
					continue
				}
				seen[m.Criteria] = true
				out.Criteria = append(out.Criteria, m.Criteria)
				if m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
					m.VersionEndIncluding != "" || m.VersionEndExcluding != "" {
					out.Ranges = append(out.Ranges, CPERange{
						Criteria:       m.Criteria,
						StartIncluding: m.VersionStartIncluding,
						StartExcluding: m.VersionStartExcluding,
						EndIncluding:   m.VersionEndIncluding,
						EndExcluding:   m.VersionEndExcluding,
					})
				}
			}
		}
	}
	for _, r := range c.References {
		if r.URL != "" {
			out.Refs = append(out.Refs, r.URL)
		}
	}
	return out, true
}

// pickScore mirrors NVD precedence: Primary V31 > any V31 > V30 > V2.
func pickScore(metrics map[string]json.RawMessage) (score *float64, vector, severity string) {
	if metrics == nil {
		return nil, "", "UNKNOWN"
	}
	primary, anyHit := pickFromMetricList(metrics["cvssMetricV31"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	primary, anyHit = pickFromMetricList(metrics["cvssMetricV30"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	primary, anyHit = pickFromMetricList(metrics["cvssMetricV2"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	return nil, "", "UNKNOWN"
}

type picked struct {
	score    *float64
	vector   string
	severity string
}

func pickFromMetricList(raw json.RawMessage, wantType string) (picked, bool) {
	if len(raw) == 0 {
		return picked{}, false
	}
	var list []nvdMetric
	if json.Unmarshal(raw, &list) != nil {
		return picked{}, false
	}
	var fallback *nvdMetric
	for i := range list {
		m := list[i]
		if m.CVSSData.BaseScore == 0 && m.CVSSData.VectorString == "" {
			continue
		}
		if m.Type == wantType {
			return toPicked(m), true
		}
		if fallback == nil {
			fallback = &list[i]
		}
	}
	if fallback != nil {
		return toPicked(*fallback), true
	}
	return picked{}, false
}

func toPicked(m nvdMetric) picked {
	s := m.CVSSData.BaseScore
	p := picked{score: &s, vector: m.CVSSData.VectorString, severity: m.CVSSData.BaseSeverity}
	if p.severity == "" {
		p.severity = mapScoreToSeverity(m.CVSSData.BaseScore)
	}
	return p
}

// mapScoreToSeverity maps a numeric base score onto the v3 severity ladder.
// Used as fallback when the source doesn't carry a textual severity; the legacy
// v2 term set is intentionally folded onto this same ladder.
func mapScoreToSeverity(score float64) string {
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

// firstSentence trims the description to a one-line title: up to the first
// period followed by a space, capped at 160 runes.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 && i < 200 {
		s = s[:i+1]
	}
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > 160 {
		return string(r[:157]) + "..."
	}
	return s
}
