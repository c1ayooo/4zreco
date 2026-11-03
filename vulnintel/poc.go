package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PoC 是一次同步写入的聚合条目。来源两类:GitHub code search 命中(按 CVE 引用
// 计排序)与 exploit-db CVE 状态(公开 CSV)。nuclei-templates 属于"模板即检测",
// 在 FindNucleiTemplates 单独建模。
type PoC struct {
	CVEID  string
	Source string // github / exploit-db
	URL    string
	Title  string
	Kind   string // poc / exploit
	Stars  int
}

// UpsertPoC writes one aggregated entry. Uniqueness is (source, url); cve_id is
// re-derivable but stored for cve-keyed lookup.
func (s *Store) UpsertPoC(ctx context.Context, p PoC) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_pocs (cve_id, source, url, title, kind, stars)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (source, url) DO UPDATE SET
		  cve_id=EXCLUDED.cve_id, title=EXCLUDED.title, kind=EXCLUDED.kind,
		  stars=EXCLUDED.stars, synced_at=now()`,
		p.CVEID, p.Source, p.URL, p.Title, p.Kind, p.Stars)
	if err != nil {
		return fmt.Errorf("upsert poc %s: %w", p.CVEID, err)
	}
	return nil
}

// PoCHit is get_poc's per-entry output: URL + what it is, no body fetching —
// the worker decides what to open via its own HTTP tooling (through the
// recording proxy, like any other traffic).
type PoCHit struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Title  string `json:"title"`
	Kind   string `json:"kind"`
	Stars  int    `json:"stars"`
}

// GetPoCs returns aggregated PoC entries for one CVE.
func (s *Store) GetPoCs(ctx context.Context, cveID string) ([]PoCHit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, url, title, kind, stars
		FROM vuln_pocs WHERE cve_id=$1 ORDER BY stars DESC, synced_at DESC LIMIT 50`,
		strings.ToUpper(strings.TrimSpace(cveID)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PoCHit{}
	for rows.Next() {
		var h PoCHit
		if err := rows.Scan(&h.Source, &h.URL, &h.Title, &h.Kind, &h.Stars); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- GitHub PoC aggregation ----

// GitHubClient hits the public GitHub REST API (10 req/min unauthenticated for
// search; 60/h for code search — the sync runs daily/6-hourly and pages short
// result sets, well within budget). An optional token lifts limits. Base is
// overridable for tests.
type GitHubClient struct {
	Base   string
	HTTP   *http.Client
	Token  string
}

func NewGitHubClient(token string, proxyURL string) (*GitHubClient, error) {
	transport, err := newFallbackTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	h := &http.Client{Timeout: 60 * time.Second, Transport: transport}
	return &GitHubClient{Base: "https://api.github.com", HTTP: h, Token: strings.TrimSpace(token)}, nil
}

func (c *GitHubClient) do(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimited{RetryAfter: parseSeconds(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("github api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// SearchPoCs queries GitHub for repos referencing the CVE. Query targets repo
// names AND descriptions (in:name,description) so "CVE-2021-41773-exploit" and
// PoC repos whose description cites the CVE both surface; code search (which
// needs authenticated scope-on tokens) is intentionally not used here.
func (c *GitHubClient) SearchPoCs(ctx context.Context, cveID string) ([]PoC, error) {
	q := url.Values{}
	q.Set("q", cveID+" in:name,description")
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("per_page", "30")
	var out struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			FullName    string `json:"full_name"`
			Description string `json:"description"`
			Stars       int    `json:"stargazers_count"`
			PushedAt    string `json:"pushed_at"`
			HTMLURL     string `json:"html_url"`
		} `json:"items"`
	}
	base := c.Base
	if base == "" {
		base = "https://api.github.com"
	}
	if err := c.do(ctx, base+"/search/repositories?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	pocs := make([]PoC, 0, len(out.Items))
	for _, it := range out.Items {
		if !strings.Contains(strings.ToLower(it.FullName), strings.ToLower(cveID)) &&
			!strings.Contains(strings.ToLower(it.Description), strings.ToLower(cveID)) {
			continue
		}
		title := firstSentence(it.Description)
		if title == "" {
			title = it.FullName
		}
		pocs = append(pocs, PoC{
			CVEID:  cveID,
			Source: "github",
			URL:    it.HTMLURL,
			Title:  title,
			Kind:   "poc",
			Stars:  it.Stars,
		})
	}
	// Star sort: search sort is advisory, client re-sorts after filtering.
	sort.Slice(pocs, func(i, j int) bool { return pocs[i].Stars > pocs[j].Stars })
	return pocs, nil
}

// FindNucleiTemplates scans a local nuclei-templates checkout for files
// containing the CVE ID (template files embed the CVE in their info/metadata
// block). templatesDir is the cloned JSON/yaml tree. Returns relative paths
// under the tree — the executor (later batch) builds full paths from here.
func FindNucleiTemplates(templatesDir, cveID string) []string {
	var out []string
	cveID = strings.ToLower(cveID)
	_ = filepath.WalkDir(templatesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		// 1MB cap: template files are tiny; oversized files are not templates.
		if len(b) <= (1<<20) && strings.Contains(strings.ToLower(string(b)), cveID) {
			if rel, rerr := filepath.Rel(templatesDir, path); rerr == nil {
				out = append(out, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}
