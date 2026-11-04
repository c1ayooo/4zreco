package vulnintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSearchPoCsFiltersAndSorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/repositories" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("q"); got != "CVE-2099-0001 in:name,description" {
			t.Errorf("q=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 3,
			"items": []map[string]any{
				{"full_name": "someone/CVE-2099-0001-POC", "description": "", "stargazers_count": 12, "html_url": "https://github.com/someone/CVE-2099-0001-POC"},
				{"full_name": "other/unrelated-repo", "description": "does not mention the id", "stargazers_count": 9999, "html_url": "https://github.com/other/unrelated-repo"},
				{"full_name": "third/exploit-CVE-2099-0001", "description": "Exploit for CVE-2099-0001. RCE chain.", "stargazers_count": 340, "html_url": "https://github.com/third/exploit-CVE-2099-0001"},
			},
		})
	}))
	defer srv.Close()

	client, err := NewGitHubClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	client.Base = srv.URL
	pocs, err := client.SearchPoCs(context.Background(), "CVE-2099-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(pocs) != 2 {
		t.Fatalf("entries=%d want 2 (unrelated filtered)", len(pocs))
	}
	if pocs[0].Stars < pocs[1].Stars {
		t.Fatalf("not star-sorted: %v", pocs)
	}
	e := pocs[0]
	if e.Source != "github" || e.Kind != "poc" || e.Stars != 340 {
		t.Fatalf("entry=%+v", e)
	}
	// Empty description falls back to the repo full name as the title.
	if pocs[1].Title != "someone/CVE-2099-0001-POC" {
		t.Fatalf("title fallback broken: %q", pocs[1].Title)
	}
}

func TestUpsertAndGetPoCsRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_pocs WHERE cve_id='CVE-9000-0005'`)
	})
	if err := st.UpsertPoC(ctx, PoC{
		CVEID: "CVE-9000-0005", Source: "github", URL: "https://github.test/a/poc",
		Title: "PoC A", Kind: "poc", Stars: 5,
	}); err != nil {
		t.Fatal(err)
	}
	// Same source+URL upserts rather than duplicating.
	if err := st.UpsertPoC(ctx, PoC{
		CVEID: "CVE-9000-0005", Source: "github", URL: "https://github.test/a/poc",
		Title: "PoC A (updated)", Kind: "poc", Stars: 9,
	}); err != nil {
		t.Fatal(err)
	}
	hits, err := st.GetPoCs(ctx, "cve-9000-0005") // case-insensitive lookup
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%d want 1", len(hits))
	}
	if hits[0].Stars != 9 || hits[0].Title != "PoC A (updated)" {
		t.Fatalf("hit=%+v", hits[0])
	}
}

func TestFindNucleiTemplates(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("http/cves/2099/CVE-2099-0001.yaml", "id: CVE-2099-0001\ninfo: template mentioning cve-2099-0001 lowercase\n")
	write("http/cves/2099/other.yaml", "id: not-related\n")
	write("network/scan.yaml", "id: cve-2099-0001 in a template\n")
	write("docs/readme.md", "discusses cve-2099-0001 but is not a yaml template\n")

	got := FindNucleiTemplates(dir, "CVE-2099-0001")
	want := []string{"http/cves/2099/CVE-2099-0001.yaml", "network/scan.yaml"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestFetchKEVAndGitHubRateLimitPath(t *testing.T) {
	// RateLimited surfaces through the same error type for both clients.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	client := &GitHubClient{HTTP: srv.Client()}
	err := client.do(context.Background(), srv.URL+"/anything", &struct{}{})
	var rl *RateLimited
	if err == nil {
		t.Fatal("expected error")
	}
	asRL(err, &rl)
}

func asRL(err error, target **RateLimited) {
	if rl, ok := err.(*RateLimited); ok {
		*target = rl
	}
}
