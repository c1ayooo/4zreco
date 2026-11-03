package vulnintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchKEVParsesCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sites/default/files/feeds/known_exploited_vulnerabilities.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"title":          "CISA Catalog",
			"catalogVersion": "2024.01.02",
			"dateReleased":   "2024-01-02",
			"count":          2,
			"vulnerabilities": []map[string]any{
				{
					"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
					"dateAdded": "2021-11-17", "shortDescription": "Path traversal in Apache HTTP Server.",
					"knownRansomwareCampaignUse": "Known",
				},
				{"cveID": "", "vendorProject": "skipped-empty-cve"},
				{
					"cveID": "CVE-2010-0001", "vendorProject": "X", "product": "Y",
					"dateAdded": "bad-date",
				},
			},
		})
	}))
	defer srv.Close()

	client := &NvdClient{Base: srv.URL, HTTP: srv.Client()}
	cat, err := client.FetchKEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cat.Version != "2024.01.02" || cat.Count != 2 {
		t.Fatalf("version=%s count=%d", cat.Version, cat.Count)
	}
	if len(cat.Vulnerabilities) != 2 {
		t.Fatalf("entries=%d want 2 (empty cveID skipped)", len(cat.Vulnerabilities))
	}
	e := cat.Vulnerabilities[0]
	want, _ := time.Parse("2006-01-02", "2021-11-17")
	if e.CVEID != "CVE-2021-41773" || e.Vendor != "Apache" || !e.DateAdded.Equal(want) {
		t.Fatalf("entry=%+v", e)
	}
	// Unparsable date must leave the zero time, not fail the whole feed.
	if !cat.Vulnerabilities[1].DateAdded.IsZero() {
		t.Fatalf("bad date should parse to zero, got %v", cat.Vulnerabilities[1].DateAdded)
	}
}
