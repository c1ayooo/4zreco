package vulnintel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// testStore mirrors the other packages' testmain pattern: without ZRECO_PG_DSN
// the suite skips (tables live in the shared idempotent schema).
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("ZRECO_PG_DSN")
	if dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return New(pg)
}

func cve(id, vendor, product, version string, score float64) CVE {
	s := score
	return CVE{
		ID: id, Title: "Test vuln " + id, Description: "Synthetic record for tests.",
		Severity: "HIGH", Score: &s, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Published: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Modified:  time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC),
		Criteria: []string{
			"cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*",
		},
		Refs: []string{"https://example.test/advisory"},
	}
}

func TestUpsertSearchGetRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	id := "CVE-9000-0001"
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, id)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id=$1`, id)
	})

	if err := st.UpsertCVE(ctx, cve(id, "apache", "http_server", "2.4.49", 9.8)); err != nil {
		t.Fatal(err)
	}

	hits, err := st.SearchVulns(ctx, "", "http_server", "2.4.49", 20)
	if err != nil {
		t.Fatal(err)
	}
	var hit *VulnHit
	for i := range hits {
		if hits[i].CVEID == id {
			hit = &hits[i]
		}
	}
	if hit == nil {
		t.Fatalf("record not found in %d hits", len(hits))
	}
	if hit.Severity != "HIGH" || !hit.VersionSeen {
		t.Fatalf("hit=%+v", hit)
	}
	if len(hit.Matched) == 0 || hit.Matched[0] != "apache/http_server" {
		t.Fatalf("matched=%v", hit.Matched)
	}

	// Vendor filter narrows; wrong vendor excludes.
	narrow, err := st.SearchVulns(ctx, "apache", "http_server", "", 20)
	if err != nil || len(narrow) == 0 {
		t.Fatalf("vendor filter: %d hits err=%v", len(narrow), err)
	}
	none, err := st.SearchVulns(ctx, "microsoft", "http_server", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range none {
		if h.CVEID == id {
			t.Fatal("vendor=microsoft must not match apache record")
		}
	}

	d, err := st.GetVuln(ctx, id)
	if err != nil || d == nil {
		t.Fatalf("get: %v %+v", err, d)
	}
	if d.Description == "" || len(d.Criteria) != 1 || len(d.Refs) != 1 {
		t.Fatalf("detail incomplete: %+v", d)
	}
	if d.Published != "2024-01-02T03:04:05Z" {
		t.Fatalf("published=%q", d.Published)
	}

	missing, err := st.GetVuln(ctx, "CVE-9000-9999")
	if err != nil || missing != nil {
		t.Fatalf("absent lookup: %v %+v", err, missing)
	}
}

func TestUpsertIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	id := "CVE-9000-0002"
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, id)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id=$1`, id)
	})
	if err := st.UpsertCVE(ctx, cve(id, "apache", "http_server", "2.4.49", 9.8)); err != nil {
		t.Fatal(err)
	}
	// Same record twice: still one row, one index set (rebuild semantics).
	if err := st.UpsertCVE(ctx, cve(id, "apache", "http_server", "2.4.49", 9.8)); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := st.db.QueryRow(`SELECT count(*) FROM vuln_cves WHERE cve_id=$1`, id).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("rows=%d err=%v", rows, err)
	}
	var prods int
	if err := st.db.QueryRow(`SELECT count(*) FROM vuln_cpe_products WHERE cve_id=$1`, id).Scan(&prods); err != nil || prods != 1 {
		t.Fatalf("index rows=%d err=%v", prods, err)
	}
}

func TestMarkKEVStubAndMerge(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	stubID := "CVE-9000-0003" // unknown to NVD sync → stub row
	mergeID := "CVE-9000-0004"
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id IN ($1,$2)`, stubID, mergeID)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id IN ($1,$2)`, stubID, mergeID)
	})
	added := time.Date(2024, 3, 4, 0, 0, 0, 0, time.UTC)

	if err := st.MarkKEV(ctx, stubID, added); err != nil {
		t.Fatal(err)
	}
	d, err := st.GetVuln(ctx, stubID)
	if err != nil || d == nil || !d.KEV {
		t.Fatalf("stub visible: %v %+v", err, d)
	}

	if err := st.UpsertCVE(ctx, cve(mergeID, "x", "y", "1", 8.0)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkKEV(ctx, mergeID, added); err != nil {
		t.Fatal(err)
	}
	// Now the NVD sync refreshes the same row — the kev flag must survive.
	if err := st.UpsertCVE(ctx, cve(mergeID, "x", "y", "1", 8.0)); err != nil {
		t.Fatal(err)
	}
	d2, err := st.GetVuln(ctx, mergeID)
	if err != nil || d2 == nil || !d2.KEV {
		t.Fatalf("kev flag lost after nvd upsert: %v %+v", err, d2)
	}
}

func TestSyncStateRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const src = "nvd-test"
	t.Cleanup(func() { _, _ = st.db.Exec(`DELETE FROM vuln_sync_state WHERE source=$1`, src) })

	// Absent → zero value with enabled defaulting to true.
	s0, err := st.GetSyncState(ctx, src)
	if err != nil || s0.Cursor != "" || !s0.Enabled {
		t.Fatalf("absent state: %+v err=%v", s0, err)
	}

	ts := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	if err := st.SaveSyncState(ctx, SyncState{
		Source: src, LastSyncAt: &ts, Cursor: "2024-05-06T07:08:09Z", TotalSynced: 42, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	s1, err := st.GetSyncState(ctx, src)
	if err != nil || s1.Cursor != "2024-05-06T07:08:09Z" || s1.TotalSynced != 42 {
		t.Fatalf("state=%+v err=%v", s1, err)
	}
	if s1.LastSyncAt == nil || !s1.LastSyncAt.Equal(ts) {
		t.Fatalf("last_sync_at=%v", s1.LastSyncAt)
	}
}

// CWE 数组的写读闭环 + 两源合并语义：NVD 先写 → GHSA merge 并集去重，
// 谁后写都不该抹掉先写的（cwes 列是 M1「CVE→方法论 skill」联动的数据基础）。
func TestCwesRoundTripAndMerge(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	id := "CVE-9000-0002"
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, id)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id=$1`, id)
	})

	c := cve(id, "acme", "widget", "1.0", 9.8)
	c.Cwes = []string{"CWE-89", "CWE-89", "CWE-79"} // 重复项应在入库前去重（数组归一由 SQL 兜底）
	if err := st.UpsertCVE(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetVuln(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("GetVuln: %v", err)
	}
	if len(got.Cwes) == 0 {
		t.Fatal("UpsertCVE 后 GetVuln 应带出 cwes")
	}
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}
	if !has(got.Cwes, "CWE-89") || !has(got.Cwes, "CWE-79") {
		t.Fatalf("cwes=%v，应含 CWE-89 与 CWE-79", got.Cwes)
	}

	// GHSA merge：补一条 NVD 没有的 CWE，已有值不被覆盖。
	if err := st.mergeGhsaCWEs(ctx, GhsaFinding{ID: id, Cwes: []string{"CWE-200"}}); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.GetVuln(ctx, id)
	if !has(got2.Cwes, "CWE-200") || !has(got2.Cwes, "CWE-89") {
		t.Fatalf("GHSA merge 后 cwes=%v，应为三源并集", got2.Cwes)
	}

	// search_vulns 的命中行也要带出 cwes。
	hits, err := st.SearchVulns(ctx, "acme", "widget", "", 10)
	if err != nil || len(hits) == 0 {
		t.Fatalf("SearchVulns: %v", err)
	}
	if !has(hits[0].Cwes, "CWE-89") {
		t.Fatalf("search hit cwes=%v，应含 CWE-89", hits[0].Cwes)
	}
}
