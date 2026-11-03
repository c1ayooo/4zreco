package vulnintel

import (
	"context"
	"testing"
)

func TestCmpVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},        // missing segments = 0
		{"1.10", "1.9", 1},         // numeric not lexical
		{"2.4.49", "2.4.50", -1},   //
		{"1.0b3", "1.0", -1},       // suffix sorts below bare number
		{"v2.4.49", "2.4.49", 0},   // leading v tolerated
		{"3.0", "2.99.9", 1},       //
		{"1.2.3.4", "1.2.3", 1},    // longer wins when prefix equal
	}
	for _, c := range cases {
		if got := cmpVersions(c.a, c.b); got != c.want {
			t.Errorf("cmpVersions(%q,%q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const id = "CVE-9000-0007"
	const product = "http_server"
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, id)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id=$1`, id)
	})

	// 影响区间 [2.4.49, 2.4.51):NVD 常见表达 start_incl=2.4.49 / end_excl=2.4.51
	c := cve(id, "apache", product, "2.4.49", 9.8)
	c.Ranges = []CPERange{{
		Criteria:       "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		StartIncluding: "2.4.49",
		EndExcluding:   "2.4.51",
	}}
	if err := st.UpsertCVE(ctx, c); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		v    string
		want bool
	}{
		{"2.4.49", true},  // start inclusive
		{"2.4.50", true},  // inside
		{"2.4.51", false}, // end exclusive
		{"2.4.48", false}, // before
		{"2.5", false},    // after
	}
	for _, tc := range cases {
		in, comparable := st.VersionInRange(ctx, id, product, tc.v)
		if !comparable {
			t.Fatalf("version %s: no comparable range stored", tc.v)
		}
		if in != tc.want {
			t.Errorf("VersionInRange(%s) = %v want %v", tc.v, in, tc.want)
		}
	}
	// 其他 product 无区间 → not comparable
	if _, comparable := st.VersionInRange(ctx, id, "tomcat", "7.0"); comparable {
		t.Error("unrelated product reported comparable")
	}
}
