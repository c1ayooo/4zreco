package vulnintel

import (
	"testing"
)

// semver 区间 → CPE 区间列的转换。
//
// 这层转换错了会**直接导致版本判定反了**（把受影响的判成不受影响），
// 所以每个方向都要有断言。
func TestGhsaRangeToCPERange(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want CPERange
	}{
		{
			name: "小于上界",
			expr: "< 3.10.0",
			want: CPERange{EndExcluding: "3.10.0"},
		},
		{
			name: "小于等于上界",
			expr: "<= 3.10.0",
			want: CPERange{EndIncluding: "3.10.0"},
		},
		{
			name: "大于下界",
			expr: "> 1.0.0",
			want: CPERange{StartExcluding: "1.0.0"},
		},
		{
			name: "大于等于下界",
			expr: ">= 1.0.0",
			want: CPERange{StartIncluding: "1.0.0"},
		},
		{
			name: "等于某版本",
			expr: "= 2.5.0",
			want: CPERange{StartIncluding: "2.5.0", EndIncluding: "2.5.0"},
		},
		{
			name: "复合区间取交集",
			expr: ">= 1.0.0, <= 1.11.0",
			want: CPERange{StartIncluding: "1.0.0", EndIncluding: "1.11.0"},
		},
		{
			name: "有解析不了的片段时整条不可信",
			expr: "^2.0.0",
			want: CPERange{},
		},
		{
			name: "空区间",
			expr: "",
			want: CPERange{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ghsaRangeToCPERange(c.expr)
			if got != c.want {
				t.Errorf("区间 %q 转换错误:\n got %+v\nwant %+v", c.expr, got, c.want)
			}
		})
	}
}

// 转换后的 CPE 区间能被现有的 VersionInRange 逻辑正确判定。
//
// 这一条最关键：转换出的边界必须与 cmpVersions 的比较方向一致
// （version_start_incl: version >= start；version_end_excl: version < end）。
func TestGhsaRangeToCPERangeSemanticsMatchVersionInRange(t *testing.T) {
	// "< 3.10.0" → 3.9.0 受影响，3.10.0 不受影响。
	r := ghsaRangeToCPERange("< 3.10.0")
	if r.StartIncluding != "" || r.StartExcluding != "" {
		t.Fatalf("不该有下界: %+v", r)
	}
	if r.EndExcluding != "3.10.0" {
		t.Fatalf("上界应为排他 3.10.0: %+v", r)
	}
	// 手工按 VersionInRange 的语义验算。
	if !(cmpVersions("3.9.0", "3.10.0") < 0) {
		t.Error("3.9.0 应小于 3.10.0")
	}
	if !(cmpVersions("3.10.0", "3.10.0") >= 0) {
		t.Error("3.10.0 应等于 3.10.0（排他上界 → 不受影响）")
	}
	// ">= 1.0.0, <= 1.11.0" → 1.11.0 受影响，1.11.1 不受影响。
	r2 := ghsaRangeToCPERange(">= 1.0.0, <= 1.11.0")
	if r2.StartIncluding != "1.0.0" || r2.EndIncluding != "1.11.0" {
		t.Fatalf("复合区间转换错误: %+v", r2)
	}
	if !(cmpVersions("1.11.0", "1.11.0") <= 0) {
		t.Error("1.11.0 应落在闭区间内")
	}
	if !(cmpVersions("1.11.1", "1.11.0") > 0) {
		t.Error("1.11.1 应超出闭区间")
	}
}

// 包名 → 倒排索引的 (vendor, product) 形态。
//
// 关键：composer 包名是 `vendor/package`，而 CPE product 是单段——
// 不做形态转换就永远匹配不上资产的技术指纹。
func TestGhsaIndexRows(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "composer", Name: "contao/core-bundle"})
	if len(rows) == 0 {
		t.Fatal("应产生索引行")
	}
	// 必须有 vendor=contao product=core_bundle 这一形态。
	found := false
	for _, r := range rows {
		if r.vendor == "contao" && r.product == "core_bundle" {
			found = true
		}
	}
	if !found {
		t.Errorf("应含 (contao, core_bundle) 形态，实际 %+v", rows)
	}
	// 也应有去连字符的形态（corebundle）——技术指纹写 "Contao" 时靠它兜底。
	foundCompact := false
	for _, r := range rows {
		if r.product == "corebundle" {
			foundCompact = true
		}
	}
	if !foundCompact {
		t.Errorf("应含 corebundle 形态，实际 %+v", rows)
	}
}

// 索引形态要能与技术指纹的 token 匹配上（这是联动的实际判据）。
func TestGhsaIndexRowsMatchTechTokens(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "composer", Name: "contao/core-bundle"})
	tech := techTokens("Contao 5.3")
	hit := false
	for _, r := range rows {
		for _, ct := range cpeTokens(r.product) {
			for _, t := range tech {
				if t == ct {
					hit = true
				}
			}
		}
	}
	if !hit {
		t.Errorf("GHSA 包 contao/core-bundle 应能与技术指纹 %v 匹配上", tech)
	}
}

// 单段包名（无斜杠）也要能索引。
func TestGhsaIndexRowsSingleSegment(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "npm", Name: "lodash"})
	if len(rows) != 1 {
		t.Fatalf("单段包名应产生 1 行，实际 %d: %+v", len(rows), rows)
	}
	if rows[0].product != "lodash" {
		t.Errorf("product 应为 lodash，实际 %q", rows[0].product)
	}
}
