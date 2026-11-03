package vulnintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 真实 GHSA 响应样本（2026-10-22 实抓 api.github.com/advisories?cve_id=CVE-2026-85990）。
//
// 保留原样而不是构造一个"好看的"样本：真实数据里有两个坑——
//  1. first_patched_version 是**字符串** "3.10.0"，不是 {"identifier": ...}；
//  2. references 是**字符串数组**，不是对象数组。
// 照着"想象中"的格式写测试，这两处就都测不出来。
const ghsaRealAdvisory = `[
  {
    "ghsa_id": "GHSA-54mm-6729-r5wp",
    "cve_id": "CVE-2026-85990",
    "html_url": "https://github.com/Leantime/leantime/security/advisories/GHSA-54mm-6729-r5wp",
    "summary": "Leantime: Any Authenticated User Can Self-Escalate to Admin via Unauthorized JSON-RPC Methods",
    "description": "Leantime 3.9.0 and below are vulnerable.",
    "severity": "high",
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8},
    "cvss_severity": null,
    "published_at": "2026-10-15T20:14:43Z",
    "updated_at": "2026-10-15T20:14:44Z",
    "withdrawn_at": null,
    "vulnerabilities": [
      {
        "package": {"ecosystem": "composer", "name": "leantime/leantime"},
        "vulnerable_version_range": "< 3.10.0",
        "first_patched_version": "3.10.0",
        "vulnerable_functions": []
      }
    ],
    "references": [
      "https://github.com/Leantime/leantime/security/advisories/GHSA-54mm-6729-r5wp",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-85990"
    ],
    "cwes": [
      {"cwe_id": "CWE-269", "name": "Improper Privilege Management"},
      {"cwe_id": "CWE-862", "name": "Missing Authorization"}
    ]
  }
]`

// 真实响应能解析出包、区间与修复版本。
func TestParseGhsaFromRealAdvisory(t *testing.T) {
	var advs []GhsaAdvisory
	if err := json.Unmarshal([]byte(ghsaRealAdvisory), &advs); err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("应有 1 条 advisory，实际 %d", len(advs))
	}
	f := ParseGhsa(advs[0])

	if f.ID != "CVE-2026-85990" {
		t.Errorf("主键应为 CVE 号，实际 %q", f.ID)
	}
	if f.GHSID != "GHSA-54mm-6729-r5wp" {
		t.Errorf("GHSA 号解析错误: %q", f.GHSID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("严重度应为 HIGH，实际 %q", f.Severity)
	}
	if f.Score == nil || *f.Score != 8.8 {
		t.Errorf("CVSS 分数应为 8.8，实际 %v", f.Score)
	}
	if len(f.Packages) != 1 {
		t.Fatalf("应有 1 个受影响包，实际 %d", len(f.Packages))
	}
	p := f.Packages[0]
	if p.Ecosystem != "composer" || p.Name != "leantime/leantime" {
		t.Errorf("包信息错误: %+v", p)
	}
	if p.Range != "< 3.10.0" {
		t.Errorf("版本区间错误: %q", p.Range)
	}
	// 真实 API 里 first_patched_version 是字符串——这个坑必须被测到。
	if p.PatchedVersion != "3.10.0" {
		t.Errorf("修复版本应为 3.10.0，实际 %q", p.PatchedVersion)
	}
	if len(f.Refs) != 2 {
		t.Errorf("应有 2 条引用，实际 %d", len(f.Refs))
	}
	if len(f.Cwes) != 2 || f.Cwes[0] != "CWE-269" {
		t.Errorf("CWE 解析错误: %v", f.Cwes)
	}
	if f.Published.IsZero() {
		t.Error("发布时间未解析")
	}
}

// 没有 CVE 号的 advisory 也要留——版本区间才是我们要的东西。
func TestParseGhsaKeepsAdvisoryWithoutCVE(t *testing.T) {
	f := ParseGhsa(GhsaAdvisory{GHSID: "GHSA-xxxx-yyyy-zzzz", Summary: "some issue"})
	if f.ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("无 CVE 号时主键应为 GHSA 号，实际 %q", f.ID)
	}
}

// first_patched_version 的对象形态（OSV 生态用）也要认。
func TestParseGhsaAcceptsObjectPatchedVersion(t *testing.T) {
	var advs []GhsaAdvisory
	raw := `[{"ghsa_id":"GHSA-a","summary":"x","vulnerabilities":[{"package":{"ecosystem":"npm","name":"p"},"vulnerable_version_range":"< 1.2.3","first_patched_version":{"identifier":"1.2.3"}}]}]`
	if err := json.Unmarshal([]byte(raw), &advs); err != nil {
		t.Fatal(err)
	}
	f := ParseGhsa(advs[0])
	if f.Packages[0].PatchedVersion != "1.2.3" {
		t.Errorf("对象形态的修复版本应解析出，实际 %q", f.Packages[0].PatchedVersion)
	}
}

// semver 区间判定：命中/不命中/边界。
func TestGhsaVersionAffected(t *testing.T) {
	pkg := GhsaPackage{Ecosystem: "composer", Name: "leantime/leantime", Range: "< 3.10.0", PatchedVersion: "3.10.0"}
	cases := []struct {
		version string
		want    bool
		why     string
	}{
		{"3.9.0", true, "低于上界 → 受影响"},
		{"3.10.0", false, "等于上界（< 是排除）→ 不受影响"},
		{"3.10.1", false, "高于上界 → 不受影响"},
		{"2.0.0", true, "远低于上界 → 受影响"},
		{"3.9", true, "两段版本号 → 低于 3.10.0 → 受影响"},
		{"4.0", false, "高于上界 → 不受影响"},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			got := GhsaVersionAffected(pkg, c.version)
			if got.Affected != c.want {
				t.Errorf("版本 %s: Affected=%v，应为 %v（%s）\n理由: %s",
					c.version, got.Affected, c.want, c.why, got.Reason)
			}
		})
	}
}

// 复合区间（AND）：两个条件都要满足。
func TestGhsaVersionAffectedCompositeRange(t *testing.T) {
	pkg := GhsaPackage{Name: "react/http", Range: ">= 1.0.0, <= 1.11.0"}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.5.0", true},
		{"0.9.0", false},  // 低于下界
		{"1.11.0", true},  // 等于上界（<= 含）
		{"1.11.1", false}, // 高于上界
		{"2.0.0", false},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			got := GhsaVersionAffected(pkg, c.version)
			if got.Affected != c.want {
				t.Errorf("版本 %s: Affected=%v，应为 %v\n理由: %s", c.version, got.Affected, c.want, got.Reason)
			}
		})
	}
}

// **保守策略**：拿不准时一律判「可能受影响」。
//
// 判错方向是不对称的：误判「不受影响」会让模型直接跳过漏洞——
// 而这正是新披露 CVE 最容易丢的地方。所以解析失败必须往「可能受影响」偏。
func TestGhsaVersionAffectedIsConservative(t *testing.T) {
	cases := []struct {
		name    string
		pkg     GhsaPackage
		version string
	}{
		{"版本解析不出", GhsaPackage{Name: "p", Range: "< 3.10.0"}, "8.3.1-dev-build"},
		{"区间为空", GhsaPackage{Name: "p", Range: ""}, "1.0.0"},
		{"区间算子不认识", GhsaPackage{Name: "p", Range: "^2.0.0"}, "2.5.0"},
		{"区间是自然语言", GhsaPackage{Name: "p", Range: "all versions before 3.10"}, "3.0.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GhsaVersionAffected(c.pkg, c.version)
			if !got.Affected {
				t.Errorf("拿不准时应判「可能受影响」，实际判了不受影响: %s", got.Reason)
			}
			if got.Reason == "" {
				t.Error("应给出判定理由")
			}
		})
	}
}

// 预发布版本比同号正式版小（semver 规范）。
func TestSemverPreReleaseOrdering(t *testing.T) {
	a := parseSemver("1.0.0-alpha")
	b := parseSemver("1.0.0")
	if !a.Valid || !b.Valid {
		t.Fatal("解析失败")
	}
	if compareSemver(a, b) != -1 {
		t.Error("预发布版应小于正式版")
	}
	if compareSemver(b, a) != 1 {
		t.Error("正式版应大于预发布版")
	}
}

// 版本号解析：各种写法都要认。
func TestParseSemver(t *testing.T) {
	cases := []struct {
		in    string
		major int
		minor int
		patch int
		valid bool
	}{
		{"1.2.3", 1, 2, 3, true},
		{"v1.2.3", 1, 2, 3, true},
		{"8.3.1", 8, 3, 1, true},
		{"4.8.1", 4, 8, 1, true},
		{"1.2", 1, 2, 0, true},
		{"1", 1, 0, 0, true},
		{"1.2.3-rc1", 1, 2, 3, true},
		{"1.2.3RC1", 1, 2, 3, true},
		{"", 0, 0, 0, false},
		{"abc", 0, 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := parseSemver(c.in)
			if got.Valid != c.valid {
				t.Fatalf("valid=%v，应为 %v", got.Valid, c.valid)
			}
			if !c.valid {
				return
			}
			if got.Major != c.major || got.Minor != c.minor || got.Patch != c.patch {
				t.Errorf("解析为 %d.%d.%d，应为 %d.%d.%d",
					got.Major, got.Minor, got.Patch, c.major, c.minor, c.patch)
			}
		})
	}
}

// 版本区间「未确认」的两种形态。
func TestGhsaRangeUndetermined(t *testing.T) {
	noPkg := GhsaFinding{GHSID: "GHSA-a"}
	if !GhsaRangeUndetermined(noPkg) {
		t.Error("没有包信息应算未确认")
	}
	emptyRange := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: ""}}}
	if !GhsaRangeUndetermined(emptyRange) {
		t.Error("有包但区间为空应算未确认")
	}
	withRange := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: "< 3.10.0"}}}
	if GhsaRangeUndetermined(withRange) {
		t.Error("有明确区间不应算未确认")
	}
}

// 客户端：按 CVE 查、拉列表（增量过滤）。
func TestGhsaClientFetchByCVEID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cve_id"); got != "CVE-2026-85990" {
			t.Errorf("cve_id 参数错误: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ghsaRealAdvisory))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	advs, err := c.FetchByCVEID(context.Background(), "CVE-2026-85990")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("应有 1 条，实际 %d", len(advs))
	}
	f := ParseGhsa(advs[0])
	if f.ID != "CVE-2026-85990" || f.Packages[0].Range != "< 3.10.0" {
		t.Errorf("解析结果错误: %+v", f)
	}
}

// 增量：since 之前的条目要被滤掉。
func TestGhsaClientFetchAdvisoriesFiltersBySince(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("sort"); got != "updated" {
			t.Errorf("sort 参数应为 updated，实际 %q", got)
		}
		if got := r.URL.Query().Get("direction"); got != "desc" {
			t.Errorf("direction 参数应为 desc，实际 %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"ghsa_id":"GHSA-new","cve_id":"CVE-1","summary":"new","updated_at":"2026-10-22T10:00:00Z"},
			{"ghsa_id":"GHSA-old","cve_id":"CVE-2","summary":"old","updated_at":"2026-10-01T10:00:00Z"}
		]`))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	since, err := time.Parse(time.RFC3339, "2026-10-20T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	advs, err := c.FetchAdvisories(context.Background(), since, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("应只剩 1 条（新的），实际 %d", len(advs))
	}
	if advs[0].GHSID != "GHSA-new" {
		t.Errorf("留下的应是新条目，实际 %q", advs[0].GHSID)
	}
}

// 错误状态码要报出来（不能静默当成"没有数据"——那会让同步看起来成功）。
func TestGhsaClientReportsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	_, err := c.FetchByCVEID(context.Background(), "CVE-2026-1")
	if err == nil {
		t.Fatal("403 应报错")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("错误信息应含状态码，实际 %q", err.Error())
	}
}

// GHSA 的版本区间判定与 NVD 的「版本待定」是同一件事的两个来源——
// 任一来源能确定就算确定。
func TestGhsaAndNvdUndeterminedAreIndependent(t *testing.T) {
	// NVD 侧：版本区间为空 → 待定。
	nvdEmpty := CVE{ID: "CVE-1", Criteria: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}}
	if !VersionRangeUndetermined(nvdEmpty) {
		t.Error("NVD 版本区间为空应判待定")
	}
	// GHSA 侧：有明确区间 → 不待定。
	f := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: "< 3.10.0"}}}
	if GhsaRangeUndetermined(f) {
		t.Error("GHSA 有明确区间不应判待定")
	}
	// GHSA 侧：区间也空 → 仍待定（两源都没信息）。
	f2 := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: ""}}}
	if !GhsaRangeUndetermined(f2) {
		t.Error("GHSA 区间为空应判待定")
	}
}

// GHSA 的提示文案要说清「不代表不受影响」——否则模型会直接跳过。
func TestGhsaVersionNoteWording(t *testing.T) {
	f := GhsaFinding{
		GHSID:    "GHSA-abc",
		Packages: []GhsaPackage{{Name: "leantime/leantime", Range: "< 3.10.0", PatchedVersion: "3.10.0"}},
	}
	note := GhsaVersionNote(f)
	if note == "" {
		t.Fatal("提示不应为空")
	}
	for _, want := range []string{"leantime/leantime", "3.10.0", "GHSA-abc"} {
		if !strings.Contains(note, want) {
			t.Errorf("提示应含 %q，实际 %q", want, note)
		}
	}
}
