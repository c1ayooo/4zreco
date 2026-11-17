package db

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// 多键去重（finding_keys.go 移植）：键生成与强弱键判定（纯函数）。
func TestStrongFindingKeyRank(t *testing.T) {
	// endpoint/param/name/asset_class 是弱键（rank 99）——只进提示不自动合并。
	for _, kind := range []string{FindingKeyEndpoint, FindingKeyParam, FindingKeyName, FindingKeyAssetClass} {
		if got := strongFindingKeyRank(kind); got != 99 {
			t.Errorf("rank(%s)=%d want 99", kind, got)
		}
	}
	if r := strongFindingKeyRank(FindingKeyRoot); r >= 99 {
		t.Errorf("root must be strong: %d", r)
	}
	if r := strongFindingKeyRank(FindingKeyCVE); r >= 99 {
		t.Errorf("cve must be strong: %d", r)
	}
	if r := strongFindingKeyRank(FindingKeyLegacy); r >= 99 {
		t.Errorf("legacy must be strong: %d", r)
	}
}

func TestNormalizeRootCauseKey(t *testing.T) {
	if got := normalizeRootCauseKey("Admin Panel Bypass!"); got != "admin-panel-bypass" {
		t.Fatalf("got %q", got)
	}
	// 通用词/过短/空 → 不构成根因标识
	for _, in := range []string{"", "  ", "xss", "VULN", "auth", "ab", "未知漏洞"} {
		if got := normalizeRootCauseKey(in); got != "" {
			t.Errorf("normalizeRootCauseKey(%q)=%q want empty", in, got)
		}
	}
}

func TestNormalizeFindingEndpoint(t *testing.T) {
	cases := map[string]string{
		"http://Evil.test/Admin/Panel?id=1": "evil.test/Admin/Panel", // host 小写,路径保大小写,去 query
		"http://evil.test":                  "evil.test/",            // 无路径 = 根(被 findingEndpointIsRoot 拒绝)
		"https://evil.test/admin/":          "evil.test/admin",       // 去尾斜杠
		"/admin/panel":                      "/admin/panel",
		"http://ho st":                      "", // fail-closed:解析失败的假 URL 不构成身份
	}
	for in, want := range cases {
		if got := normalizeFindingEndpoint(in); got != want {
			t.Errorf("normalizeFindingEndpoint(%q)=%q want %q", in, got, want)
		}
	}
	if !findingEndpointIsRoot(normalizeFindingEndpoint("http://evil.test")) {
		t.Fatal("bare base URL must be root endpoint")
	}
	// 全角标点连带文案在 URL 提取层就被截掉（findingURLRe 排除全角括号），
	// 只剩 "http://host" → 裸基址 → 不产生 endpoint 键。
	m := firstFindingURL(RecordFindingInput{Evidence: "见 http://host（说明文字）"})
	if m != "http://host" {
		t.Fatalf("firstFindingURL=%q want http://host", m)
	}
	if ep := normalizeFindingEndpoint(m); !findingEndpointIsRoot(ep) {
		t.Fatalf("endpoint=%q want root", ep)
	}
}

func TestFindingDedupKeysShape(t *testing.T) {
	in := RecordFindingInput{
		VulnClass:    "sqli",
		Name:         "Union SQLi on /login（完整证据）", // 括号后缀剥掉
		Severity:     "high",
		Summary:      "leaks CVE-2024-12345 and cve-2023-1 (too short)",
		Evidence:     "GET http://evil.test/admin/panel?id=1",
		AssetIDs:     []int64{7, 3},
		RootCauseKey: "Union Dump Superadmin",
		Parameter:    "id",
	}
	keys := FindingDedupKeys(in, "fp123")
	byKind := map[string][]string{}
	for _, k := range keys {
		byKind[k.Kind] = append(byKind[k.Kind], k.Key)
	}
	if got := byKind[FindingKeyRoot]; len(got) != 1 || got[0] != "root:union-dump-superadmin" {
		t.Fatalf("root keys=%v", byKind[FindingKeyRoot])
	}
	if got := byKind[FindingKeyCVE]; len(got) != 1 || got[0] != "cve:CVE-2024-12345" {
		t.Fatalf("cve keys=%v (短编号 cve-2023-1 不该命中)", byKind[FindingKeyCVE])
	}
	if got := byKind[FindingKeyEndpoint]; len(got) != 1 || got[0] != "endpoint:evil.test/admin/panel" {
		t.Fatalf("endpoint keys=%v", byKind[FindingKeyEndpoint])
	}
	if got := byKind[FindingKeyParam]; len(got) != 1 || got[0] != "param:evil.test/admin/panel:id" {
		t.Fatalf("param keys=%v", byKind[FindingKeyParam])
	}
	if got := byKind[FindingKeyLegacy]; len(got) != 1 || got[0] != "legacy:fp123" {
		t.Fatalf("legacy keys=%v", byKind[FindingKeyLegacy])
	}
	if got := byKind[FindingKeyName]; len(got) != 1 || got[0] != "name:union sqli on /login" {
		t.Fatalf("name keys=%v (括号后缀必须剥掉)", byKind[FindingKeyName])
	}
	if got := byKind[FindingKeyAssetClass]; len(got) != 1 || got[0] != "asset_class:3,7:sqli" {
		t.Fatalf("asset_class keys=%v (资产 id 必须排序)", byKind[FindingKeyAssetClass])
	}
}

// 裸资产基址（host+/）不生成 endpoint 键，否则同资产全部漏洞共享一个键。
func TestFindingDedupKeysRootURLOnly(t *testing.T) {
	in := RecordFindingInput{
		Name:     "Webshell at http://base.test/",
		Evidence: "see http://base.test/",
	}
	for _, k := range FindingDedupKeys(in, "") {
		if k.Kind == FindingKeyEndpoint {
			t.Fatalf("bare base URL must not yield endpoint key: %v", k)
		}
	}
}

// ── 集成（连真 PG）：强键自动合并 / 弱键只提示 ─────────────────────────────

func newFindingKeysTestDB(t *testing.T) (*DB, *Task) {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("finding keys test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	return d, task
}

func findingKeysTestAsset(t *testing.T, d *DB, domain string) int64 {
	t.Helper()
	var id int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain) VALUES ('service',$1,'test') RETURNING id`, domain).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	return id
}

func findingKeysCount(t *testing.T, d *DB, findingID int64) map[string]int {
	t.Helper()
	rows, err := d.Query(`SELECT kind, count(*) FROM finding_keys WHERE finding_id=$1 GROUP BY kind`, findingID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			t.Fatal(err)
		}
		out[kind] = n
	}
	return out
}

// root 强键命中 → 自动合并进原记录；endpoint 弱键命中 → 不合并但进 merge_candidates。
func TestRecordFindingMultiKeyMerge(t *testing.T) {
	d, task := newFindingKeysTestDB(t)
	ctx := context.Background()

	asset := findingKeysTestAsset(t, d, "mkeys.test")

	// ① 显式 root_cause_key 的上报
	r1, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "sqli", Name: "SQLi in search", Severity: "high",
		Summary: "first", Evidence: "http://mkeys.test/s?q=1",
		Worker: "w1", AssetIDs: []int64{asset}, RootCauseKey: "shared root cause 01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Duplicate {
		t.Fatal("first report must not be duplicate")
	}

	// ② 不同 vulnclass/name（指纹必不同），但同一 root_cause_key → 强键合并
	r2, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "xss", Name: "Reflected XSS elsewhere", Severity: "critical",
		Summary: "second", Evidence: "different evidence body entirely",
		Worker: "w2", AssetIDs: []int64{asset}, RootCauseKey: "shared root cause 01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Duplicate || r2.FindingID != r1.FindingID {
		t.Fatalf("root-key hit must merge into #%d: dup=%v id=%d", r1.FindingID, r2.Duplicate, r2.FindingID)
	}

	var ev, sev, rootKey string
	if err := d.QueryRow(`SELECT evidence, severity, COALESCE(root_cause_key,'') FROM findings WHERE id=$1`, r1.FindingID).Scan(&ev, &sev, &rootKey); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev, "different evidence body") || !strings.Contains(ev, "mkeys.test/s?q=1") {
		t.Fatal("merged evidence lost one of the reports")
	}
	if sev != "critical" {
		t.Fatalf("severity=%q want critical (只升不降)", sev)
	}
	if rootKey != "shared-root-cause-01" {
		t.Fatalf("root_cause_key=%q", rootKey)
	}
	kinds := findingKeysCount(t, d, r1.FindingID)
	if kinds[FindingKeyRoot] < 1 || kinds[FindingKeyLegacy] < 2 {
		t.Fatalf("keys on merged finding=%v (两次上报的 legacy 键都该落上)", kinds)
	}

	// ③ 弱键(endpoint)命中但语义不同 → 不合并，新行 + merge_candidates 提示
	r3, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "infoleak", Name: "Debug page exposed",
		Summary: "debug console reachable", Evidence: "open http://mkeys.test/s?q=1",
		Worker: "w3", AssetIDs: []int64{asset},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r3.Duplicate {
		t.Fatal("endpoint 弱键命中绝不允许自动合并")
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("rows=%d want 2 (强键合并 1 行 + 弱键新行 1 行)", rows)
	}

	// merge_candidates：f3 与 f1 共享 endpoint 弱键
	cands, err := d.FindingMergeCandidates(ctx, r3.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cands {
		if c.ID == r1.FindingID {
			found = true
		}
	}
	if !found {
		t.Fatalf("endpoint 弱键候选必须提示 f#%d，got %v", r1.FindingID, cands)
	}
}

// finding_cases 候选打分联动：共享弱键的记录进候选并带「同弱键」hit_reason。
func TestFindingCaseCandidatesKeyLinkage(t *testing.T) {
	d, task := newFindingKeysTestDB(t)
	ctx := context.Background()
	asset := findingKeysTestAsset(t, d, "linkage.test")

	f1, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "sqli", Name: "Alpha injection", Severity: "high",
		Summary: "alpha", Evidence: "endpoint http://linkage.test/console/logs",
		Worker: "w1", AssetIDs: []int64{asset},
	})
	if err != nil {
		t.Fatal(err)
	}
	f2, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "infoleak", Name: "Beta disclosure", Severity: "low",
		Summary: "beta", Evidence: "same endpoint http://linkage.test/console/logs",
		Worker: "w2", AssetIDs: []int64{asset},
	})
	if err != nil {
		t.Fatal(err)
	}

	cands, _, _, err := d.FindingCaseCandidates(f1.FindingID, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	var hit map[string]any
	for _, c := range cands {
		if c["finding_id"] == strconv.FormatInt(f2.FindingID, 10) {
			hit = c
		}
	}
	if hit == nil {
		t.Fatalf("候选必须包含弱键命中的 f#%d（类型/名称都不重叠）: %+v", f2.FindingID, cands)
	}
	reasons, _ := hit["hit_reasons"].([]string)
	okReason := false
	for _, r := range reasons {
		if strings.Contains(r, "同弱键") {
			okReason = true
		}
	}
	if !okReason {
		t.Fatalf("hit_reasons=%v 必须含「同弱键」", reasons)
	}
	if score, _ := hit["score"].(int); score < 1 {
		t.Fatalf("弱键命中至少 +1 分，got %v", hit["score"])
	}
}
