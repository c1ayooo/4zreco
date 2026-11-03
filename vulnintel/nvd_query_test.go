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

// NVD 客户端的新查询维度：按 CVE ID 精确查、按 publishedDate 查「近期披露」。
//
// 为什么需要（2026-10-22 的实测）：
//
//  1. **按 ID 查**：现有 FetchPage 只能按 lastModifiedDate 划窗口，要确认某个
//     具体 CVE 是否存在只能扫几百天的窗口（实测 200 天扫描跑了 40 分钟还因
//     代理 TLS 抖动中断）。cveId 参数是一次精确查询，成本是窗口查询的零头。
//
//  2. **按 publishedDate 查**：「刚披露的高危漏洞」要的是**发布时间**，
//     不是 lastModified——后者会把老 CVE 的元数据更新也算进来，而
//     lastModified 窗口的跨度是 120 天、游标按窗口推进，一轮翻不完。
//     近期快通道需要一个小窗口、窄维度的查询。
//
//  3. **CVSS 门槛**：快通道只留高危（CVSS≥9.0 或 KEV），避免把几万条
//     中低危也拉进来。NVD API 不支持按分数过滤，只能拉回来后自己筛——
//     所以 FetchPublished 的结果里要能拿到分数。

// nvdStub 起一个假 NVD，记录收到的查询参数。
func nvdStub(t *testing.T, body string, gotQuery map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.URL.Query() {
			gotQuery[k] = v[0]
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// 按 ID 查询必须把 cveId 传给 API，并且只返回该 ID 的记录。
func TestFetchByCVEIDPassesIDAndReturnsRecord(t *testing.T) {
	body := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-109618",
		"published":"2026-10-01T00:00:00.000","descriptions":[{"lang":"en","value":"test vuln"}],
		"metrics":{}}}]}`
	q := map[string]string{}
	srv := nvdStub(t, body, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	got, err := c.FetchByCVEID(context.Background(), "CVE-2026-109618")
	if err != nil {
		t.Fatal(err)
	}
	if q["cveId"] != "CVE-2026-109618" {
		t.Errorf("cveId 参数=%q，应为 CVE-2026-109618", q["cveId"])
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("返回 %d 条，应为 1 条", len(got.Vulnerabilities))
	}
	if got.Vulnerabilities[0].CVE.ID != "CVE-2026-109618" {
		t.Errorf("返回的 ID=%q", got.Vulnerabilities[0].CVE.ID)
	}
}

// 按 ID 查询不存在的 CVE → 0 条，不是错误。
func TestFetchByCVEIDNotFoundReturnsEmpty(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	got, err := c.FetchByCVEID(context.Background(), "CVE-2020-00000")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vulnerabilities) != 0 {
		t.Errorf("不存在的 CVE 应返回 0 条，实际 %d 条", len(got.Vulnerabilities))
	}
}

// 空 ID 直接报错，不去打 API。
func TestFetchByCVEIDRejectsEmpty(t *testing.T) {
	c := &NvdClient{Base: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	if _, err := c.FetchByCVEID(context.Background(), "  "); err == nil {
		t.Error("空 CVE ID 应报错")
	}
}

// 按发布时间查询必须用 pubStartDate/pubEndDate（不是 lastMod*）。
func TestFetchPublishedUsesPublishDateParams(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	if _, err := c.FetchPublished(context.Background(), 0, 2000, start, end); err != nil {
		t.Fatal(err)
	}
	if q["pubStartDate"] == "" || q["pubEndDate"] == "" {
		t.Errorf("未传 pubStartDate/pubEndDate，实际参数=%v", q)
	}
	if q["lastModStartDate"] != "" || q["lastModEndDate"] != "" {
		t.Errorf("不应传 lastMod* 参数（那是另一个维度），实际参数=%v", q)
	}
	if !strings.HasPrefix(q["pubStartDate"], "2026-10-15") {
		t.Errorf("pubStartDate=%q，应以 2026-10-15 开头", q["pubStartDate"])
	}
}

// 按发布时间查询也要能翻页（startIndex / resultsPerPage）。
func TestFetchPublishedPaginates(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	if _, err := c.FetchPublished(context.Background(), 4000, 500, time.Now().AddDate(0, 0, -7), time.Now()); err != nil {
		t.Fatal(err)
	}
	if q["startIndex"] != "4000" {
		t.Errorf("startIndex=%q，应为 4000", q["startIndex"])
	}
	if q["resultsPerPage"] != "500" {
		t.Errorf("resultsPerPage=%q，应为 500", q["resultsPerPage"])
	}
}

// RecentCritical 只保留「高危」：CVSS≥9.0 或 KEV。
//
// 用途是近期快通道：NVD API 不支持按分数过滤，只能拉回来后自己筛——
// 不筛的话每天几万条中低危会把库和 hint 淹没。
func TestRecentCriticalFiltersBySeverityAndKEV(t *testing.T) {
	mk := func(id, sev string, score float64, kev bool) map[string]any {
		return map[string]any{
			"id":      id,
			"metrics": map[string]any{"cvssMetricV31": []any{map[string]any{"cvssData": map[string]any{"baseScore": score, "baseSeverity": sev}}}},
			"kev":     kev,
		}
	}
	_ = mk
	// 直接测筛选函数本身。severity 字符串刻意不出现在判据里
	//（"CRITICAL" 而无分数是数据异常，不能据此放行）。
	cases := []struct {
		score  *float64
		kev    bool
		wantOK bool
	}{
		{f64(9.8), false, true},
		{f64(9.0), false, true},
		{f64(8.9), false, false},
		{f64(7.5), true, true}, // KEV 优先：已在野利用
		{f64(5.0), false, false},
		{f64(8.5), false, false}, // 分数不够
	}
	for _, c := range cases {
		if got := isRecentCritical(c.score, c.kev); got != c.wantOK {
			t.Errorf("isRecentCritical(score=%v kev=%v)=%v，应为 %v",
				c.score, c.kev, got, c.wantOK)
		}
	}
}

// 分数缺失时（metrics 空）不应误判为高危。
func TestIsRecentCriticalHandlesMissingScore(t *testing.T) {
	if isRecentCritical(nil, false) {
		t.Error("无分数无 KEV 时不应判为高危")
	}
}

// isRecentCritical 的返回值必须是「能进快通道」而不是「一定严重」。
func TestRecentCriticalThresholdIsDocumented(t *testing.T) {
	if recentCriticalScoreThreshold != 9.0 {
		t.Errorf("快通道的分数门槛=%v，应为 9.0", recentCriticalScoreThreshold)
	}
}

// 编译期确认 nvdResponse 的 JSON 标签没被改坏。
func TestNVDResponseTagsUnchanged(t *testing.T) {
	b, err := json.Marshal(nvdResponse{TotalResults: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"totalResults":7`) {
		t.Errorf("nvdResponse 的 JSON 标签变了: %s", b)
	}
}
