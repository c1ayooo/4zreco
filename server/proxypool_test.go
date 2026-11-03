package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// 批量导入的行解析：用户从付费站导出的格式五花八门，解析器必须认得常见几种，
// 并且不把注释/空行当条目。
func TestParseProxyLine(t *testing.T) {
	cases := []struct {
		raw      string
		wantURL  string
		wantName string
		comment  bool
	}{
		{"1.2.3.4:8080", "http://1.2.3.4:8080", "", false},
		{"http://1.2.3.4:8080", "http://1.2.3.4:8080", "", false},
		{"socks5://user:pass@5.6.7.8:1080", "socks5://user:pass@5.6.7.8:1080", "", false},
		{"1.2.3.4:8080:user:pass", "http://user:pass@1.2.3.4:8080", "", false},
		{"HK-01 | 1.2.3.4:8080", "http://1.2.3.4:8080", "HK-01", false},
		{"# comment", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		name, u, comment, err := parseProxyLine(c.raw)
		if err != nil {
			t.Errorf("parseProxyLine(%q) err=%v", c.raw, err)
			continue
		}
		if comment != c.comment {
			t.Errorf("parseProxyLine(%q) comment=%v want %v", c.raw, comment, c.comment)
		}
		if c.comment {
			continue
		}
		if u != c.wantURL {
			t.Errorf("parseProxyLine(%q) url=%q want %q", c.raw, u, c.wantURL)
		}
		if name != c.wantName {
			t.Errorf("parseProxyLine(%q) name=%q want %q", c.raw, name, c.wantName)
		}
	}
}

// 批量导入要能识别非法行并逐行报告，而不是整批失败。
func TestProxyPoolBulkReportsInvalidLines(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	body, _ := json.Marshal(map[string]any{
		"text": "# 注释\n1.2.3.4:8080\nsocks5://u:p@5.6.7.8:1080\n",
		"mode": "replace",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Added   int `json:"added"`
		Invalid []struct {
			Line   int    `json:"line"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 {
		t.Errorf("added=%d want 2", res.Added)
	}
	// 「not a url at all」含空格且不是合法 host:port，应被判为非法行。
	bad := "not a url at all"
	body, _ = json.Marshal(map[string]any{"text": bad, "mode": "replace"})
	req = httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w = httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	res.Invalid = nil
	res.Added = 0
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Invalid) != 1 {
		t.Fatalf("invalid=%+v want 1 条", res.Invalid)
	}
	if res.Invalid[0].Line != 1 {
		t.Errorf("line=%d want 1", res.Invalid[0].Line)
	}
	if res.Invalid[0].Reason == "" {
		t.Error("非法行必须带原因")
	}
}

// 代理池的连通性验证：好代理判可用，坏代理判不可用。
// 用一个本地 HTTP 代理当"好代理"，探测目标也用本地服务——不依赖外网。
func TestProxyPoolCheckDistinguishesGoodAndBad(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	// 目标服务
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer target.Close()
	// 好代理：把请求原样转发到目标
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse(target.URL)
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer good.Close()

	entries := []map[string]any{
		{"url": good.URL, "name": "good", "enabled": true, "weight": 1},
		{"url": "http://127.0.0.1:1", "name": "bad", "enabled": true, "weight": 1},
	}
	body, _ := json.Marshal(map[string]any{"entries": entries, "strategy": "round_robin"})
	req := httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolPut(w, req)
	if w.Code != 200 {
		t.Fatalf("put status=%d body=%s", w.Code, w.Body.String())
	}

	body, _ = json.Marshal(map[string]any{
		"target": target.URL, "break_on_fail": true, "timeout_seconds": 3,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/proxypool/check", bytes.NewReader(body))
	w = httptest.NewRecorder()
	s.proxyPoolCheck(w, req)
	if w.Code != 200 {
		t.Fatalf("check status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Results []struct {
			URL string `json:"url"`
			OK  bool   `json:"ok"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("results=%d want 2", len(res.Results))
	}
	okCount := 0
	for _, r := range res.Results {
		if r.OK {
			okCount++
		}
	}
	if okCount != 1 {
		t.Errorf("可用=%d want 1（好代理应通、坏代理应不通）", okCount)
	}
}

// 漏洞情报的错误提示：页面上"坏了因为啥坏的看不到"是原问题，
// 这里保证常见错误都能翻成可执行的建议。
func TestVulnIntelErrorHint(t *testing.T) {
	cases := []struct {
		err  string
		want string
	}{
		{"kev feed status 404: <!DOCTYPE html>", "404"},
		{"nvd api decode: context deadline exceeded", "超时"},
		{"dial tcp: lookup www.cisa.gov: no such host", "DNS"},
		{"proxyconnect tcp: connection refused", "代理"},
		{"status 429: rate limit exceeded", "限速"},
	}
	for _, c := range cases {
		hint := vulnIntelErrorHint(c.err)
		if hint == "" {
			t.Errorf("vulnIntelErrorHint(%q) 为空", c.err)
			continue
		}
		if !bytes.Contains([]byte(hint), []byte(c.want)) {
			t.Errorf("vulnIntelErrorHint(%q)=%q，期望包含 %q", c.err, hint, c.want)
		}
	}
	if vulnIntelErrorHint("") != "" {
		t.Error("无错误时不应给建议")
	}
	_ = time.Second
}
