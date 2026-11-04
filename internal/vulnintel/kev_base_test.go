package vulnintel

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FetchKEV 必须打 cisa.gov，而不是 NVD 的 Base。
//
// 线上表现是每轮同步都刷 "kev feed status 404" + 一段 XHTML 错误页：URL 被拼成
// https://services.nvd.nist.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// （实测 curl 同一路径确实返回 404 的 XHTML）。KEV 因此从未同步成功过。
//
// 这里把生产客户端的默认 Base 原样喂进去，只替换 Transport 观察实际请求的地址。
func TestFetchKEVUsesCisaHostNotNvdBase(t *testing.T) {
	var requested []string
	prod := &NvdClient{
		Base: "https://services.nvd.nist.gov", // NewNvdClient 设的就是这个
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requested = append(requested, r.URL.Scheme+"://"+r.URL.Host+r.URL.Path)
			return nil, context.Canceled // 只关心地址，不必真跑完
		})},
	}
	_, _ = prod.FetchKEV(context.Background())

	if len(requested) != 1 {
		t.Fatalf("expected exactly one request, got %v", requested)
	}
	if !strings.HasPrefix(requested[0], "https://www.cisa.gov/") {
		t.Fatalf("KEV must hit cisa.gov, got %s", requested[0])
	}
	if !strings.HasSuffix(requested[0], "/sites/default/files/feeds/known_exploited_vulnerabilities.json") {
		t.Fatalf("unexpected KEV path: %s", requested[0])
	}
}
