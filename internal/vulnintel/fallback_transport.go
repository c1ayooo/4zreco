package vulnintel

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// fallbackTransport 在代理传输失败时回退到直连。
//
// 为什么需要：出网代理不是万能的。实测（2026-10-21）代理 10.10.70.14:7897
// 对 api.github.com 正常（200），但对 www.cisa.gov / services.nvd.nist.gov
// 会「CONNECT 成功、然后 TLS 握手时 unexpected eof」——隧道建起来却不转发数据。
// 于是同一轮同步里 GitHub 源成功、NVD/KEV 源全挂，表现为 EOF。
//
// 而直连这两个源是通的（NVD 200/0.9s，CISA 200/2.2s）。也就是说代理在这里
// 不但没用，还把本来能通的直连路给堵死了。
//
// 只在**传输层失败**时回退（连接被拒/被重置/EOF/超时）。HTTP 层的错误
// （404/403/429）不回退——那是源本身的问题，换条路也还是那个答案，回退只会
// 把一次请求变成两次，徒增配额消耗和限流风险。
type fallbackTransport struct {
	proxy   http.RoundTripper
	direct  http.RoundTripper
	enabled bool
}

// parseProxyURL 解析并校验代理地址。三个 client（NVD/KEV、GitHub、PoC）共用。
func parseProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("vulnintel: bad proxy url: %w", err)
	}
	return u, nil
}

func newFallbackTransport(proxyURL string) (http.RoundTripper, error) {
	direct := http.DefaultTransport.(*http.Transport).Clone()
	// 直连必须真的直连。http.DefaultTransport 会读环境变量
	// HTTP_PROXY / HTTPS_PROXY —— 服务进程带着这些变量启动（systemd 的
	// Environment=），克隆出来的 transport 依然带着代理，于是「回退直连」
	// 又回到同一个坏代理上，等于没回退。显式清掉 Proxy 才是真的直连。
	direct.Proxy = nil
	t := strings.TrimSpace(proxyURL)
	if t == "" {
		return direct, nil
	}
	u, err := parseProxyURL(t)
	if err != nil {
		return nil, err
	}
	proxied := http.DefaultTransport.(*http.Transport).Clone()
	proxied.Proxy = http.ProxyURL(u)
	return &fallbackTransport{proxy: proxied, direct: direct, enabled: true}, nil
}

func (t *fallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.proxy.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	if !t.enabled || !isTransportFailure(err) {
		return resp, err
	}
	// 代理失败 → 直连重试一次。请求体已经被代理消费过（若是流式），重放
	// 可能不完整；但情报源全是 GET，没有请求体，安全。
	if req.Body != nil && req.GetBody == nil {
		return resp, err
	}
	if req.GetBody != nil {
		body, gerr := req.GetBody()
		if gerr != nil {
			return resp, err
		}
		req.Body = body
	}
	return t.direct.RoundTrip(req)
}

// isTransportFailure 判断错误是否属于「换条路可能就好了」这一类。
// HTTP 状态码错误不在此列（那是源的问题，不是路的问题）。
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}
	// 代理返回的 502（Bad Gateway）也是路的问题：代理自己没拿到上游的响应。
	var proxyErr interface{ StatusCode() int }
	if errors.As(err, &proxyErr) && proxyErr.StatusCode() == http.StatusBadGateway {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, m := range []string{
		"eof",                     // TLS 握手/读取时对端断开（代理隧道不转发的典型症状）
		"connection reset",        // 目标或中间设备重置
		"connection refused",      // 端口没人听
		"broken pipe",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
		"tls handshake timeout",
		"unexpected eof",
		"proxyconnect",
		"transport connection broken",
	} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}
