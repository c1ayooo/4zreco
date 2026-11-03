// Package proxyprobe:出网代理的连通性自测。
//
// 为什么要单独一个包:代理有两处使用者——install.sh 装机期(走 curl)和
// 运行期(走 Go 的 http.Client)。两边的「怎么算通」必须一致,否则会出现
// 「装机说通了、运行时却连不上」的割裂。判定口径统一放这里。
//
// 判定标准用 GitHub API:装机流程本来就要访问它,自测与实际用途同源。
// HTTP 200/301/302 都算通(403 是 GitHub 限流,链路本身是通的)。
package proxyprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Result 是一次代理自测的结果。
type Result struct {
	OK        bool   `json:"ok"`
	Proxy     string `json:"proxy"`
	Scheme    string `json:"scheme"`
	LatencyMS int64  `json:"latency_ms"`
	Status    int    `json:"status"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// DefaultProbeURL 默认探测目标：GitHub 的 release API（装机流程本来就要访问它）。
const DefaultProbeURL = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"

// Validate 校验代理地址格式。空串 = 直连，返回 nil。
//
// 只允许 http/https/socks5/socks5h：这三个协议是 hostd 的下载器、
// apt 的 Acquire 代理、以及 curl 的 -x 都能理解的交集。写成别的（比如
// ss:// 或 vless://）不会有任何组件能用它，静默失败比报错更糟。
func Validate(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.ContainsAny(raw, "\n\r\t ") {
		return "", fmt.Errorf("代理地址含非法空白字符")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("代理地址无法解析: %v", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("代理协议不支持: %q（支持 http/https/socks5/socks5h）", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("代理地址缺少 host:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", fmt.Errorf("代理地址缺少 host:port")
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("代理地址缺少 host:port")
	}
	return u.String(), nil
}

// Normalize 把用户随手写的形式补成标准 URL：
//   "10.0.0.14:7897"        → http://10.0.0.14:7897（本地代理多是 http 混合口）
//   "10.0.0.14:7897/"       → 同上
//   "socks5://h:1080"       → 原样
// 空串原样返回（=直连）。
func Normalize(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.Trim(s, "\"'")
	s = strings.TrimRight(s, "/")
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	return s
}

// ClientFor 按协议构造带代理的 HTTP 客户端。导出给 hostd 的下载器复用，
// 保证「装机期下载」和「运行期自测」用的是同一套代理语义。
//
// socks5 必须走 x/net/proxy 的 SOCKS5 dialer：net/http 的 ProxyURL 只懂
// HTTP CONNECT 代理，喂它 socks5:// 会得到 "unsupported protocol scheme"——
// 表现就是「填了 socks 代理但下载照样失败」，而用户完全看不出是协议不匹配。
func ClientFor(proxyURL string, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "socks5", "socks5h":
			d, err := newSocksDialer(u)
			if err != nil {
				return nil, err
			}
			tr.Proxy = nil // SOCKS 已在 dial 层生效
			tr.DialContext = d.DialContext
		default:
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// clientFor 是 ClientFor 的包内别名。
func clientFor(proxyURL string, timeout time.Duration) (*http.Client, error) {
	return ClientFor(proxyURL, timeout)
}

type socksDialer struct{ d proxy.Dialer }

func (s *socksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.d.Dial(network, addr)
}

// newSocksDialer 把 socks5 URL 转成 dialer（带认证）。
// socks5h 与 socks5 在此等价：DNS 解析交给代理侧（h = hostname 交给代理解析）。
func newSocksDialer(u *url.URL) (*socksDialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return &socksDialer{d: d}, nil
}

// Probe 对一个代理做一次真实请求，给出可用性与诊断信息。
//
// probeURL 为空时用 DefaultProbeURL。exitIPURL 非空时额外请求一次
// 拿出口 IP（SOCKS5 场景下用户最关心「到底走没走代理」）。
func Probe(ctx context.Context, proxyURL, probeURL, exitIPURL string) Result {
	res := Result{Proxy: proxyURL}
	if proxyURL == "" {
		res.OK = true
		res.Hint = "未配置代理，直连"
		return res
	}
	if u, err := url.Parse(proxyURL); err == nil {
		res.Scheme = u.Scheme
	}
	if probeURL == "" {
		probeURL = DefaultProbeURL
	}

	c, err := clientFor(proxyURL, 20*time.Second)
	if err != nil {
		res.Error = err.Error()
		res.Hint = hintFor(res.Scheme, res.Error)
		return res
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Hint = hintFor(res.Scheme, res.Error)
		return res
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	res.Status = resp.StatusCode

	switch {
	case resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302:
		res.OK = true
	case resp.StatusCode == 403:
		// GitHub 限流：链路是通的，只是被限流。不算失败，但要说明。
		res.OK = true
		res.Hint = "GitHub 返回 403（限流），链路通但当前被限流"
	default:
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		res.Hint = "代理能连上但目标返回异常状态码，可能是代理改写了响应或被拦截"
	}

	if res.OK && exitIPURL != "" {
		if ip, err := fetchExitIP(ctx, c, exitIPURL); err == nil {
			res.ExitIP = ip
		}
	}
	return res
}

// fetchExitIP 读一次出口 IP。失败不影响整体判定（很多出口不提供这个服务）。
func fetchExitIP(ctx context.Context, c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	// 有些服务返回 {"ip":"1.2.3.4"} 这样的 JSON
	if i := strings.Index(ip, `"ip"`); i >= 0 {
		rest := ip[i+4:]
		if j := strings.Index(rest, `"`); j >= 0 {
			ip = rest[:j]
		}
	}
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return strings.Trim(ip, `"`), nil
}

// hintFor 按错误文本给出可执行的修复建议。
func hintFor(scheme, errMsg string) string {
	low := strings.ToLower(errMsg)
	switch {
	case strings.Contains(low, "unsupported protocol scheme"):
		return "代理协议与组件不匹配：apt 只认 http 代理，socks5 请另配"
	case strings.Contains(low, "no such host"), strings.Contains(low, "dns"):
		return "代理主机名解析失败，检查地址是否写对"
	case strings.Contains(low, "connection refused"):
		return "代理端口没人监听，检查端口号"
	case strings.Contains(low, "timeout"), strings.Contains(low, "deadline exceeded"):
		return "代理连通超时：可能被墙或需换端口"
	case strings.Contains(low, "certificate"), strings.Contains(low, "tls"):
		return "TLS 握手失败：https 代理需要证书，或改用 http://"
	case strings.Contains(low, "407"):
		return "代理要求认证：格式写成 http://user:pass@host:port"
	case strings.Contains(low, "permission denied"):
		return "无权使用该代理，可能需要认证信息"
	}
	if scheme == "socks5" || scheme == "socks5h" {
		return "SOCKS5 代理不可用，检查端口与是否需要认证"
	}
	return "代理不可用，检查地址、端口与认证信息"
}
