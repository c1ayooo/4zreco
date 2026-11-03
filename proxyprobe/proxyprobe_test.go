package proxyprobe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// socks5HandshakeServer 起一个最小 SOCKS5 服务器：完成握手后把请求回显成
// 一个 HTTP 响应。用来验证客户端真的走了 SOCKS 隧道，而不是静默直连。
func socks5HandshakeServer(t *testing.T, seen *string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00}) // 选「无认证」
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 0x01:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					b := make([]byte, l[0])
					io.ReadFull(c, b)
					host = string(b)
				case 0x04:
					b := make([]byte, 16)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				}
				portBuf := make([]byte, 2)
				io.ReadFull(c, portBuf)
				port := int(binary.BigEndian.Uint16(portBuf))
				if seen != nil {
					*seen = net.JoinHostPort(host, itoa(port))
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				buf := make([]byte, 1024)
				c.Read(buf)
				body := "SOCKS-OK"
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(body)) +
					"\r\nConnection: close\r\n\r\n" + body))
			}(c)
		}
	}()
	return ln
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// socks5:// 必须建立 SOCKS 隧道。
// 回归背景：原来只用 http.ProxyURL，喂 socks5:// 会得到
// "unsupported protocol scheme"——用户填了 socks 代理但下载照样失败。
func TestProbeSocks5UsesTunnel(t *testing.T) {
	var seen string
	ln := socks5HandshakeServer(t, &seen)
	res := Probe(context.Background(), "socks5://"+ln.Addr().String(),
		"http://example.test/whatever", "")
	if !res.OK {
		t.Fatalf("经 socks5 代理应判为可用: %s", res.Error)
	}
	if !strings.HasPrefix(seen, "example.test:") {
		t.Errorf("SOCKS 服务器应看到目标主机名 example.test,看到 %q", seen)
	}
	if res.Scheme != "socks5" {
		t.Errorf("scheme 应为 socks5,得到 %q", res.Scheme)
	}
}

// socks5h 也要走 SOCKS（h = 把 DNS 解析也交给代理）。
func TestProbeSocks5hUsesTunnel(t *testing.T) {
	var seen string
	ln := socks5HandshakeServer(t, &seen)
	res := Probe(context.Background(), "socks5h://"+ln.Addr().String(), "http://example.test/x", "")
	if !res.OK {
		t.Fatalf("经 socks5h 代理应判为可用: %s", res.Error)
	}
	if !strings.HasPrefix(seen, "example.test:") {
		t.Errorf("socks5h 应把主机名原样交给代理,看到 %q", seen)
	}
}

// http 代理仍走 CONNECT，不能因为加了 socks 分支就坏掉。
func TestClientForHTTPProxySetsProxy(t *testing.T) {
	c, err := ClientFor("http://127.0.0.1:1/", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport 类型不对")
	}
	if tr.Proxy == nil {
		t.Error("http 代理应当设置 tr.Proxy")
	}
	u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "x.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || u.Host != "127.0.0.1:1" {
		t.Errorf("http 代理应生效,得到 %v", u)
	}
}

// Normalize 把用户随手写的形式补成标准 URL。
func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"10.0.0.14:7897":            "http://10.0.0.14:7897",
		"10.0.0.14:7897/":           "http://10.0.0.14:7897",
		"http://10.0.0.14:7897":     "http://10.0.0.14:7897",
		"socks5://h:1080":           "socks5://h:1080",
		"socks5h://h:1080":          "socks5h://h:1080",
		"  http://u:p@h:1080  ":      "http://u:p@h:1080",
		"\"http://10.0.0.14:7897\"":  "http://10.0.0.14:7897",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q,期望 %q", in, got, want)
		}
	}
}

// Validate 拒绝不认识的协议与缺端口的地址。
func TestValidate(t *testing.T) {
	if _, err := Validate(""); err != nil {
		t.Errorf("空串应通过(直连): %v", err)
	}
	for _, ok := range []string{
		"http://10.0.0.14:7897",
		"https://h:443",
		"socks5://h:1080",
		"socks5h://h:1080",
		"http://user:pass@10.0.0.14:7897",
	} {
		if _, err := Validate(ok); err != nil {
			t.Errorf("Validate(%q) 应通过: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"ss://h:1080",       // 不支持的协议
		"vless://h:1080",    // 不支持的协议
		"http://h",          // 缺端口
		"http://:7897",      // 缺主机
		"http://h:7897\nx",  // 含换行(会被当成 argv 注入面)
	} {
		if _, err := Validate(bad); err == nil {
			t.Errorf("Validate(%q) 应报错", bad)
		}
	}
}

// 代理不可达时不能挂死：必须快速失败并给出可执行提示。
func TestProbeUnreachableProxyFailsFast(t *testing.T) {
	start := time.Now()
	res := Probe(context.Background(), "socks5://127.0.0.1:1", "http://x.test/", "")
	if res.OK {
		t.Error("不可达的代理应判为不可用")
	}
	if res.Error == "" {
		t.Error("应给出错误信息")
	}
	if res.Hint == "" {
		t.Error("应给出修复提示")
	}
	if time.Since(start) > 25*time.Second {
		t.Errorf("探测耗时过长: %v", time.Since(start))
	}
}

// 空代理 = 直连，判定为可用并说明。
func TestProbeEmptyProxyIsDirect(t *testing.T) {
	res := Probe(context.Background(), "", "", "")
	if !res.OK {
		t.Error("空代理应判为可用(直连)")
	}
	if res.Hint == "" {
		t.Error("应说明这是直连")
	}
}
