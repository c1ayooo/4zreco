package server

import "testing"

// v0.4.42 移植：autobind 的纯函数部分——文本里的主机提取与截断。
func TestExtractHosts(t *testing.T) {
	text := "GET http://Admin.Example.COM/login via https://10.0.0.1:8443/admin and cdn.example.com\n" +
		"also http://localhost:3000 and single-word host"
	hosts := extractHosts(text)
	for _, want := range []string{"admin.example.com", "10.0.0.1", "cdn.example.com"} {
		if !hosts[want] {
			t.Errorf("missing host %q in %v", want, hosts)
		}
	}
	// localhost 无点、裸单词不是主机
	if hosts["localhost"] {
		t.Errorf("localhost must not be treated as host")
	}
}

func TestExtractHostsFullWidthPunctuation(t *testing.T) {
	// 全角括号连带文案不应把括号内容并进主机（与 URL 正则同一教训）
	hosts := extractHosts("见 http://evil.test/admin（说明文字）")
	if len(hosts) != 1 || !hosts["evil.test"] {
		t.Fatalf("hosts=%v want only evil.test", hosts)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abcdefgh", 4); got != "abcd…" {
		t.Fatalf("got %q", got)
	}
	if got := truncateRunes("中文截断测试", 3); got != "中文截…" {
		t.Fatalf("got %q (must count runes, not bytes)", got)
	}
	if got := truncateRunes("  short  ", 40); got != "short" {
		t.Fatalf("got %q", got)
	}
}

func TestIsDocArtifactName(t *testing.T) {
	for _, name := range []string{"a.doc", "a.docx", "a.xls", "a.xlsx", "a.pdf", "a.odt", "a.pptx", "a.rtf"} {
		if !isDocArtifactName(name) {
			t.Errorf("%q should be doc", name)
		}
	}
	for _, name := range []string{"a.json", "a.log", "a.txt", "a.zip"} {
		if isDocArtifactName(name) {
			t.Errorf("%q should not be doc", name)
		}
	}
}
