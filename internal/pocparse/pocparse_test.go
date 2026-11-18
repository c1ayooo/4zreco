package pocparse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	return b
}

// 上游 v1.6.5 语义：完整模板的全部字段归一化，Content 保留原文。
func TestParseBasicTemplate(t *testing.T) {
	raw := readTestdata(t, "basic.yaml")
	tpl, err := Parse(raw, "")
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if tpl.TemplateID != "CVE-2021-44228-log4j-rce" {
		t.Errorf("TemplateID=%q", tpl.TemplateID)
	}
	if tpl.Name != "Apache Log4j2 JNDI RCE" {
		t.Errorf("Name=%q", tpl.Name)
	}
	// severity 大小写归一化
	if tpl.Severity != "critical" {
		t.Errorf("Severity=%q, want critical", tpl.Severity)
	}
	// requests 是 http 协议的历史别名
	if tpl.Protocol != "http" {
		t.Errorf("Protocol=%q, want http", tpl.Protocol)
	}
	if tpl.CVEID != "CVE-2021-44228" || tpl.CWEID != "CWE-502" {
		t.Errorf("CVEID=%q CWEID=%q", tpl.CVEID, tpl.CWEID)
	}
	if tpl.CVSSScore == nil || *tpl.CVSSScore != 10.0 {
		t.Errorf("CVSSScore=%v, want 10.0", tpl.CVSSScore)
	}
	if len(tpl.Tags) != 3 || tpl.Tags[0] != "log4j" {
		t.Errorf("Tags=%v", tpl.Tags)
	}
	// author 序列 → 逗号串
	if tpl.Author != "pdteam,dwisiswant0" {
		t.Errorf("Author=%q", tpl.Author)
	}
	if len(tpl.References) != 1 || !strings.Contains(tpl.References[0], "CVE-2021-44228") {
		t.Errorf("References=%v", tpl.References)
	}
	if len(tpl.Digest) != 64 {
		t.Errorf("Digest 应为 64 位 hex，得到 %q", tpl.Digest)
	}
	// Content 保原文：不能是有损往返后的重排 YAML
	if !strings.Contains(tpl.Content, "matchers:") || strings.HasPrefix(tpl.Content, "id:") == false {
		t.Errorf("Content 未保留原始 YAML 结构: %q", tpl.Content)
	}
}

// 缺 id → fallbackID；再缺 → slug（同名稳定、异名不同）。
func TestParseFallbackIDAndSlug(t *testing.T) {
	raw := readTestdata(t, "minimal.yaml")
	tpl, err := Parse(raw, "import-row-42")
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if tpl.TemplateID != "import-row-42" {
		t.Errorf("无 id 时应使用 fallbackID，得到 %q", tpl.TemplateID)
	}
	if tpl.Severity != "medium" {
		t.Errorf("moderate 应归一化为 medium，得到 %q", tpl.Severity)
	}
	if tpl.Protocol != "" {
		t.Errorf("无协议键时 Protocol 应为空，得到 %q", tpl.Protocol)
	}
	if tpl.CVSSScore != nil {
		t.Errorf("无 cvss-score 时应为 nil，得到 %v", *tpl.CVSSScore)
	}

	a, err := Parse(raw, "")
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !strings.HasPrefix(a.TemplateID, "my-custom-poc-") {
		t.Errorf("slug 形式不符: %q", a.TemplateID)
	}
	b, _ := Parse(raw, "")
	if a.TemplateID != b.TemplateID {
		t.Errorf("同名 slug 应稳定: %q vs %q", a.TemplateID, b.TemplateID)
	}
	c, _ := Parse([]byte("info:\n  name: Other POC\n"), "")
	if c.TemplateID == a.TemplateID {
		t.Errorf("异名 slug 不应相同: %q", c.TemplateID)
	}
}

func TestParseProtocolDetection(t *testing.T) {
	cases := map[string]string{
		"http":      "http",
		"requests":  "http",
		"tcp":       "network",
		"udp":       "network",
		"network":   "network",
		"dns":       "dns",
		"headless":  "headless",
		"workflows": "workflow",
		"":          "",
	}
	for key, want := range cases {
		content := "info:\n  name: P\n"
		if key != "" {
			content += key + ":\n  - x: 1\n"
		}
		tpl, err := Parse([]byte(content), "")
		if err != nil {
			t.Fatalf("%s: Parse 失败: %v", key, err)
		}
		if tpl.Protocol != want {
			t.Errorf("%s: Protocol=%q, want %q", key, tpl.Protocol, want)
		}
	}
}

func TestParseSeverityNormalization(t *testing.T) {
	cases := map[string]string{
		"info": "info", "informational": "info", "LOW": "low",
		"medium": "medium", "moderate": "medium", "high": "high",
		"CRITICAL": "critical", "weird": "unknown", "": "unknown",
	}
	for raw, want := range cases {
		if got := normalizeSeverity(raw); got != want {
			t.Errorf("normalizeSeverity(%q)=%q, want %q", raw, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte("  \n\t"), ""); err == nil || !strings.Contains(err.Error(), "为空") {
		t.Errorf("空内容应报错，得到 %v", err)
	}
	if _, err := Parse(readTestdata(t, "broken.yaml"), ""); err == nil || !strings.Contains(err.Error(), "YAML 解析失败") {
		t.Errorf("坏 YAML 应报解析失败，得到 %v", err)
	}
	if _, err := Parse([]byte("id: x\ninfo:\n  severity: high\n"), ""); err == nil || !strings.Contains(err.Error(), "info.name") {
		t.Errorf("缺 info.name 应报错，得到 %v", err)
	}
}

// BOM / NUL / 非法 UTF-8：入库面（PostgreSQL text）不接受 NUL，解析面先清掉。
func TestParseSanitizesText(t *testing.T) {
	raw := append([]byte{0xEF, 0xBB, 0xBF}, []byte("info:\n  name: \"P\\0OC\"\n")...)
	tpl, err := Parse(raw, "")
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if strings.ContainsRune(tpl.Name, '\x00') || strings.ContainsRune(tpl.Content, '\x00') {
		t.Errorf("NUL 未被清除: name=%q", tpl.Name)
	}
	if !strings.HasPrefix(strings.TrimSpace(tpl.Content), "info:") {
		t.Errorf("BOM 未剥离: %q", tpl.Content)
	}
	if got := sanitizeText("\xff\xfeok"); got != "ok" {
		t.Errorf("非法 UTF-8 应被丢弃，得到 %q", got)
	}
}
