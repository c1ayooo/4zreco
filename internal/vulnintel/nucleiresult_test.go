package vulnintel

import (
	"strings"
	"testing"
)

const nucleiSample = `{"template_id":"CVE-2021-41773","name":"Apache Path Traversal","severity":"high","host":"https://t.example","matched_at":"https://t.example/cgi-bin/.%2e/","type":"http","timestamp":"2026-11-19T10:00:00Z","curl_command":"curl -H 'Cookie: sid=SECRET123' https://t.example","request":"GET / HTTP/1.1\r\nAuthorization: Bearer TOPSECRET\r\n\r\n","response":"root:x:0:0","extracted":["/etc/passwd"]}
{"template_id":"tech-detect","name":"Nginx","severity":"info","host":"https://t.example","matched_at":"https://t.example","type":"http","response":"nginx"}
`

func TestParseNucleiJSONLBasic(t *testing.T) {
	hits, stats, err := ParseNucleiJSONL(nucleiSample)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(hits) != 2 || stats.Parsed != 2 || stats.Lines != 2 {
		t.Fatalf("hits=%d parsed=%d lines=%d", len(hits), stats.Parsed, stats.Lines)
	}
	if stats.Severity["high"] != 1 || stats.Severity["info"] != 1 {
		t.Errorf("severity 统计不符: %v", stats.Severity)
	}
	if hits[0].TemplateID != "CVE-2021-41773" || hits[0].Extracted[0] != "/etc/passwd" {
		t.Errorf("字段解析不符: %+v", hits[0])
	}
}

func TestParseNucleiJSONLRedactsSecrets(t *testing.T) {
	hits, _, err := ParseNucleiJSONL(nucleiSample)
	if err != nil {
		t.Fatal(err)
	}
	joined := hits[0].Curl + "\n" + hits[0].Request
	for _, leak := range []string{"SECRET123", "TOPSECRET"} {
		if strings.Contains(joined, leak) {
			t.Errorf("凭据未脱敏，仍含 %q: %s", leak, joined)
		}
	}
	if !strings.Contains(joined, "Cookie: ***") || !strings.Contains(joined, "Authorization: ***") {
		t.Errorf("应保留头名并抹值: %s", joined)
	}
}

func TestParseNucleiJSONLDedupAndBadLines(t *testing.T) {
	text := strings.Join([]string{
		`{"template_id":"x","name":"X","severity":"high","matched_at":"https://a"}`,
		`{"template_id":"x","name":"X","severity":"high","matched_at":"https://a"}`, // 重复
		`not json at all`,         // 坏行
		`{"stats":{"matched":0}}`, // nuclei 进度行
		``,                        // 空行
		`{"template_id":"y","name":"Y","severity":"medium","matched_at":"https://b"}`,
	}, "\n")
	hits, stats, err := ParseNucleiJSONL(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("去重后应剩 2 条，得到 %d", len(hits))
	}
	if stats.Duplicates != 1 {
		t.Errorf("duplicates=%d, want 1", stats.Duplicates)
	}
	if stats.Skipped != 2 {
		t.Errorf("skipped=%d, want 2（坏行 + 进度行）", stats.Skipped)
	}
	if len(stats.SkippedAt) != 2 {
		t.Errorf("坏行摘要条数=%d", len(stats.SkippedAt))
	}
}

func TestParseNucleiJSONLEmpty(t *testing.T) {
	hits, stats, err := ParseNucleiJSONL("  \n\n")
	if err != nil || len(hits) != 0 || stats.Lines != 0 {
		t.Fatalf("空输入应返回空结果: hits=%d err=%v", len(hits), err)
	}
}

func TestPacketText(t *testing.T) {
	if got := PacketText("ok\x00"); got != "ok" {
		t.Errorf("NUL 应被丢弃: %q", got)
	}
	// 0xff 不是合法 UTF-8 → 转义成 \xff
	if got := PacketText("a\xffb"); got != `a\xffb` {
		t.Errorf("非法字节应转义: %q", got)
	}
	if got := PacketText("中文 ok"); got != "中文 ok" {
		t.Errorf("合法文本不应被改写: %q", got)
	}
}

func TestRedactSecretsVariants(t *testing.T) {
	cases := map[string]string{
		"Cookie: a=1; b=2":                  "Cookie: ***",
		"authorization: Basic dXNlcjpwYXNz": "authorization: ***",
		"-H 'X-API-Key: k-123456'":          "-H 'X-API-Key: ***'",
		"GET / HTTP/1.1\r\nHost: t\r\n":     "GET / HTTP/1.1\r\nHost: t\r\n",
	}
	for in, want := range cases {
		if got := RedactSecrets(in); got != want {
			t.Errorf("RedactSecrets(%q)=%q, want %q", in, got, want)
		}
	}
}
