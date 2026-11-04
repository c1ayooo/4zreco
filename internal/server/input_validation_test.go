package server

import (
	"strings"
	"testing"
)

// DB CHECK 约束的前置校验。回归背景：契约巡检发现
// POST /api/llm/profiles 与 POST /api/mcp 在 format/transport 非法时返回
// 500 + SQLSTATE 23514（数据库约束错误直接冒给用户），而 POST
// /api/llm/profiles/active 在 profile 不存在时也返回 500。
// 三者都应是 4xx：调用方能据此纠正请求，而不是看到「服务器内部错误」。

func TestCheckEnumRejectsInvalidValues(t *testing.T) {
	if msg := checkEnum("format", "openai", validLLMProfileFormats); msg != "" {
		t.Fatalf("valid format rejected: %s", msg)
	}
	if msg := checkEnum("format", "gemini", validLLMProfileFormats); msg == "" {
		t.Fatal("invalid format accepted")
	} else if !strings.Contains(msg, "format") || !strings.Contains(msg, "gemini") {
		t.Fatalf("error message should name the field and the value: %s", msg)
	}
	if msg := checkEnum("format", "", validLLMProfileFormats); msg == "" {
		t.Fatal("empty format accepted")
	}
	if msg := checkEnum("transport", "sse", validMCPTransports); msg != "" {
		t.Fatalf("valid transport rejected: %s", msg)
	}
	if msg := checkEnum("transport", "grpc", validMCPTransports); msg == "" {
		t.Fatal("invalid transport accepted")
	}
}

// 合法值集合必须与 db/schema.sql 的 CHECK 保持一致，否则前置校验会放行
// 数据库仍然拒绝的值（又变回 500）。
func TestValidSetsMatchSchemaConstraints(t *testing.T) {
	for _, f := range []string{"openai", "anthropic", "openai-responses"} {
		if !validLLMProfileFormats[f] {
			t.Errorf("format %q must be accepted (schema CHECK allows it)", f)
		}
	}
	if len(validLLMProfileFormats) != 3 {
		t.Errorf("format set size = %d, want 3", len(validLLMProfileFormats))
	}
	for _, tr := range []string{"stdio", "http", "sse"} {
		if !validMCPTransports[tr] {
			t.Errorf("transport %q must be accepted (schema CHECK allows it)", tr)
		}
	}
	if len(validMCPTransports) != 3 {
		t.Errorf("transport set size = %d, want 3", len(validMCPTransports))
	}
}
