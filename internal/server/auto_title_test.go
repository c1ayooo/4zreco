package server

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

type autoTitleProvider struct {
	reply string
	err   error
	req   llm.CompletionRequest
}

func (p *autoTitleProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.req = req
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, "stop", llm.Usage{}, nil
}

func (p *autoTitleProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func TestGenerateAutoTitleCleansResponse(t *testing.T) {
	long := strings.Repeat("很长", 30)
	p := &autoTitleProvider{reply: "\n\"标题：" + long + "\"\n第二行"}
	got, err := generateAutoTitle(t.Context(), p, "用户希望整理项目设置")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "标题：") || strings.HasPrefix(got, "\"") || len([]rune(got)) > autoTitleMaxRunes {
		t.Fatalf("unclean title %q", got)
	}
	if p.req.Thinking != "disabled" || p.req.MaxTokens != 96 || len(p.req.Tools) != 0 {
		t.Fatalf("request options: %+v", p.req)
	}

	quoted := &autoTitleProvider{reply: `标题："整理项目设置"`}
	got, err = generateAutoTitle(t.Context(), quoted, "整理项目设置")
	if err != nil {
		t.Fatal(err)
	}
	if got != "整理项目设置" {
		t.Fatalf("nested quote/prefix cleanup: got %q", got)
	}
}

func TestGenerateAutoTitleProviderError(t *testing.T) {
	if _, err := generateAutoTitle(t.Context(), &autoTitleProvider{err: errors.New("boom")}, "内容"); err == nil {
		t.Fatal("expected provider error")
	}
	if _, err := generateAutoTitle(t.Context(), nil, "内容"); err == nil {
		t.Fatal("expected nil provider error")
	}
	if _, err := generateAutoTitle(t.Context(), &autoTitleProvider{reply: "标题"}, "  "); err == nil {
		t.Fatal("expected empty content error")
	}
}

func TestCleanAutoTitle(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"整理项目设置", "整理项目设置"},
		{"  整理项目设置  ", "整理项目设置"},
		{"\"整理项目设置\"", "整理项目设置"},
		{"'整理项目设置'", "整理项目设置"},
		{"“整理项目设置”", "整理项目设置"},
		{"「整理项目设置」", "整理项目设置"},
		{"标题：整理项目设置", "整理项目设置"},
		{"标题:整理项目设置", "整理项目设置"},
		{"\"标题：整理项目设置\"\n第二行说明", "整理项目设置"},
		{"整理\t项目  设置", "整理 项目 设置"}, // 制表/重复空白折叠
		{"整理\t项目 \n 设置", "整理 项目"},   // 换行截断先于空白折叠（只留首行）
		{"", ""},
	}
	for _, tc := range cases {
		if got := cleanAutoTitle(tc.raw); got != tc.want {
			t.Errorf("cleanAutoTitle(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	long := strings.Repeat("标", autoTitleMaxRunes + 5)
	if got := cleanAutoTitle(long); len([]rune(got)) != autoTitleMaxRunes {
		t.Errorf("rune cap: got %d runes", len([]rune(got)))
	}
}

func TestAutoTitleMayReplace(t *testing.T) {
	for _, current := range []string{"", "新对话", "首条消息预览"} {
		if !autoTitleMayReplace(current, "首条消息预览") {
			t.Errorf("expected %q to be replaceable", current)
		}
	}
	if autoTitleMayReplace("用户手动改的标题", "首条消息预览") {
		t.Error("manual title must not be overwritten")
	}
}

func TestAutoTitleIsUsable(t *testing.T) {
	for _, generated := range []string{"", "新对话"} {
		if autoTitleIsUsable(generated) {
			t.Errorf("placeholder title %q must be rejected", generated)
		}
	}
	if !autoTitleIsUsable("整理项目设置") {
		t.Error("generated title should be accepted")
	}
}
