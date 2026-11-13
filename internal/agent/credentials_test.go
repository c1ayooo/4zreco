package agent

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

type credentialFixtureProvider struct {
	reply   string
	calls   int
	request llm.CompletionRequest
	stop    string
}

func (p *credentialFixtureProvider) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	p.request = r
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, p.stop, llm.Usage{InputTokens: 123, OutputTokens: 45}, nil
}
func (p *credentialFixtureProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) { panic("credential processor must not stream or run tools") }
}

// TestCredentialStructuredParsingAndExactValues（移植自 ARTEX）：嵌套对象不跨组错配、
// 模型编造的字段被拒绝、JSON 转义值经解码后仍可精确接地。
func TestCredentialStructuredParsingAndExactValues(t *testing.T) {
	raw := `{"credentials":[{"username":"admin","password":"p@ss:<>Word!","url":"https://qa.invalid"},{"token":"qa-token-1234"},{"cookie":"session=a+b=="},{"username":"admin","password":"p@ss:<>Word!","url":"https://qa.invalid"}]}`
	got, ok := ParseCredentialJSON(raw)
	if !ok || len(got) != 3 || got[0].Password != "p@ss:<>Word!" {
		t.Fatalf("parse: %+v %v", got, ok)
	}
	// 嵌套的独立对象之间不得互相配对。
	if _, ok = ParseCredentialJSON(`{"a":{"username":"a"},"b":{"password":"password"}}`); !ok {
		t.Fatal("explicit password-only credential must be preserved")
	}
	if _, err := ValidateCredentialAccounts(raw, []db.CredentialAccount{{Username: "admin", Password: "made-up-secret"}}); err == nil {
		t.Fatal("invented secret accepted")
	}
	got, err := ValidateCredentialAccounts(`{"password":"escaped\\secret"}`, []db.CredentialAccount{{Password: `escaped\secret`}})
	if err != nil || len(got) != 1 {
		t.Fatal("escaped JSON value rejected", err)
	}
}

// TestCredentialModelIsSingleBoundedGroundedCall（移植自 ARTEX）：恰好一次调用、
// 无工具、无历史、输出上限 6000、编造字段拒绝、空结果合法、坏 JSON/截断输出拒绝。
func TestCredentialModelIsSingleBoundedGroundedCall(t *testing.T) {
	raw := "admin:complex-fixture-pass (service)"
	p := &credentialFixtureProvider{reply: `{"accounts":[{"username":"admin","password":"complex-fixture-pass"}]}`}
	got, usage, err := ExtractCredentials(t.Context(), p, "", raw, 0)
	if err != nil || len(got) != 1 || p.calls != 1 || usage.InputTokens != 123 || p.request.MaxTokens != 6000 || len(p.request.Tools) != 0 {
		t.Fatalf("extract: %+v %+v %v calls=%d", got, usage, err, p.calls)
	}
	if len(p.request.Messages) != 1 || strings.Contains(p.request.Messages[0].Text(), "previous conversation") {
		t.Fatal("unexpected context")
	}
	p.reply = `{"accounts":[{"password":"invented"}]}`
	if _, _, err = ExtractCredentials(t.Context(), p, "", raw, 500); err == nil {
		t.Fatal("hallucinated response saved")
	}
	p.reply = `{"accounts":[]}`
	if got, _, err = ExtractCredentials(t.Context(), p, "", raw, 500); err != nil || len(got) != 0 {
		t.Fatal("empty legitimate result rejected")
	}
	p.reply = `not JSON`
	if _, _, err = ExtractCredentials(t.Context(), p, "", raw, 500); err == nil {
		t.Fatal("malformed output accepted")
	}
	p.reply = `{"accounts":[]}`
	p.stop = "max_tokens"
	if _, _, err = ExtractCredentials(t.Context(), p, "", raw, 500); err == nil {
		t.Fatal("truncated response accepted")
	}
}
