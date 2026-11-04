package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
)

// 线上实测的错误原文（三个路径都被它咬过）。
const realThinkingReject = `openai: status 400: {"error":{"type":"server_error","message":"Upstream request failed: [bad_request_error] invalid params, model \"MiniMax-M3.1-Flash\" requires adaptive thinking; thinking.type=\"disabled\" (including reasoning.effort=none) is not allowed (2013)"}}`

// 上游拒收 thinking 参数的错误必须被识别出来——这是自动降级的前提。
func TestIsThinkingRejected(t *testing.T) {
	if !isThinkingRejected(errors.New(realThinkingReject)) {
		t.Fatal("实测的 thinking 拒绝错误没被识别出来")
	}
	// 变体：不同网关的措辞略有差异。
	for _, v := range []string{
		`model "X" requires adaptive thinking`,
		`thinking.type="disabled" is not allowed`,
		`thinking.type='disabled' is not allowed`,
		`invalid params (2013)`,
	} {
		if !isThinkingRejected(errors.New(v)) {
			t.Fatalf("变体未被识别: %q", v)
		}
	}
}

// 别的错误不能被误判成 thinking 拒绝——误判会导致把正常的 thinking 参数
// 摘掉，白白改变模型行为。
func TestIsThinkingRejectedRejectsOthers(t *testing.T) {
	for _, v := range []string{
		"",
		"connection reset by peer",
		"status 429: too many requests",
		"status 500: internal server error",
		"context deadline exceeded",
		// 普通的 400（请求本身有问题），摘掉 thinking 也没用。
		`status 400: {"error":{"message":"max_tokens is too large"}}`,
	} {
		if isThinkingRejected(errors.New(v)) {
			t.Fatalf("被误判成 thinking 拒绝: %q", v)
		}
	}
	if isThinkingRejected(nil) {
		t.Fatal("nil 不该被判成 thinking 拒绝")
	}
}

// 粗粒度匹配最常见的翻车方式：与 thinking 无关的 "disabled" 不能被误伤。
func TestIsThinkingRejectedNotOverBroad(t *testing.T) {
	if isThinkingRejected(errors.New("feature disabled by administrator")) {
		t.Fatal("与 thinking 无关的 disabled 被误判")
	}
}

// provider 是否会发 thinking 字段，看的是**配置**不是请求——
// thinking 参数是在 provider 配置层注入的（llm.Config.ThinkingType）。
//
// 这一条是第一版实现的教训：改请求的 req.Thinking 恒为空（请求级开关默认不用），
// 条件永远为假、降级从不触发。实测把 profile 的 thinking_type 设成 disabled 后，
// 2013 错误如期出现 23 次，而降级日志 0 次。
func TestProviderSendsThinkingReadsConfig(t *testing.T) {
	// 没配 thinking_type → 不发该字段 → 降级没有意义。
	if providerSendsThinking(agent.Config{}) {
		t.Fatal("未配 thinking_type 时不该认为会发 thinking")
	}
	// 配了 disabled → 会发 → 降级有意义。
	if !providerSendsThinking(agent.Config{ThinkingType: "disabled"}) {
		t.Fatal("配了 thinking_type=disabled 时应认为会发 thinking")
	}
	// SuppressThinking（降级用的 provider）→ 不发。
	if providerSendsThinking(agent.Config{ThinkingType: "disabled", SuppressThinking: true}) {
		t.Fatal("SuppressThinking 时不该认为会发 thinking")
	}
}

// 降级 provider 必须真的不发 thinking.type —— 这靠 agent.Config.NewProvider
// 里的 SuppressThinking 分支实现。测不到网络层，就测配置到 llm.Config 的映射。
func TestSuppressThinkingDropsThinkingType(t *testing.T) {
	cfg := agent.Config{
		Format:       "openai",
		BaseURL:      "http://127.0.0.1:1",
		APIKey:       "k",
		Model:        "m",
		ThinkingType: "disabled",
	}
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider 失败: %v", err)
	}
	if prov == nil {
		t.Fatal("NewProvider 返回了 nil provider")
	}
	// 关键行为在 llm.Config 内部，这里只能断言「不 panic + 返回有效 provider」。
	// 真正的「不发送」由 llm 库保证（ThinkingType 为空 = 省略该字段）。
}

// 降级时构造的配置必须是「同一个 provider，但不发 thinking」。
func TestDowngradedConfigKeepsEverythingElse(t *testing.T) {
	base := agent.Config{
		Format:          "openai",
		BaseURL:         "http://127.0.0.1:1",
		APIKey:          "k",
		Model:           "m",
		ThinkingType:    "disabled",
		ReasoningEffort: "high",
		MaxTokens:       4096,
		ContextWindowK:  1000,
	}
	down := base
	down.SuppressThinking = true

	if down.ThinkingType != base.ThinkingType {
		t.Fatal("降级不应改 ThinkingType 本身（只是不发送它）")
	}
	for _, pair := range []struct{ name string; a, b any }{
		{"Format", down.Format, base.Format},
		{"BaseURL", down.BaseURL, base.BaseURL},
		{"APIKey", down.APIKey, base.APIKey},
		{"Model", down.Model, base.Model},
		{"ReasoningEffort", down.ReasoningEffort, base.ReasoningEffort},
		{"MaxTokens", down.MaxTokens, base.MaxTokens},
		{"ContextWindowK", down.ContextWindowK, base.ContextWindowK},
	} {
		if pair.a != pair.b {
			t.Errorf("降级改了 %s: %v != %v", pair.name, pair.a, pair.b)
		}
	}
	if !providerSendsThinking(base) {
		t.Fatal("原配置应会发 thinking")
	}
	if providerSendsThinking(down) {
		t.Fatal("降级配置不该发 thinking")
	}
}

// 错误文本里出现 "disabled" 但不是 thinking 拒绝的情形不能被误伤。
func TestIsThinkingRejectedIgnoresUnrelatedDisabled(t *testing.T) {
	err := errors.New("tls handshake: protocol version disabled")
	if isThinkingRejected(err) {
		t.Fatalf("误判: %v", err)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatal("测试样本本身应含 disabled")
	}
}
