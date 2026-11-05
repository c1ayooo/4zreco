package acllm

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/cloudwego/eino/schema"
)

// Table-driven usage mapping (方案 §4-P1 第 3 条): eino PromptTokens = raw input
// + cache_read + cache_write, with CachedTokens / CacheWriteTokens carried
// separately in PromptTokenDetails. FromToken recovers the raw input by
// subtraction; ToToken rebuilds the provider-style total.
func TestUsageFromTokenTable(t *testing.T) {
	cases := []struct {
		name string
		in   *schema.TokenUsage
		want llm.Usage
	}{
		{
			name: "nil carriers no usage",
			in:   nil,
			want: llm.Usage{},
		},
		{
			name: "claude-style total includes cache read+write (V1 spike)",
			in: &schema.TokenUsage{
				PromptTokens: 16, CompletionTokens: 25,
				PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 4, CacheWriteTokens: 2},
			},
			want: llm.Usage{InputTokens: 10, OutputTokens: 25, CacheReadTokens: 4, CacheWriteTokens: 2},
		},
		{
			name: "openai-style cached tokens are a subset of prompt_tokens (V2 spike)",
			in: &schema.TokenUsage{
				PromptTokens: 10, CompletionTokens: 5,
				PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 3},
			},
			want: llm.Usage{InputTokens: 7, OutputTokens: 5, CacheReadTokens: 3},
		},
		{
			name: "no cache detail at all",
			in:   &schema.TokenUsage{PromptTokens: 100, CompletionTokens: 20},
			want: llm.Usage{InputTokens: 100, OutputTokens: 20},
		},
		{
			name: "cache write only",
			in: &schema.TokenUsage{
				PromptTokens: 30, CompletionTokens: 1,
				PromptTokenDetails: schema.PromptTokenDetails{CacheWriteTokens: 5},
			},
			want: llm.Usage{InputTokens: 25, OutputTokens: 1, CacheWriteTokens: 5},
		},
		{
			name: "total smaller than cache detail falls back to the total (defensive)",
			in: &schema.TokenUsage{
				PromptTokens:       6,
				PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 4, CacheWriteTokens: 4},
			},
			want: llm.Usage{InputTokens: 6, CacheReadTokens: 4, CacheWriteTokens: 4},
		},
		{
			name: "all zero",
			in:   &schema.TokenUsage{},
			want: llm.Usage{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := UsageFromToken(c.in); got != c.want {
				t.Fatalf("UsageFromToken(%+v) = %+v, want %+v", c.in, got, c.want)
			}
		})
	}
}

func TestUsageToTokenTable(t *testing.T) {
	cases := []struct {
		name string
		in   llm.Usage
		want schema.TokenUsage
	}{
		{
			name: "full breakdown",
			in:   llm.Usage{InputTokens: 10, OutputTokens: 25, CacheReadTokens: 4, CacheWriteTokens: 2},
			want: schema.TokenUsage{
				PromptTokens: 16, CompletionTokens: 25, TotalTokens: 41,
				PromptTokenDetails: schema.PromptTokenDetails{CachedTokens: 4, CacheWriteTokens: 2},
			},
		},
		{
			name: "no cache",
			in:   llm.Usage{InputTokens: 100, OutputTokens: 20},
			want: schema.TokenUsage{
				PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120,
			},
		},
		{
			name: "zero usage",
			in:   llm.Usage{},
			want: schema.TokenUsage{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := UsageToToken(c.in)
			if got == nil {
				t.Fatal("UsageToToken returned nil")
			}
			if *got != c.want {
				t.Fatalf("UsageToToken(%+v) = %+v, want %+v", c.in, *got, c.want)
			}
		})
	}
}

// The round trip is an involution for well-formed usage: DTO → eino → DTO.
func TestUsageRoundTripInvolution(t *testing.T) {
	cases := []llm.Usage{
		{InputTokens: 10, OutputTokens: 25, CacheReadTokens: 4, CacheWriteTokens: 2},
		{InputTokens: 7, OutputTokens: 5, CacheReadTokens: 3},
		{},
	}
	for _, u := range cases {
		if back := UsageFromToken(UsageToToken(u)); back != u {
			t.Fatalf("round trip of %+v gave %+v", u, back)
		}
	}
}
