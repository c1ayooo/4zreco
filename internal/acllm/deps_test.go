package acllm

import (
	"context"
	"net/http"
	"testing"

	"github.com/Autumn-27/norma/llm"
	eclaude "github.com/cloudwego/eino-ext/components/model/claude"
	eopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// This file is the P1 依赖尖刺 in-repo (方案 §4-P1 第 1 条): the four pinned
// modules (cloudwego/eino v0.9.21, eino-ext model/claude v0.1.26, model/openai
// v0.1.13, eino-contrib/jsonschema v1.0.3) must resolve and wire together on
// THIS module's dependency tree. Construction only — no request is sent (the
// injected HTTP client would never be dialed), keeping the test hermetic. It
// also keeps the adapter modules required (not // indirect) so `go mod tidy`
// preserves the exact pins the boundary gate locks.
//
// Wire-level behavior of these adapters (streaming usage split, thinking
// signature Extra keys, GetBody replay) was spike-verified on 4zrec against the
// same versions (V1/V2, docs/eino-migration.md 已验证结论) and is not re-tested
// here against the network.

func TestPinnedAdaptersWireUp(t *testing.T) {
	ctx := context.Background()
	client := &http.Client{} // never dialed: no call is made in this test

	cl, err := eclaude.NewChatModel(ctx, &eclaude.Config{
		APIKey:     "spike-key",
		Model:      "claude-spike",
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("claude adapter does not wire up: %v", err)
	}
	var _ model.ToolCallingChatModel = cl

	oai, err := eopenai.NewChatModel(ctx, &eopenai.ChatModelConfig{
		APIKey:     "spike-key",
		Model:      "gpt-spike",
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("openai adapter does not wire up: %v", err)
	}
	var _ model.ToolCallingChatModel = oai

	// WithTools (the seam the P1 kernel uses to attach the toolset) must accept
	// an acllm-converted ToolInfo on both adapters.
	info, err := ToolSchemaToInfo(llm.ToolSchema{
		Name:        "spike_tool",
		Description: "spike",
		InputSchema: map[string]any{"type": "object"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WithTools([]*schema.ToolInfo{info}); err != nil {
		t.Fatalf("claude WithTools: %v", err)
	}
	if _, err := oai.WithTools([]*schema.ToolInfo{info}); err != nil {
		t.Fatalf("openai WithTools: %v", err)
	}
}
