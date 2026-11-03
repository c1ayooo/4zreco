package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.4.27：http_probe 批量探活工具——只落脚本+组命令，不自己发请求。
func TestHTTPProbeComposesCommand(t *testing.T) {
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.httpProbe()
	in, _ := json.Marshal(map[string]any{"urls": []string{
		"https://a.example.com/x", "https://b.example.com/y?q=1", "not-a-url", "https://a.example.com/x",
	}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out struct {
		RunWithBash string `json:"run_with_bash"`
		Count       int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, toolResultText(t, res))
	}
	if out.Count != 2 {
		t.Fatalf("count=%d want 2（非法 URL 与重复项应剔除）", out.Count)
	}
	if !strings.Contains(out.RunWithBash, "4zreco-probe.sh") || !strings.Contains(out.RunWithBash, "https://b.example.com/y?q=1") {
		t.Fatalf("command=%q", out.RunWithBash)
	}
	// 脚本已落盘（调用方式是 `bash <script>`，不依赖可执行位——Windows 无 exec 位）。
	script := filepath.Join(dir, "4zreco-probe.sh")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("script missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("script empty")
	}
	// 第二次调用复用同一脚本（幂等落盘）。
	res2, _ := tool.Call(context.Background(), in, nil)
	var out2 struct {
		RunWithBash string `json:"run_with_bash"`
	}
	_ = json.Unmarshal([]byte(toolResultText(t, res2)), &out2)
	if out2.RunWithBash != out.RunWithBash {
		t.Fatalf("command not stable across calls:\n%s\n%s", out.RunWithBash, out2.RunWithBash)
	}
}

// 没有 runDir（如 reporter chat 工具集）时明确报错，而不是静默成功。
func TestHTTPProbeRequiresRunDir(t *testing.T) {
	ts := NewToolSet(nil, "reporter")
	tool := ts.httpProbe()
	in, _ := json.Marshal(map[string]any{"urls": []string{"https://a.example.com/"}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(toolResultText(t, res), "未启用") {
		t.Fatalf("expected 未启用 error, got: %s", toolResultText(t, res))
	}
}
