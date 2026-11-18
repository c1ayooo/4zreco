package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

const nucleiOutputFixture = `{"template_id":"CVE-2021-41773","name":"Apache Path Traversal","severity":"high","host":"https://t.example","matched_at":"https://t.example/cgi-bin/","type":"http","curl_command":"curl -H 'Cookie: sid=SECRET123' https://t.example","request":"GET / HTTP/1.1\r\nAuthorization: Bearer TOPSECRET\r\n","response":"root:x:0:0"}
{"template_id":"tech-detect","name":"Nginx","severity":"info","host":"https://t.example","matched_at":"https://t.example","type":"http","response":"nginx"}
`

func callParseNuclei(t *testing.T, ts *ToolSet, body string) (string, bool) {
	t.Helper()
	res, err := ts.parseNucleiOutput().Call(context.Background(), json.RawMessage(body), nil)
	if err != nil {
		t.Fatalf("工具返回 Go error: %v", err)
	}
	return res.Flatten(), res.IsError
}

func TestParseNucleiOutputTextMode(t *testing.T) {
	out, isErr := callParseNuclei(t, &ToolSet{}, `{"text":`+jsonQuote(nucleiOutputFixture)+`}`)
	if isErr {
		t.Fatalf("text 模式不应失败: %s", out)
	}
	for _, want := range []string{`"total_hits":2`, `"high":1`, `"info":1`, `"CVE-2021-41773"`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺 %s：%s", want, out)
		}
	}
	// 凭据不得出现在结果里
	for _, leak := range []string{"SECRET123", "TOPSECRET"} {
		if strings.Contains(out, leak) {
			t.Errorf("输出泄露凭据 %q：%s", leak, out)
		}
	}
}

func TestParseNucleiOutputPathMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scan.jsonl"), []byte(nucleiOutputFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	out, isErr := callParseNuclei(t, &ToolSet{runDir: dir}, `{"path":"scan.jsonl","limit":1}`)
	if isErr {
		t.Fatalf("path 模式不应失败: %s", out)
	}
	if !strings.Contains(out, `"source":"scan.jsonl"`) || !strings.Contains(out, `"truncated":true`) {
		t.Errorf("应回显来源并标记截断：%s", out)
	}
}

func TestParseNucleiOutputEmptyAndErrors(t *testing.T) {
	// 空输出 = 无命中，不是错误
	out, isErr := callParseNuclei(t, &ToolSet{}, `{"text":"  \n"}`)
	if isErr || !strings.Contains(out, `"total_hits":0`) || !strings.Contains(out, "没有解析到任何命中") {
		t.Errorf("空输入应返回空命中并给排查提示: isErr=%v out=%s", isErr, out)
	}
	// 入参组合
	if out, isErr := callParseNuclei(t, &ToolSet{}, `{}`); !isErr || !strings.Contains(out, "至少给一个") {
		t.Errorf("空入参应报错: isErr=%v out=%s", isErr, out)
	}
	// 路径越界
	dir := t.TempDir()
	secret := filepath.Join(filepath.Dir(dir), "secret.jsonl")
	if err := os.WriteFile(secret, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })
	if out, isErr := callParseNuclei(t, &ToolSet{runDir: dir}, `{"path":"../secret.jsonl"}`); !isErr {
		t.Errorf("越界路径应被拒绝: %s", out)
	}
	// 扩展名白名单
	if err := os.WriteFile(filepath.Join(dir, "scan.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := callParseNuclei(t, &ToolSet{runDir: dir}, `{"path":"scan.yaml"}`); !isErr || !strings.Contains(out, "扩展名") {
		t.Errorf("非白名单扩展名应被拒绝: isErr=%v out=%s", isErr, out)
	}
}

func TestParseNucleiOutputRegistered(t *testing.T) {
	const key = "parse_nuclei_output"
	ts := NewToolSet(nil, "")
	has := func(tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == key {
				return true
			}
		}
		return false
	}
	if !has(ts.PlannerTools()) || !has(ts.WorkerTools()) || !has(ts.MainAgentTools()) {
		t.Error("parse_nuclei_output 未进入三张工具清单")
	}
	bound := map[string]bool{}
	for _, s := range BuiltinToolSeeds() {
		if s.Key == key {
			for _, a := range s.Agents {
				bound[a] = true
			}
		}
	}
	for _, want := range []string{"planner", "worker", "mainagent"} {
		if !bound[want] {
			t.Errorf("内置工具目录未绑定到 %s", want)
		}
	}
}
