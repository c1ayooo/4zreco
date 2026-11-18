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

const pocTestTemplate = `id: CVE-2022-22965-spring4shell
info:
  name: Spring4Shell RCE
  severity: critical
  author: test
  classification:
    cve-id: CVE-2022-22965
    cwe-id: CWE-94
    cvss-score: 9.8
  tags: spring,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`

// callParseTpl 调用 parse_poc_template 并返回 (文本, 是否错误)。
func callParseTpl(t *testing.T, body string) (string, bool) {
	t.Helper()
	res, err := (&ToolSet{}).parsePocTemplate().Call(context.Background(), json.RawMessage(body), nil)
	if err != nil {
		t.Fatalf("工具返回 Go error: %v", err)
	}
	return res.Flatten(), res.IsError
}

// setupPocTree 建一个临时 nuclei-templates 树并接上包级变量。
func setupPocTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	SetNucleiTemplatesDir(root)
	t.Cleanup(func() { SetNucleiTemplatesDir("") })
	if err := os.MkdirAll(filepath.Join(root, "http", "cves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "http", "cves", "spring.yaml"), []byte(pocTestTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestParsePocTemplateContentMode(t *testing.T) {
	SetNucleiTemplatesDir("")
	out, isErr := callParseTpl(t, `{"content":`+jsonQuote(pocTestTemplate)+`,"fallback_id":"row-1"}`)
	if isErr {
		t.Fatalf("content 模式不应失败: %s", out)
	}
	for _, want := range []string{`"template_id":"CVE-2022-22965-spring4shell"`, `"severity":"critical"`, `"protocol":"http"`, `"cve_id":"CVE-2022-22965"`, `"cvss_score":9.8`, `"source":"content"`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺 %s：%s", want, out)
		}
	}
}

func TestParsePocTemplatePathModes(t *testing.T) {
	root := setupPocTree(t)
	// 相对路径
	out, isErr := callParseTpl(t, `{"path":"http/cves/spring.yaml"}`)
	if isErr {
		t.Fatalf("相对路径应可解析: %s", out)
	}
	if !strings.Contains(out, `"source":"http/cves/spring.yaml"`) {
		t.Errorf("source 应为相对路径：%s", out)
	}
	// 树内绝对路径
	out, isErr = callParseTpl(t, `{"path":`+jsonQuote(filepath.Join(root, "http", "cves", "spring.yaml"))+`}`)
	if isErr {
		t.Fatalf("树内绝对路径应可解析: %s", out)
	}
	if !strings.Contains(out, `"template_id":"CVE-2022-22965-spring4shell"`) {
		t.Errorf("解析结果不符：%s", out)
	}
}

func TestParsePocTemplateRejectsEscape(t *testing.T) {
	root := setupPocTree(t)
	secret := filepath.Join(filepath.Dir(root), "secret.yaml")
	if err := os.WriteFile(secret, []byte(pocTestTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })
	if err := os.WriteFile(filepath.Join(root, "http", "spring.txt"), []byte(pocTestTemplate), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"相对穿越":   `{"path":"../secret.yaml"}`,
		"绝对树外":   `{"path":` + jsonQuote(secret) + `}`,
		"非 yaml": `{"path":"http/spring.txt"}`,
	}
	for name, body := range cases {
		out, isErr := callParseTpl(t, body)
		if !isErr {
			t.Errorf("%s 应被拒绝，实际返回：%s", name, out)
		}
	}

	// 树内符号链接指向树外：词法前缀挡不住，EvalSymlinks 后必须拒。
	link := filepath.Join(root, "http", "evil.yaml")
	if err := os.Symlink(secret, link); err == nil {
		if out, isErr := callParseTpl(t, `{"path":"http/evil.yaml"}`); !isErr {
			t.Errorf("符号链接逃逸应被拒绝，实际返回：%s", out)
		}
	}
}

func TestParsePocTemplateLimitsAndErrors(t *testing.T) {
	root := setupPocTree(t)

	// 超过 2MB
	big := filepath.Join(root, "http", "big.yaml")
	if err := os.WriteFile(big, append([]byte("info:\n  name: big\n"), make([]byte, pocTemplateMaxBytes)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := callParseTpl(t, `{"path":"http/big.yaml"}`); !isErr || !strings.Contains(out, "上限") {
		t.Errorf("超大模板应被拒绝，得到 isErr=%v out=%s", isErr, out)
	}

	// 不存在的文件
	if out, isErr := callParseTpl(t, `{"path":"http/none.yaml"}`); !isErr || !strings.Contains(out, "不可读") {
		t.Errorf("缺失文件应报不可读，得到 isErr=%v out=%s", isErr, out)
	}

	// 入参组合
	if out, isErr := callParseTpl(t, `{}`); !isErr || !strings.Contains(out, "至少给一个") {
		t.Errorf("空入参应报错，得到 isErr=%v out=%s", isErr, out)
	}
	if out, isErr := callParseTpl(t, `{"path":"http/cves/spring.yaml","content":"x"}`); !isErr || !strings.Contains(out, "只能给一个") {
		t.Errorf("path+content 应报错，得到 isErr=%v out=%s", isErr, out)
	}

	// 模板树未就绪
	SetNucleiTemplatesDir("")
	if out, isErr := callParseTpl(t, `{"path":"http/cves/spring.yaml"}`); !isErr || !strings.Contains(out, "模板树未就绪") {
		t.Errorf("树未就绪应报错，得到 isErr=%v out=%s", isErr, out)
	}
}

// jsonQuote 用标准库转义，避免手写 JSON 里换行/引号出错。
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// 注册三件套回归（AGENTS §4「工具实现了必须注册」）：三张清单 + toolcatalog seed。
func TestParsePocTemplateRegistered(t *testing.T) {
	const key = "parse_poc_template"
	ts := NewToolSet(nil, "")
	has := func(name string, tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == name {
				return true
			}
		}
		return false
	}
	if !has(key, ts.PlannerTools()) {
		t.Error("PlannerTools 缺 parse_poc_template")
	}
	if !has(key, ts.WorkerTools()) {
		t.Error("WorkerTools 缺 parse_poc_template")
	}
	if !has(key, ts.MainAgentTools()) {
		t.Error("MainAgentTools 缺 parse_poc_template")
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
			t.Errorf("内置工具目录未把 parse_poc_template 绑定到 %s", want)
		}
	}
}
