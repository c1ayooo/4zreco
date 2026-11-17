package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// CWE→方法论 skill 联动（M1 闭环）：relatedSkillsFor 按命中 CWE 去重返回
// skill 名单；未注入索引或无命中时返回 nil——工具输出里不出现 related_skills，
// 联动是纯增量，不能让既有形状变化。
func TestRelatedSkillsFor(t *testing.T) {
	// 未注入索引：恒为 nil。
	if got := relatedSkillsFor([]string{"CWE-89"}); got != nil {
		t.Fatalf("未注入索引时应返回 nil，got=%v", got)
	}

	SetCweSkillIndex(map[string][]string{
		"CWE-89":  {"inj-skill"},
		"CWE-862": {"authz-skill"},
		"CWE-639": {"authz-skill"},
	})
	t.Cleanup(func() { SetCweSkillIndex(nil) })

	// 单 CWE 命中。
	if got := relatedSkillsFor([]string{"CWE-89"}); !reflect.DeepEqual(got, []string{"inj-skill"}) {
		t.Fatalf("CWE-89 → %v", got)
	}
	// 多 CWE 去重：两个 CWE 指向同一 skill 时只出现一次；大小写不敏感。
	got := relatedSkillsFor([]string{"CWE-862", "cwe-639"})
	if !reflect.DeepEqual(got, []string{"authz-skill"}) {
		t.Fatalf("CWE-862+cwe-639 → %v，应为去重后的 [authz-skill]", got)
	}
	// 无命中返回 nil。
	if got := relatedSkillsFor([]string{"CWE-999"}); got != nil {
		t.Fatalf("无命中应返回 nil，got=%v", got)
	}
}

// 联动字段必须是「无则缺失」：不带 related_skills 的 get_vuln 输出形状与
// 既有调用方（提示词里写的字段名）保持一致。
func TestVulnDetailWithSkillsOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(vulnDetailWithSkills{VulnDetail: nil})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["related_skills"]; ok {
		t.Fatal("无联动时 related_skills 不应出现在输出里")
	}
}

// ---- 0.4.71 加固回补：scan_with_nuclei 命令注入防御 ----

// shellJoinArgs 逐参数单引号包裹：& ; $() 反引号不再被 shell 解释。
func TestShellJoinArgsQuotesEveryArg(t *testing.T) {
	got := shellJoinArgs([]string{"nuclei", "-target", "https://t/api?id=1&x=2"})
	want := `'nuclei' '-target' 'https://t/api?id=1&x=2'`
	if got != want {
		t.Errorf("shellJoinArgs = %s, want %s", got, want)
	}
	// 内部单引号按 '\'' 转义，不提前闭合引号。
	got2 := shellJoinArgs([]string{"it's"})
	if want2 := `'it'\''s'`; got2 != want2 {
		t.Errorf("单引号转义错误: got %s, want %s", got2, want2)
	}
	// 命令替换/管道符号也必须被引号包住。
	got3 := shellJoinArgs([]string{"a;b|$(whoami) `id`"})
	if want3 := `'a;b|$(whoami) ` + "`id`" + `'`; got3 != want3 {
		t.Errorf("元字符应保持字面量: got %s, want %s", got3, want3)
	}
}

// scanWithNuclei 测试基座：临时模板树（带 .git）+ 假 nuclei 二进制上 PATH。
func scanWithNucleiTestEnv(t *testing.T) actool.CoreTool {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	SetNucleiTemplatesDir(dir)
	t.Cleanup(func() { SetNucleiTemplatesDir("") })

	binDir := t.TempDir()
	fake := filepath.Join(binDir, "nuclei")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return (&ToolSet{}).scanWithNuclei()
}

// target 必须是 http(s) URL：语义校验先于拼命令。
func TestScanWithNucleiRejectsNonHTTPTarget(t *testing.T) {
	tool := scanWithNucleiTestEnv(t)
	for _, target := range []string{"not a url", "ftp://x.test", "file:///etc/passwd", "http://", "javascript:alert(1)"} {
		in, _ := json.Marshal(map[string]any{"target": target})
		res, err := tool.Call(context.Background(), in, nil)
		if err != nil {
			t.Fatalf("target=%q: %v", target, err)
		}
		if !res.IsError {
			t.Errorf("target=%q 应被拒绝", target)
		}
	}
	// http(s) URL 放行。
	in, _ := json.Marshal(map[string]any{"target": "https://t.test/x"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Errorf("合法 https target 不应被拒绝: %v", res.Content)
	}
}

// severity 只允许枚举值的逗号组合：任意文本（含注入载荷）不进命令行。
func TestScanWithNucleiRejectsBadSeverity(t *testing.T) {
	tool := scanWithNucleiTestEnv(t)
	for _, sev := range []string{"high; rm -rf /", "high,medium || curl evil", "critical -severity x"} {
		in, _ := json.Marshal(map[string]any{"target": "https://t.test/x", "severity": sev})
		res, err := tool.Call(context.Background(), in, nil)
		if err != nil {
			t.Fatalf("severity=%q: %v", sev, err)
		}
		if !res.IsError {
			t.Errorf("severity=%q 应被拒绝", sev)
		}
	}
	// 合法组合放行。
	in, _ := json.Marshal(map[string]any{"target": "https://t.test/x", "severity": "critical,high"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Errorf("合法 severity 不应被拒绝: %v", res.Content)
	}
}

// 组出的命令：逐参数单引号包裹 + 有 GNU timeout 时包 600s 墙钟。
func TestScanWithNucleiQuotesCommandAndWrapsTimeout(t *testing.T) {
	tool := scanWithNucleiTestEnv(t)
	in, _ := json.Marshal(map[string]any{
		"target":   "https://t.test/api?id=1&x=2",
		"severity": "high",
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("工具报错: %v", res.Content)
	}
	run := toolResultJSON(t, res)["run_with_bash"].(string)

	// target 里的 & 必须在单引号内保持字面量，而不是被 shell 当后台符号。
	if !strings.Contains(run, `'https://t.test/api?id=1&x=2'`) {
		t.Errorf("target 应整体单引号包裹: %s", run)
	}
	// 不能再出现裸拼接（旧实现 strings.Join 的形态：-target 后无引号直接跟 URL）。
	if strings.Contains(run, " -target https://") {
		t.Errorf("命令参数未经引号包裹（旧缺陷形态）: %s", run)
	}
	// 有 GNU timeout 时（Linux 生产默认有）最外层包 600s 墙钟。
	if _, terr := exec.LookPath("timeout"); terr == nil && runtime.GOOS != "windows" {
		if !strings.HasPrefix(run, "'") || !strings.Contains(run, "' 600 '") {
			t.Errorf("应有 timeout 600 外层包裹: %s", run)
		}
	}
}
