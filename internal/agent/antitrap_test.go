package agent

import (
	"strings"
	"testing"
)

// 反 AI 蜜罐红线是代码固定尾：workerSystem 渲染结果必含红线段，DB 编辑正文
// （PromptOverride）覆盖不掉。
func TestWorkerSystemAntiTrapRules(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	got := workerSystem("", "", "/data", "/data")
	if !strings.Contains(got, "反 AI 蜜罐红线") {
		t.Fatalf("worker missing anti-trap rules: %q", got)
	}

	// DB 覆盖正文也删不掉红线段。
	PromptOverride = func(k string) (string, bool) { return "用户编辑正文", true }
	if got := workerSystem("", "", "/data", "/data"); !strings.Contains(got, "反 AI 蜜罐红线") {
		t.Fatalf("edited body must not drop anti-trap rules: %q", got)
	}
}
