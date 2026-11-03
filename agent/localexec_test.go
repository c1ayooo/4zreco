package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// local_exec 关掉的 agent 必须丢掉一切本机执行/写文件工具，只留只读检查与平台工具——
// 否则「用 spawn_task 派活」就只是一句提示词，模型手里仍握着 Bash，实测会直接自己动手。
func TestDropLocalExecTools(t *testing.T) {
	base := actool.DefaultTools()
	// 平台/编排工具没有 SDK 行，必须原样保留。
	spawn := actool.Build(actool.Spec{Name: "spawn_task", Description: "d"})
	// shell_* 是交互式 PTY 会话族：与 Bash 同一件事的另一个入口，也必须摘掉。
	shellOpen := actool.Build(actool.Spec{Name: "shell_open", Description: "d"})
	base = append(base, spawn, shellOpen)

	kept := DropLocalExecTools(base)
	have := map[string]bool{}
	for _, tl := range kept {
		have[tl.Name()] = true
	}
	for _, banned := range []string{"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "shell_open"} {
		if have[banned] {
			t.Errorf("%s 应被摘掉（本地执行已关闭）", banned)
		}
	}
	for _, want := range []string{"Read", "LS", "Glob", "Grep", "spawn_task"} {
		if !have[want] {
			t.Errorf("%s 应保留（只读检查 / 平台工具）", want)
		}
	}
}
