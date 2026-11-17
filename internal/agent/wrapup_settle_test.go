package agent

// 收尾阶段执行类工具面收窄的名单测试（上游 0.4.71）：
// 只藏 Bash 不够——job_*、http/auth 请求、listener_*、扫描执行类都能绕过 Bash
// 继续执行/打目标，收尾预算会被新探测吃掉。名单是代码固定策略，用测试钉住。

import (
	"context"
	"encoding/json"
	"testing"

	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

func mustNamedTool(t *testing.T, name string) actool.CoreTool {
	t.Helper()
	return actool.Build(actool.Spec{
		Name:        name,
		Description: name,
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text(name + " ran"), nil
		},
	})
}

func TestSettlementDisabledToolsCoversBypassChannels(t *testing.T) {
	have := map[string]bool{}
	for _, n := range settlementDisabledTools() {
		have[n] = true
	}
	// 本机执行面 + 绕过 Bash 的执行/触目标通道，缺一个都等于给收尾期留后门。
	for _, n := range []string{
		"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
		"job_start", "http_request", "session_login", "auth_request", "diff_responses",
		"listener_start", "listener_stop", "listener_sessions",
		"gogo_scan", "spray_finger", "katana_scan", "scan_with_nuclei",
		"zombie_weakpass", "proton_secrets",
		"run_script", "poc_scaffold",
	} {
		if !have[n] {
			t.Fatalf("settlementDisabledTools 缺少 %q", n)
		}
	}
	// 写证据/收官判定类工具绝不能进名单——收尾预算就是留给它们的。
	for _, n := range []string{"record_fact", "report_finding", "prove_goal", "add_intent", "goal_met", "save_evidence"} {
		if have[n] {
			t.Fatalf("settlementDisabledTools 不应包含写证据工具 %q", n)
		}
	}
}

func TestDropSettleToolsDropsExecAndShellFamily(t *testing.T) {
	tools := []actool.CoreTool{
		mustNamedTool(t, "Bash"),
		mustNamedTool(t, "shell_open"),
		mustNamedTool(t, "gogo_scan"),
		mustNamedTool(t, "scan_with_nuclei"),
		mustNamedTool(t, "listener_start"),
		mustNamedTool(t, "Read"),
		mustNamedTool(t, "Grep"),
		mustNamedTool(t, "graph_overview"),
		mustNamedTool(t, "prove_goal"),
	}
	out := DropSettleTools(tools)
	names := map[string]bool{}
	for _, tool := range out {
		names[tool.Name()] = true
	}
	for _, blocked := range []string{"Bash", "shell_open", "gogo_scan", "scan_with_nuclei", "listener_start"} {
		if names[blocked] {
			t.Fatalf("DropSettleTools 未摘掉 %q", blocked)
		}
	}
	for _, kept := range []string{"Read", "Grep", "graph_overview", "prove_goal"} {
		if !names[kept] {
			t.Fatalf("DropSettleTools 误摘了 %q", kept)
		}
	}
}

func TestDropSettleDeferredFiltersDeferredNames(t *testing.T) {
	got := dropSettleDeferred([]string{"mcp__nuclei__scan", "mcp__shell__exec", "mcp__docs__read"})
	if len(got) != 2 {
		t.Fatalf("dropSettleDeferred 结果=%v，期望保留 2 个", got)
	}
	for _, n := range got {
		if n == "mcp__shell__exec" {
			t.Fatalf("shell_* 族应被整族摘掉，结果=%v", got)
		}
	}
}
