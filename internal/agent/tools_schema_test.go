package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 工具的 JSON Schema 不允许出现空的必填字段名。
//
// 坑：`obj(props, required...)` 的第二个参数是「必填字段名」列表，传
// `obj(props, "")` 会产生 `{"required": [""]}`——模型被要求必须传一个名为空
// 字符串的字段，参数校验会永远失败，工具等于废了。
//
// 这类错只有真跑一次模型才暴露（模型传不出空字符串的字段名），所以在这里
// 直接扫全部工具的 schema。
func TestNoToolHasEmptyRequiredFieldName(t *testing.T) {
	ts := NewToolSet(nil, "")

	check := func(t *testing.T, tl actool.CoreTool) {
		t.Helper()
		schema := tl.InputSchema()
		if schema == nil {
			return
		}
		raw, ok := schema["required"]
		if !ok {
			return
		}
		list, ok := raw.([]string)
		if !ok {
			// required 可能是 []any（从 map[string]any 组装时）——逐个断言。
			if anys, ok2 := raw.([]any); ok2 {
				for _, v := range anys {
					if s, ok3 := v.(string); ok3 && s == "" {
						t.Errorf("工具 %s 的 schema 里���空的必填字段名（required=%v）——模型永远传不出这个字段",
							tl.Name(), anys)
					}
				}
			}
			return
		}
		for _, r := range list {
			if r == "" {
				t.Errorf("工具 %s 的 schema 里有空的必填字段名（required=%v）——模型永远传不出这个字段",
					tl.Name(), list)
			}
		}
	}

	for _, tl := range ts.WorkerTools() {
		check(t, tl)
	}
	for _, tl := range ts.PlannerTools() {
		check(t, tl)
	}
	for _, tl := range ts.MainAgentTools() {
		check(t, tl)
	}
}

// 漏洞情报的工具必须挂在 worker/planner/mainagent 三个角色上——
// worker 扫到资产要用、planner 排 todolist 要用、用户在环路上问「最近出了
// 什么高危」也要用。
func TestRecentCriticalToolIsBoundToAllThreeRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	has := func(tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == "search_recent_critical" {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools()) {
		t.Error("worker 未绑定 search_recent_critical——扫到资产时用不上「最近出了什么高危」")
	}
	if !has(ts.PlannerTools()) {
		t.Error("planner 未绑定 search_recent_critical——规划时排不出「有现成利用方向」")
	}
	if !has(ts.MainAgentTools()) {
		t.Error("mainagent 未绑定 search_recent_critical——人在环路上问不了")
	}
}
