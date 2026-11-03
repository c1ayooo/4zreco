package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/db"
)

// summary 长度上限：超长要截断，保留头部（目标+做什么在开头）。
func TestClampIntentSummaryTruncates(t *testing.T) {
	long := strings.Repeat("探测目标主机的登录面并尝试默认口令", 60)
	got := clampIntentSummary(long)
	if utf8.RuneCountInString(got) > maxIntentSummaryRunes+40 {
		t.Fatalf("截断后仍过长: %d rune", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "截断") {
		t.Errorf("截断后应有标记: %q", got[:min(80, len(got))])
	}
	// 头部必须保留——目标+做什么在开头。
	if !strings.HasPrefix(got, "探测目标主机") {
		t.Errorf("头部未保留: %q", got[:min(40, len(got))])
	}
}

// 正常长度不该被改动。
func TestClampIntentSummaryKeepsShort(t *testing.T) {
	short := "对 10.10.47.11 用已拿到的 root 提取 ZStack 管理 API 凭据"
	if got := clampIntentSummary(short); got != short {
		t.Fatalf("短 summary 不该被改: got %q", got)
	}
}

// 空 summary 仍然非法。
func TestClampIntentSummaryEmpty(t *testing.T) {
	if got := clampIntentSummary("   "); got != "" {
		t.Fatalf("空白应被清成空串: %q", got)
	}
}

// 接续代数：一条接续链的代数要能正确累加。
func TestContinuationDepthAccumulates(t *testing.T) {
	// 老节点（没有 continuation_depth 字段）当首探。
	old := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x"}`)}
	if got := continuationDepthOf(old); got != 1 {
		t.Fatalf("无字段的旧意图应算 1 代,got %d", got)
	}
	// 显式记录的代数。
	n2 := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x","continuation_depth":2}`)}
	if got := continuationDepthOf(n2); got != 2 {
		t.Fatalf("应读出 2 代,got %d", got)
	}
	// 非法值退回 1。
	bad := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x","continuation_depth":0}`)}
	if got := continuationDepthOf(bad); got != 1 {
		t.Fatalf("非法代数应退回 1,got %d", got)
	}
	// nil 安全。
	if got := continuationDepthOf(nil); got != 1 {
		t.Fatalf("nil 应返回 1,got %d", got)
	}
	// payload 不是合法 JSON 也安全。
	broken := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`not json`)}
	if got := continuationDepthOf(broken); got != 1 {
		t.Fatalf("坏 payload 应返回 1,got %d", got)
	}
}

// 接续代数上限必须是 3——2 太紧（误杀正当深挖），4+ 太松（挡不住无限接续）。
func TestMaxContinuationDepthValue(t *testing.T) {
	if maxContinuationDepth != 3 {
		t.Fatalf("接续代数上限应为 3,got %d", maxContinuationDepth)
	}
}

// intentItem 必须能解析 continues 字段。
func TestIntentItemParsesContinues(t *testing.T) {
	var it intentItem
	in := `{"summary":"接续 #578 继续挖","continues":[578],"parent_ids":[558],"asset_ids":[12]}`
	if err := json.Unmarshal([]byte(in), &it); err != nil {
		t.Fatal(err)
	}
	if got := pidList(it.Continues); len(got) != 1 || got[0] != 578 {
		t.Fatalf("continues 解析错误: %v", got)
	}
	if got := pidList(it.ParentIDs); len(got) != 1 || got[0] != 558 {
		t.Fatalf("parent_ids 解析错误: %v", got)
	}
}

// 不给 continues 时是空的（不是 0 元素里有 0）。
func TestIntentItemWithoutContinues(t *testing.T) {
	var it intentItem
	if err := json.Unmarshal([]byte(`{"summary":"全新方向"}`), &it); err != nil {
		t.Fatal(err)
	}
	if got := pidList(it.Continues); len(got) != 0 {
		t.Fatalf("未给 continues 应为空: %v", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
