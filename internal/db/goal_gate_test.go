package db

import (
	"encoding/json"
	"testing"
)

// 上游 0.4.80 #20：能力型目标关键词判定（纯函数，无需数据库）。
func TestGoalRequiresCapabilityEvidence(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"获取 RCE", true},
		{"拿到后台管理员控制权", true},
		{"验证高危业务数据越权泄露", true},
		{"获取敏感数据", true},
		{"拿到 root 权限", true},
		{"获取 webshell", true},
		{"确认是否存在 RCE", false},
		{"排查命令执行入口", false},
		{"验证 SQL 注入", false},
		{"收集管理员登录页与端口", false},
		{"whether the target is vulnerable to RCE", false},
		{"", false},
	}
	for _, c := range cases {
		if got := GoalRequiresCapabilityEvidence(c.text); got != c.want {
			t.Errorf("GoalRequiresCapabilityEvidence(%q)=%v, want %v", c.text, got, c.want)
		}
	}
}

// CapabilityEvidenceError：能力型目标拒绝 fact 与 low/medium finding，接受
// high/critical finding；存在性目标不受影响。
func TestCapabilityEvidenceError(t *testing.T) {
	goal := func(text string) *Node {
		return &Node{Kind: KindGoal, Payload: mustJSON(map[string]any{"text": text})}
	}
	fact := &Node{Kind: KindFact, Payload: mustJSON(map[string]any{"summary": "未发现入口"})}
	finding := func(sev string) *Node {
		return &Node{Kind: KindFinding, Payload: mustJSON(map[string]any{"severity": sev, "name": "x"})}
	}

	if msg := CapabilityEvidenceError(goal("获取 RCE"), fact); msg == "" {
		t.Fatal("能力型目标 + fact 应被拒绝")
	}
	if msg := CapabilityEvidenceError(goal("获取 RCE"), finding("low")); msg == "" {
		t.Fatal("能力型目标 + low finding 应被拒绝")
	}
	if msg := CapabilityEvidenceError(goal("获取 RCE"), finding("medium")); msg == "" {
		t.Fatal("能力型目标 + medium finding 应被拒绝")
	}
	if msg := CapabilityEvidenceError(goal("获取 RCE"), finding("high")); msg != "" {
		t.Fatalf("能力型目标 + high finding 应放行，得到 %q", msg)
	}
	if msg := CapabilityEvidenceError(goal("获取 RCE"), finding("CRITICAL")); msg != "" {
		t.Fatalf("severity 大小写应归一化，得到 %q", msg)
	}
	if msg := CapabilityEvidenceError(goal("确认是否存在 RCE"), fact); msg != "" {
		t.Fatalf("存在性目标用 fact 证明是合法的，得到 %q", msg)
	}
	if msg := CapabilityEvidenceError(goal("收集管理员登录页与端口"), fact); msg != "" {
		t.Fatalf("非能力型目标不受影响，得到 %q", msg)
	}
	if msg := CapabilityEvidenceError(goal(""), fact); msg != "" {
		t.Fatalf("空目标文本放行，得到 %q", msg)
	}
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}
