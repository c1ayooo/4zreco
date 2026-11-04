package server

import (
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// v0.4.28 重复调用检测（PentAGI 机制自研）：同一工具+相同入参连续 ≥3 次拦截，
// 同一串最多拦 2 次后放行兜底；入参变化立即重置。
func TestRepeatTracker(t *testing.T) {
	rt := newRepeatTracker()
	in := []byte(`{"url": "https://a.example.com/x"}`)

	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("1st identical call must pass")
	}
	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("2nd identical call must pass")
	}
	if _, block := rt.observe("http_probe", in); !block {
		t.Fatal("3rd identical call must be blocked")
	}
	if _, block := rt.observe("http_probe", in); !block {
		t.Fatal("4th identical call must be blocked (2nd block)")
	}
	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("5th identical call must pass after block cap (avoid livelock)")
	}
	// 入参变化 → 重置。
	if _, block := rt.observe("http_probe", []byte(`{"url": "https://b.example.com/y"}`)); block {
		t.Fatal("changed input must reset and pass")
	}
	// 换工具名同样重置。
	if _, block := rt.observe("list_assets", []byte(`{"url": "https://b.example.com/y"}`)); block {
		t.Fatal("different tool must reset and pass")
	}
}

// 空白差异不应逃过重复判定（JSON 规范化）。
func TestRepeatTrackerWhitespaceInsensitive(t *testing.T) {
	rt := newRepeatTracker()
	rt.observe("Bash", []byte(`{"command":"id"}`))
	rt.observe("Bash", []byte(`{ "command" : "id" }`))
	if _, block := rt.observe("Bash", []byte("{\n  \"command\": \"id\"\n}")); !block {
		t.Fatal("whitespace-only differences must count as identical")
	}
}

// v0.4.28 意图软预算：usage 累计到顶只提醒一次；未到顶不打扰；禁用作废。
func TestIntentBudgetWatcher(t *testing.T) {
	in := 700
	out := 200

	var msgs []string
	steer := func(m string) error { msgs = append(msgs, m); return nil }
	w := intentBudgetWatcher(intentBudgetConfig{Enabled: true, Tokens: 1000}, steer, "test")
	if w == nil {
		t.Fatal("watcher must be non-nil when enabled")
	}
	// 未到顶的 usage 不触发。
	w(db.Activity{Kind: "usage", InputTokens: &in, OutputTokens: &out})
	if len(msgs) != 0 {
		t.Fatalf("below budget must not steer, got %v", msgs)
	}
	// 到顶触发一次。
	in2 := 1200
	w(db.Activity{Kind: "usage", InputTokens: &in2, OutputTokens: &out})
	if len(msgs) != 1 {
		t.Fatalf("crossing budget must steer once, got %d", len(msgs))
	}
	// 后续 usage 不再重复提醒。
	in3 := 1500
	w(db.Activity{Kind: "usage", InputTokens: &in3, OutputTokens: &out})
	if len(msgs) != 1 {
		t.Fatalf("must steer only once per intent, got %d", len(msgs))
	}
	// 非 usage 活动不影响。
	w(db.Activity{Kind: "tool_use"})

	// 关闭时不产生 watcher。
	if intentBudgetWatcher(intentBudgetConfig{Enabled: false, Tokens: 1000}, steer, "test") != nil {
		t.Fatal("disabled budget must return nil watcher")
	}
}

// 设置读取失败时用默认值，绝不把预算变成硬故障。
func TestIntentBudgetDefaults(t *testing.T) {
	c := intentBudgetFromPG(nil)
	if !c.Enabled || c.Tokens != defaultIntentBudgetTokens {
		t.Fatalf("nil pg must yield defaults, got %+v", c)
	}
}
