package guard

// guard_hitl_test.go — 评审第 1 轮 #2 的 fail-closed 回归（无 PG，nil db 即可）：
// hitl_mode 三半装配时点漂移（gate 半边未注入信号持有者）时，ask 决不允许静默
// 放行——要么走中断路径，要么完整回退 channel 阻塞语义。
//
//   - gate 半边未开（ctx 无 AskSignal 持有者）→ 回退 HandleAsk；nil db 下
//     HandleAsk 返回 false → block（fail-closed）；
//   - 持有者在但落库段失败（nil db 无法 INSERT pending）→ block（落库失败
//     按拒绝收口）。

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

func hitlAskGuard(t *testing.T) *Guard {
	t.Helper()
	ic := intercept.New(nil) // nil db：规则内存注入，落库/等待走失败分支
	ic.SetRulesInMemory([]db.InterceptRule{
		e2eRule(1, "[测试] hitl ask", `\bprobe\b`, "ask", 100, true, 5, "deny"),
	})
	g := NewWithInterceptor(ic)
	g.SetHitlMode(true) // guard 半边开
	return g
}

func hitlAskInput(t *testing.T) []byte {
	t.Helper()
	input, err := json.Marshal(map[string]string{"command": "probe target"})
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// gate 半边未开（装配时点漂移/开关中途翻转）→ 决不静默放行：回退 channel 阻塞
// 语义，nil db 下按拒绝收口。
func TestHitlAskFailsClosedWhenGateHalfMissing(t *testing.T) {
	g := hitlAskGuard(t)
	// context.Background() 无 AskSignal 持有者——模拟 gate SetHitl(false)。
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", hitlAskInput(t))
	if !blocked {
		t.Fatal("持有者缺失时 ask 必须回退阻塞语义并拒绝（fail-open 即审批旁路）")
	}
	if msg == "" {
		t.Fatal("拒绝必须带管控文本")
	}
}

// 持有者在但落库段失败（nil db 无法 INSERT pending）→ 同样 fail-closed。
// （注：「持有者在且落库成功→信号写入→放行」的正路径需要真库，由内核级
// TestHitl* 全链（askernel/session_hitl_test.go 经 gate/guard 信号 seam）覆盖。）
func TestHitlAskFailsClosedWhenPersistFails(t *testing.T) {
	g := hitlAskGuard(t)
	ctx := db.WithAskSignal(context.Background()) // gate 半边在
	blocked, msg, _ := g.Hooks().PreToolUse(ctx, "Bash", hitlAskInput(t))
	if !blocked {
		t.Fatal("落库段失败时 ask 必须按拒绝收口（不可静默放行）")
	}
	if msg == "" {
		t.Fatal("拒绝必须带管控文本")
	}
}
