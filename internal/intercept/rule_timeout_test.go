package intercept

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// 规则级 timeout 覆盖（修 P0：timeout_enabled/seconds/action 曾是死字段）。
//
// 背景：规则的 timeout_* 三个字段只在 CRUD（db/intercept.go、server/intercept.go）
// 里存取，裁决路径 intercept.judge() 完全没读——它只读全局 settings
// (llm_judge_timeout_seconds / llm_judge_fail_action)。于是界面上每条规则显示
// 「超时 60s / 超时后 deny」，实际生效的却是「全局 180s / 失败转 ask」。
// 用户看到的和实际做的不一致，比没这个字段更糟。
//
// 语义（本文件锁定）：
//   - 规则 timeout_enabled=false → 用全局 llm_judge_timeout_seconds + 全局
//     llm_judge_fail_action。
//   - 规则 timeout_enabled=true  → 用规则自己的 timeout_seconds + timeout_action。
//     这是规则作者的显式声明，优先于全局。
//
// 这两组测试是「死字段」的回归基线：改回读全局就会红。

// judgeRuleWithTimeout 走「规则命中 judge」路径，携带规则级 timeout 覆盖。
func judgeRuleWithTimeout(t *testing.T, rt RuleTimeout, reviewer Reviewer) (Decision, bool) {
	t.Helper()
	ic := New(nil)
	if reviewer != nil {
		ic.SetReviewer(reviewer)
	}
	return ic.JudgeRuleWithTimeout(context.Background(), "Bash", json.RawMessage(`{"command":"rm -rf /tmp/x"}`), rt)
}

// 规则显式声明了 timeout（enabled=true）时，裁决墙钟上限必须用规则自己的值，
// 而不是全局的 180s。
func TestRuleTimeoutOverridesGlobalJudgeTimeout(t *testing.T) {
	var seen time.Duration
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		// 记下 ctx 剩余的截止时间，反推实际生效的墙钟上限。
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("裁决 context 没有 deadline——超时上限没生效")
			return Decision{Action: "allow"}, nil
		}
		seen = time.Until(deadline)
		return Decision{Action: "allow", Message: "放行"}, nil
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
		RuleTimeout{Enabled: true, Seconds: 30, Action: "deny"})
	if !ok {
		t.Fatal("规则要求研判时应产出裁决")
	}
	if dec.Action != "allow" {
		t.Fatalf("裁决动作=%q want allow", dec.Action)
	}
	// 允许 2s 的调度误差（context 建立与取样之间有开销）。
	if seen < 28*time.Second || seen > 32*time.Second {
		t.Errorf("规则级超时未生效：实际墙钟上限 %v，期望约 30s", seen)
	}
}

// 规则 timeout_enabled=false 时必须用全局配置（规则没说话就听全局的）。
func TestRuleTimeoutDisabledFallsBackToGlobal(t *testing.T) {
	var seen time.Duration
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("裁决 context 没有 deadline——全局超时也没生效")
			return Decision{Action: "allow"}, nil
		}
		seen = time.Until(deadline)
		return Decision{Action: "allow"}, nil
	})

	// 规则没开 timeout（enabled=false）→ 走全局默认 180s。
	_, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
		RuleTimeout{Enabled: false, Seconds: 30, Action: "deny"})
	if !ok {
		t.Fatal("规则要求研判时应产出裁决")
	}
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("规则未启用 timeout 时应回落到全局 180s，实际 %v", seen)
	}
}

// 规则级 timeout_action 决定「模型裁决失败/超时」后的动作。
// 硬 deny 类规则必须「超时即 deny」——不能因为模型抖动就放过 mkfs。
func TestRuleTimeoutActionGovernsJudgeFailure(t *testing.T) {
	// 模型不可用（reviewer 返回错误）→ 走「失败/超时后的动作」。
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{}, context.DeadlineExceeded
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"mkfs.ext4 /dev/sda"}`),
		RuleTimeout{Enabled: true, Seconds: 5, Action: "deny"})
	if !ok {
		t.Fatal("模型失败时仍应按失败策略给出动作")
	}
	if dec.Action != "deny" {
		t.Fatalf("规则级 timeout_action=deny 未生效：裁决动作=%q want deny", dec.Action)
	}
}

// 规则级 timeout_action=allow 时，模型失败就放行。
func TestRuleTimeoutActionAllowGovernsJudgeFailure(t *testing.T) {
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{}, context.DeadlineExceeded
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -X DELETE http://x/api/users/1"}`),
		RuleTimeout{Enabled: true, Seconds: 5, Action: "allow"})
	if !ok {
		t.Fatal("模型失败时仍应按失败策略给出动作")
	}
	if dec.Action != "allow" {
		t.Fatalf("规则级 timeout_action=allow 未生效：裁决动作=%q want allow", dec.Action)
	}
}

// 规则级 timeout 覆盖不能污染全局配置：下一次不带覆盖的裁决必须仍用全局值。
func TestRuleTimeoutOverrideDoesNotLeakToGlobal(t *testing.T) {
	ic := New(nil)
	var seen time.Duration
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		deadline, _ := ctx.Deadline()
		seen = time.Until(deadline)
		return Decision{Action: "allow"}, nil
	})

	// 先来一次带规则覆盖的（30s）。
	if _, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"x"}`),
		RuleTimeout{Enabled: true, Seconds: 30, Action: "deny"}); !ok {
		t.Fatal("第一次裁决未生效")
	}
	// 再来一次不带覆盖的——必须回到全局 180s，不能被上一次的 30s 污染。
	if _, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"y"}`),
		RuleTimeout{Enabled: false}); !ok {
		t.Fatal("第二次裁决未生效")
	}
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("规则级覆盖泄漏到了全局：实际 %v，期望约 180s", seen)
	}
}

// 兜底裁决（无规则命中）不受任何规则级覆盖影响——它没有规则可依据，
// 只能听全局的。
//
// 注意：全局 judge 开关默认是关的，此时兜底根本不裁决（这是既有行为，
// 不是本次改动引入的）。所以这里断言的是「不裁决」而不是「用了哪个超时」——
// 真要断言超时值需要一个开了开关的数据库实例，那属于 db 包的测试。
func TestFallbackJudgeUsesGlobalTimeout(t *testing.T) {
	ic := New(nil)
	called := false
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		called = true
		return Decision{Action: "allow"}, nil
	})

	dec, ok := ic.Judge(context.Background(), "Bash", json.RawMessage(`{"command":"x"}`))
	if ok {
		t.Fatalf("全局 judge 关闭时兜底不应裁决，got action=%q", dec.Action)
	}
	if called {
		t.Error("全局 judge 关闭时不该调用 reviewer")
	}
}
