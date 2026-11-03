package guard

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/db"
	"github.com/c1ayooo/4zreco/intercept"
)

// 端到端验证「明令禁止」与「交给 Agent 研判」在**真实调用路径**上分流。
//
// 这条链路是：tool call → guard.applyIntercept → interceptor.Match（规则命中）
// → action=deny 直接拒绝 / action=judge 交给模型裁决 → 裁决结果决定放行或拒绝。
//
// 2026-10-22 之前，内置规则全部是 deny，所以「模型研判」这条路**从未被
// 内置规则走到过**——用户要的「明令禁止 vs 交给 Agent 研判」在规则层根本没
// 有分开。这份测试是那次分流的回归基线。

// e2eRule 用 db.InterceptRule 描述一条规则（与库里存的形状一致）。
func e2eRule(id int64, name, pattern, action string, priority int, timeoutEnabled bool, timeoutSeconds int, timeoutAction string) db.InterceptRule {
	return db.InterceptRule{
		ID:             id,
		Name:           name,
		Enabled:        true,
		Priority:       priority,
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        pattern,
		Action:         action,
		Message:        "测试规则 " + name,
		TimeoutEnabled: timeoutEnabled,
		TimeoutSeconds: timeoutSeconds,
		TimeoutAction:  timeoutAction,
	}
}

// runE2E 走一次完整的 PreToolUse，返回是否被拦截。
func runE2E(t *testing.T, rules []db.InterceptRule, reviewer intercept.Reviewer, cmd string) (blocked bool, judgeCalls int) {
	t.Helper()
	ic := intercept.New(nil)
	ic.SetRulesInMemory(rules)
	if reviewer != nil {
		ic.SetReviewer(reviewer)
	}
	g := NewWithInterceptor(ic)
	input, _ := json.Marshal(map[string]string{"command": cmd})
	blocked, _, _ = g.Hooks().PreToolUse(context.Background(), "Bash", input)
	return blocked, judgeCalls
}

// 明令禁止类规则命中时**直接拒绝**，且**不调用模型**。
//
// 「不调用模型」是关键：硬禁类的意义就是既省一次 LLM 往返，也不因为模型
// 抖动（超时、限流、解析失败）而把关卡敞开。
func TestE2EHardDenyBlocksWithoutCallingModel(t *testing.T) {
	judgeCalls := 0
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "allow", Message: "模型说放行"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[内置] 磁盘格式化 mkfs", `\bmkfs\b`, "deny", 100, false, 60, "deny"),
	}
	blocked, _ := runE2E(t, rules, reviewer, `mkfs.ext4 /dev/sda`)
	if !blocked {
		t.Error("明令禁止的 mkfs 应被拒绝")
	}
	if judgeCalls != 0 {
		t.Errorf("明令禁止不应调用模型，实际调用了 %d 次", judgeCalls)
	}
}

// 交给 Agent 研判的规则命中时**必须调用模型**，且以模型裁决为准。
//
// 这一条是本次整改的核心：整改前这类命令被规则直接 deny，模型根本没机会看。
func TestE2EJudgeRuleDelegatesToModel(t *testing.T) {
	judgeCalls := 0
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "allow", Message: "[模型] 测试产物，放行"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[内置] 递归强制删除 rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, true, 90, "allow"),
	}
	// 模型说放行 → 不拦截。
	blocked, _ := runE2E(t, rules, reviewer, `rm -rf /tmp/mytestdir`)
	if blocked {
		t.Error("模型裁决放行后不应拦截")
	}
	if judgeCalls != 1 {
		t.Errorf("研判类规则应调用模型 1 次，实际 %d 次", judgeCalls)
	}

	// 模型说拒绝 → 拦截。
	reviewer2 := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "deny", Message: "[模型] 生产数据，拒绝"}, nil
	}
	blocked, _ = runE2E(t, rules, reviewer2, `rm -rf /var/www/html`)
	if !blocked {
		t.Error("模型裁决拒绝后应拦截")
	}
	if judgeCalls != 2 {
		t.Errorf("研判类规则应调用模型 2 次，实际 %d 次", judgeCalls)
	}
}

// 研判类规则的规则级超时声明要真的传到裁决器——模型超时时按规则自己的
// 声明兜底（这里是 allow），而不是全局的默认值。
//
// 回归背景：规则上的 timeout_* 曾是死字段（界面显示 60s/deny，实际是全局
// 180s/ask）。用户看到的和实际做的不一致。
func TestE2ERuleTimeoutReachesJudge(t *testing.T) {
	// 记录裁决器看到的 ctx 截止时间。
	var seen time.Duration
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		deadline, ok := ctx.Deadline()
		if ok {
			seen = time.Until(deadline)
		}
		return intercept.Decision{Action: "allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[内置] 递归强制删除 rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, true, 45, "allow"),
	}
	runE2E(t, rules, reviewer, `rm -rf /tmp/x`)
	if seen < 43*time.Second || seen > 47*time.Second {
		t.Errorf("规则级超时未传到裁决器：实际 %v，期望约 45s", seen)
	}
}

// 规则没声明 timeout 时，走全局的默认（180s）——不能被别的规则的声明影响。
func TestE2ERuleWithoutTimeoutUsesGlobal(t *testing.T) {
	var seen time.Duration
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		deadline, ok := ctx.Deadline()
		if ok {
			seen = time.Until(deadline)
		}
		return intercept.Decision{Action: "allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[内置] 递归强制删除 rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, false, 60, "deny"),
	}
	runE2E(t, rules, reviewer, `rm -rf /tmp/x`)
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("规则未启用 timeout 时应走全局 180s，实际 %v", seen)
	}
}
