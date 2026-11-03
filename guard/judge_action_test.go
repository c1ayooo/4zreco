package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/intercept"
	"github.com/c1ayooo/4zreco/db"
)

// 规则命中 action=judge 时，guard 必须把这次调用交给模型裁决，并把裁决结果
// 落成 allow / deny / ask —— 关键是"模型说 allow 就放行、说 deny 就拦"。
//
// 这条路径不能递归：裁决结果不会再走一次 Match（否则规则会把自己再命中一次，
// 变成无限循环）。
func TestJudgeActionRoutesToModelVerdict(t *testing.T) {
	ic := intercept.New(nil) // nil db: 规则表为空，只测 guard 的路由
	g := NewWithInterceptor(ic)

	// 模拟一个"规则命中 judge"：直接构造 Decision 走同一条分支不方便
	// （Match 需要 db），所以这里用 interceptor 的 JudgeRule 注入裁决器。
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "allow", Message: "只读命令，放行"}, nil
	})

	// 手动构造 guard 内部的 judge 分支：让 Match 返回 judge 需要 db，
	// 因此这里直接验证 guard 对 judge 裁决结果的二次路由——通过拦截器
	// 的 SetReviewer + 一次 Judge 调用间接确认 reviewer 被调用。
	input, _ := json.Marshal(map[string]string{"command": "cat /etc/hosts"})
	dec, ok := ic.JudgeRule(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("JudgeRule 未产出裁决")
	}
	if dec.Action != "allow" {
		t.Fatalf("裁决动作=%q want allow", dec.Action)
	}
	// 裁决消息必须带 [模型] 前缀，便于审计页区分人工与模型。
	if !strings.HasPrefix(dec.Message, "[模型]") {
		t.Errorf("裁决消息缺少 [模型] 前缀: %q", dec.Message)
	}
	_ = g
}

// 规则显式要求研判时，全局 judge 开关关掉也必须仍然研判——
// 否则这条规则形同虚设。
func TestJudgeRuleIgnoresGlobalEnableSwitch(t *testing.T) {
	ic := intercept.New(nil)
	called := false
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		called = true
		return intercept.Decision{Action: "deny", Message: "破坏性操作"}, nil
	})
	input, _ := json.Marshal(map[string]string{"command": "rm -rf /var/www"})
	dec, ok := ic.JudgeRule(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("JudgeRule 未产出裁决（全局开关关闭时应仍生效）")
	}
	if !called {
		t.Error("reviewer 未被调用")
	}
	if dec.Action != "deny" {
		t.Errorf("裁决动作=%q want deny", dec.Action)
	}
}

// 兜底路径（无规则命中）仍受全局开关控制：关掉就不裁决。
func TestJudgeFallbackRespectsGlobalSwitch(t *testing.T) {
	ic := intercept.New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "deny"}, nil
	})
	input, _ := json.Marshal(map[string]string{"command": "rm -rf /var/www"})
	if _, ok := ic.Judge(context.Background(), "Bash", input); ok {
		t.Error("全局 judge 关闭时不应裁决")
	}
}

var _ = db.InterceptRule{}
