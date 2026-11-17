package llmguard

// 拒答守卫的接入层：把 llm.Provider 包一层「误拒答→表述优化重试」。
//
// 与上游 Pojun agent/refusal.go 的差异：上游用环境变量（POJUN_REFUSAL_GUARD /
// POJUN_REFUSAL_RETRIES）在包内自取开关；4zreco 把开关收敛到 settings
// （refusal_guard_enabled / refusal_guard_retries，环境变量 ZRECO_* 只作覆盖），
// 由 server 侧组装 provider 链时解析后经 GuardRefusal 传入——本包不读环境，
// 保持纯领域包（不感知配置面，也不感知 eino；它挂在 norma llm.Provider 层）。
//
// 行为语义与上游逐字一致：
//  1. 只在回复**开头**出现明确拒绝语句时触发（不是词表对抗，也不改用户意图）；
//  2. 重试请求只补一段「授权上下文 + 需要的技术产出」说明，追加到 system 段；
//  3. 默认最多重试两次（第二次要求从中断处继续输出技术内容），仍拒答就原样返回，
//     绝不循环；
//  4. 只有系统提示带平台注入的授权任务口径（HasAuthorizationContext）时才自动
//     重试；普通助手/未知请求不放行，避免把真正的边界请求也当成误拒答。
//
// 这不是绕过模型安全策略：请求内容、工具权限、平台拦截规则都不变，只是把
// 授权信息与需要的产出说清楚，减少误拒答。

import (
	"context"
	"iter"
	"log"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

var refusalRetries atomic.Int64

// RefusalRetryCount 返回进程内累计的「误拒答→表述优化重试」次数（供日志/排查）。
func RefusalRetryCount() int64 { return refusalRetries.Load() }

// MaxRefusalRetries 是重试上限的硬顶（与上游 POJUN_REFUSAL_RETRIES 的钳位一致）。
const MaxRefusalRetries = 3

type refusalGuard struct {
	inner   llm.Provider
	retries int
}

// GuardRefusal 包装 provider，开启「拒答→表述优化重试」。retries 是首次回复
// 之后的重试次数（0..MaxRefusalRetries；<0 视为 0，即只判定不重试）。
// 开关本身由调用方解析（settings + ZRECO_* 覆盖），这里只管包装。
func GuardRefusal(p llm.Provider, retries int) llm.Provider {
	if p == nil {
		return p
	}
	if retries < 0 {
		retries = 0
	}
	if retries > MaxRefusalRetries {
		retries = MaxRefusalRetries
	}
	return &refusalGuard{inner: p, retries: retries}
}

// reframed 给请求追加第 attempt 次（1-based）重试说明。已有同一段说明就不重复追加
// （极端情况下同一请求被包两层）。
func reframed(req llm.CompletionRequest, attempt int) llm.CompletionRequest {
	out := req
	hint := Hint(attempt)
	for _, s := range req.System {
		if strings.Contains(s, hint) {
			return out
		}
	}
	out.System = append(append([]string{}, req.System...), hint)
	return out
}

func textOfMessage(m llm.Message) string {
	var b strings.Builder
	for _, c := range m.Content {
		if c.Type == llm.BlockText {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// Complete 实现非流式路径：拒答则换表述重试，最多 g.retries 次。
// 只有系统提示带平台注入的授权任务口径时才自动重试；普通助手/未知请求
// 不自动重试，避免把真正的边界请求也当成误拒答。
func (g *refusalGuard) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, text, usage, err := g.inner.Complete(ctx, req)
	if err != nil {
		return msg, text, usage, err
	}
	if !HasAuthorizationContext(req.System) {
		return msg, text, usage, nil
	}
	for attempt := 1; attempt <= g.retries; attempt++ {
		kind := ClassifyRefusal(text)
		if kind == RefusalNone {
			return msg, text, usage, nil
		}
		refusalRetries.Add(1)
		log.Printf("[llmguard] 检测到%s拒答，第 %d/%d 次按「授权+技术产出」表述重试", refusalKindLabel(kind), attempt, g.retries)
		msg2, text2, usage2, err2 := g.inner.Complete(ctx, reframed(req, attempt))
		if err2 != nil {
			// 重试失败要透传 err2：返回旧的 err（必为 nil）会让引擎当成成功拿到拒答文本，
			// 不触发 model_error/配额分支（与 Stream 路径透传错误的行为不一致）。
			return msg, text, usage, err2
		}
		msg, text, usage = msg2, text2, usage2
	}
	return msg, text, usage, nil
}

func refusalKindLabel(kind RefusalKind) string {
	if kind == RefusalConditional {
		return "条件式"
	}
	return "明确"
}

// Stream 实现流式路径：缓冲开头一段文本再决定，是拒答就丢弃并重试，
// 否则原样回放缓冲事件并继续透传——调用方不会看到「先拒绝后重答」。
func (g *refusalGuard) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		authOK := HasAuthorizationContext(req.System)
		for attempt := 0; attempt <= g.retries; attempt++ {
			r := req
			if attempt > 0 {
				r = reframed(req, attempt)
			}
			retry, ok := g.streamAttempt(ctx, r, authOK && attempt < g.retries, yield)
			if !ok {
				return
			}
			if !retry {
				return
			}
			refusalRetries.Add(1)
			log.Printf("[llmguard] 流式回复疑似误拒答，第 %d/%d 次按「授权+技术产出」表述重试", attempt+1, g.retries)
		}
	}
}

// streamAttempt 跑一次内层流。返回值 retry=true 表示「判定为拒答且允许重试」，
// 此时缓冲事件被丢弃；ok=false 表示调用方已停止消费（yield 返回 false）。
func (g *refusalGuard) streamAttempt(
	ctx context.Context,
	req llm.CompletionRequest,
	allowRetry bool,
	yield func(llm.StreamEvent, error) bool,
) (retry bool, ok bool) {
	const decideRunes = 160
	var (
		buf     []llm.StreamEvent
		text    strings.Builder
		decided bool
		flushed bool
	)
	flush := func() bool {
		for _, ev := range buf {
			if !yield(ev, nil) {
				return false
			}
		}
		buf = nil
		flushed = true
		return true
	}
	for ev, err := range g.inner.Stream(ctx, req) {
		if err != nil {
			if !flushed {
				flush()
			}
			yield(ev, err)
			return false, false
		}
		if decided {
			if !yield(ev, nil) {
				return false, false
			}
			continue
		}
		// 思考增量实时透传（否则长思考模型会「卡住不动」）；拒答判定只看正文。
		if ev.Type == llm.SEThinkingDelta || ev.Type == llm.SEThinkingSignature {
			if !yield(ev, nil) {
				return false, false
			}
			continue
		}
		buf = append(buf, ev)
		switch ev.Type {
		case llm.SETextDelta:
			text.WriteString(ev.Text)
		case llm.SEToolUseStart, llm.SEToolInputJSON:
			// 开始调工具说明模型已接受任务，不是拒答。
			decided = true
		}
		if !decided && utf8.RuneCountInString(text.String()) < decideRunes && ev.Type != llm.SEMessageStop {
			continue
		}
		decided = true
		if allowRetry && ClassifyRefusal(text.String()) != RefusalNone {
			return true, true
		}
		if !flush() {
			return false, false
		}
	}
	if !decided && allowRetry && ClassifyRefusal(text.String()) != RefusalNone {
		return true, true
	}
	if !flushed {
		if !flush() {
			return false, true
		}
	}
	return false, true
}
