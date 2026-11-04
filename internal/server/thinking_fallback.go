package server

import (
	"strings"

	"github.com/Autumn-27/norma/llm"
	"github.com/c1ayooo/4zreco/internal/agent"
)

// thinking 拒绝错误的识别与自动降级。
//
// ## 这个坑为什么值得单独一个文件
//
// MiniMax-M3.1 这类**强制 adaptive thinking** 的模型会直接拒绝
// thinking.type="disabled"（以及 reasoning.effort=none）：
//
//	400 {"error":{"type":"server_error","message":"Upstream request failed:
//	 [bad_request_error] invalid params, model \"MiniMax-M3.1-Flash\" requires
//	 adaptive thinking; thinking.type=\"disabled\" (including reasoning.effort=none)
//	 is not allowed (2013)"}}
//
// 这个坑在 4ZRECO 里**已经踩了三次**：裁决路径（server/intercept.go）、
// 压缩路径（agent/compaction.go）、旁路摘要路径（sidequestion/context.go）——
// 三处都各自硬编码了 thinking 参数，各修一次，但只要再有一处新代码带上
// thinking，就会复发第四次。
//
// 实测代价不轻：线上一次配置切换（LongCat → minimax-m3.1）后的两小时里，
// 裁决失败 787 次、压缩失败 130 次，**全部是同一个 400**。裁决路径每次失败
// 都走「按失败策略处理」，于是 787 次工具调用被静默放行——
// 裁决这道关卡在那两小时等于完全失效。
//
// ## 为什么在这里兜底
//
// llmpool 的 shouldFailover 明确把 400 判为「不切换」——
// "a malformed or over-long request fails identically everywhere"。
// 这个判断对「请求本身有问题」是对的，但 thinking 拒绝是**参数配置问题**，
// 不是请求问题：摘掉 thinking 字段后同一个请求就能成功。
//
// 所以在任务侧 LLM 调用的统一入口（taskLLMRuntime.Stream / Complete）做一次
// 「检测 → 换 provider → 原样重试」，这类错误就能自愈，而不必要求每个
// 调用方都记得别写 thinking。
//
// ## 降级为什么必须换 provider 而不是改请求
//
// thinking 参数是在 **provider 配置层**注入的（llm.Config.ThinkingType，
// 见 agent/provider.go 的 NewProvider），**不在 llm.CompletionRequest 里**。
// 请求里的 req.Thinking 恒为空（那是「本次调用覆盖 profile 设置」用的
// 请求级开关，与 profile 级的 thinking_type 不是一回事）。
//
// 所以第一版实现（改 req.Thinking）**根本不触发**——条件
// requestHasThinking(req) 永远为 false。实测：把 profile 的 thinking_type
// 设成 disabled 后，2013 错误如期出现 23 次，而降级日志 0 次。
//
// 正确的降级是**重建一个不发 thinking.type 的 provider**（agent.Config
// .SuppressThinking），用它在同一次调用里重试。

// thinkingRejectedMarkers 是上游拒绝 thinking 参数时的特征串。
//
// 用小写匹配，因为不同网关的大小写不一致（实测见过 "requires adaptive
// thinking" 与 "thinking.type=\"disabled\" is not allowed" 两种形态，
// 且 2013 这个错误码来自网关而非模型本身）。
var thinkingRejectedMarkers = []string{
	"requires adaptive thinking",
	"thinking.type=\"disabled\"",
	"thinking.type='disabled'",
	"is not allowed (2013)",
	"2013)", // 兜底：部分网关只回错误码
}

// isThinkingRejected 报告 err 是否是「模型拒绝 thinking 参数」这一类错误。
//
// 只在错误文本里找特征串，不看 HTTP 状态码：上游把 400 包在
// server_error 里传回来，走标准库的 statusOf 未必能取到 400，
// 而文本特征在实测的三次踩坑里都稳定出现。
func isThinkingRejected(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, m := range thinkingRejectedMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// providerSendsThinking 报告 provider 的配置是否会发送 thinking.type。
//
// 判定依据是**配置**（agent.Config.ThinkingType），不是请求——因为请求里
// 永远没有这个参数（见文件头注释）。
func providerSendsThinking(cfg agent.Config) bool {
	if cfg.SuppressThinking {
		return false
	}
	return cfg.ThinkingType != ""
}

// ensure llm 引用保留（降级后的 provider 仍是 llm.Provider）。
var _ llm.Provider = (llm.Provider)(nil)
