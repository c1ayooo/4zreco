package server

// 拒答守卫（llmguard）的服务端接线。移植自 Pojun：模型把授权内安全验证误判成
// 高风险请求而拒答时，按「授权+技术产出」表述自动重试（非流式最多 retries 次；
// 流式缓冲前 160 字判定、拒答丢弃重试）。开关与重试上限走 settings
// （refusal_guard_enabled 默认开 / refusal_guard_retries 默认 2），
// ZRECO_REFUSAL_GUARD / ZRECO_REFUSAL_RETRIES 设合法值时覆盖（见 manager.go）。
//
// 挂点语义：GuardRefusal 包在**每条 provider 链成员的最外层**（llmrec 录制与
// bindSideProvider 之内、llmpool 轮询成员之内）——providerForProfile 与 applyLLM
// 的 env 配置分支是 provider 组装仅有的两个构造点，两处都包；轮询链的每个成员
// 都经 providerForProfile 构造，因此 failover 后守卫仍然生效。守卫的每次重试
// 都会经 llmrec 落盘（重试请求带追加了口径的 system，录制里看得到）。

import (
	"github.com/c1ayooo/4zreco/internal/llmguard"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

// guardRefusal wraps prov in the refusal-retry guard when the setting is on.
// prov unchanged when the manager/DB is missing or the guard is off.
func (s *Server) guardRefusal(prov llm.Provider) llm.Provider {
	if s == nil || s.m == nil || !s.m.RefusalGuardEnabled() {
		return prov
	}
	return llmguard.GuardRefusal(prov, s.m.RefusalGuardRetries())
}
