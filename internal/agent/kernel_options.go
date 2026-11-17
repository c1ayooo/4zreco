package agent

import (
	"time"

	"github.com/c1ayooo/4zreco/internal/acllm"
	"github.com/c1ayooo/4zreco/internal/kernel/askernel"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
	"github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// kernelOptionsSeed 聚合 planner/worker/mainagent/chat 四处装配 askernel.Options
// 时的差异化参数（角色相关：模型 provider、system 分段、工具集、代理与搜索后端、
// 预算与收尾资源）。O3（2026-11-13 体检）：原先四处近逐字重复的约 40 行装配块
// 收敛进 kernelOptions，公共段（权限 bypass、WebFetch 走记录代理、WebSearch 后端
// 八连、Bash 代理环境、cmd-output 布局、压缩配置）字段值与语义逐字等价；
// Hooks / CheckpointStore / Transcript / SessionID 等角色专属字段仍由调用点在
// 返回值上补设，收尾词（wrapupSettlement）也留在调用点。
type kernelOptionsSeed struct {
	prov   llm.Provider      // 经 acllm.BridgeModel 桥接（failover/录制/quota 栈不变）
	system []string          // deferredSystem 产出的 system 分段
	tools  []actool.CoreTool // 本角色可见工具集（含 AugmentTools 追加的 skill/MCP）
	def    DeferredInfo      // AugmentTools 产出的延迟工具信息（Deferred/Unlock）

	proxyAddr   string // 记录代理地址（WebFetch 出口 + Bash 代理环境共用；空 = 直连）
	proxyCACert string // 记录代理 CA 证书路径（WebFetch HTTPS 校验 + Bash 信任链共用）
	webSearch   WebSearchOpts
	// bashUA 追加进 BashEnv 的任务级客户端 UA（ZRECO_UA，worker 按任务稳定分配；
	// 其余三处留空——uaEnv 对空串原样返回，等价于仅代理环境）。
	bashUA string

	workingDir string // 会话工作目录；ToolOutputDir 由它派生（<workingDir>/cmd-output）
	maxTurns   int    // 0 = unlimited (configurable in agent management)
	// maxDuration 是 run 墙钟预算，0 = 不限（mainagent 不设；worker/planner 传入
	// clampMaxDuration 按 task deadline 夹逼后的剩余；chat 传入按轮重置的预算）。
	maxDuration        time.Duration
	maxToolOutputChars int // 0 = SDK 默认(tool.Capture 的 30000 字符)；仅 worker 收到 12000
	compactionWindow   int // compactionConfig 的窗口 token 数
	todos              *actool.TodoStore
	nonStreaming       bool // 该 profile 选非流式时走 Provider.Complete
	maxTokens          int  // 0 = 不发上限,由服务端默认值决定
}

// kernelOptions 装配四处 agent 会话共用的 askernel.Options 公共段（O3 收敛）。
// 字段值与原四处字面量逐字等价：EnableWebFetch 恒开（走记录代理留痕，载入代理
// CA 验证 MITM 重签的 HTTPS 证书——而非关掉校验；proxy 空则直连）；BashEnv 由
// 代理地址+CA 推导、bashUA 非空再追加；ToolOutputDir 恒为 <workingDir>/cmd-output
// （大回显落盘 + 回显内给绝对路径指针）。
func kernelOptions(seed kernelOptionsSeed) askernel.Options {
	return askernel.Options{
		Model:          acllm.BridgeModel(seed.prov),
		SystemPrompt:   seed.system,
		Tools:          seed.tools,
		DeferredTools:  seed.def.Deferred,
		UnlockSet:      seed.def.Unlock,
		PermissionMode: permission.ModeBypass, // 4zreco 全 agent 显式 bypass
		EnableWebFetch: true,
		WebFetchProxy:  seed.proxyAddr,
		WebFetchCACert: seed.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       seed.webSearch.Enabled,
		WebSearchBackend:      seed.webSearch.Backend,
		BraveSearchAPIKey:     seed.webSearch.BraveKey,
		TavilySearchAPIKey:    seed.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: seed.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  seed.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   seed.webSearch.DeepSeekModel,
		WebSearchProxy:        seed.webSearch.Proxy,
		// Bash 子命令默认走代理+信任 CA（工具无需 -x/-k）；bashUA 非空再注入
		// ZRECO_UA（worker 的 curl/httpx 等统一使用，任务内不更换）。
		BashEnv:            uaEnv(proxyEnv(seed.proxyAddr, seed.proxyCACert), seed.bashUA),
		WorkingDir:         seed.workingDir,
		ToolOutputDir:      cmdOutDir(seed.workingDir), // <workingDir>/cmd-output/
		MaxTurns:           seed.maxTurns,
		MaxDuration:        seed.maxDuration,
		Compaction:         compactionConfig(seed.compactionWindow),
		NonStreaming:       seed.nonStreaming,
		MaxTokens:          seed.maxTokens,
		MaxToolOutputChars: seed.maxToolOutputChars,
		// 规划待办（TodoWrite 工具的 backing store）：planner 传跨唤醒共享 store，
		// worker/mainagent/chat 传会话级新 store；nil = 不挂 TodoWrite 工具
		// （session.go 按 nil 判定）。O3 收敛时曾漏接导致 planner Panic（opts.Todos 为 nil）。
		Todos: seed.todos,
	}
}
