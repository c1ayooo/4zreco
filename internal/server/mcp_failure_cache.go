// MCP 连接失败的短期熔断。
//
// wireAgentAugment 在每个 agent run 都会把「enabled 且对该 agent 可见」的 MCP
// 连一遍。一个连不上的 MCP（比如 browser 用 `npx @playwright/mcp` 启动，而宿主
// 上没装 Node）就会在**每个 worker 启动时**刷一条错误——几十轮下来日志几乎
// 全是它，真正的问题被淹掉，而且每次都要 fork 一次进程去等它失败。
//
// 这里按 MCP 名字记住「最近失败时间」，失败后一段时间内直接跳过。成功一次
// 就清掉，下一轮照常重连（所以装好 npx 之后无需重启服务，最多等一个窗口）。
package server

import (
	"sync"
	"time"
)

const defaultMCPFailureCooldown = 10 * time.Minute

var (
	mcpFailMu   sync.Mutex
	mcpFailures = map[string]time.Time{}
)

// markMCPFailed records a connection failure; the MCP is skipped until the
// cooldown expires.
func markMCPFailed(name string, cooldown time.Duration) {
	if name == "" {
		return
	}
	if cooldown <= 0 {
		cooldown = defaultMCPFailureCooldown
	}
	mcpFailMu.Lock()
	mcpFailures[name] = time.Now().Add(cooldown)
	mcpFailMu.Unlock()
}

// mcpFailedUntil reports the cooldown deadline for a previously failed MCP.
// The second return is false when there is no recorded failure (or it expired).
func mcpFailedUntil(name string) (time.Time, bool) {
	mcpFailMu.Lock()
	defer mcpFailMu.Unlock()
	until, ok := mcpFailures[name]
	if !ok || time.Now().After(until) {
		if ok {
			delete(mcpFailures, name)
		}
		return time.Time{}, false
	}
	return until, true
}

// clearMCPFailure forgets a recorded failure so the next run reconnects at once.
func clearMCPFailure(name string) {
	mcpFailMu.Lock()
	delete(mcpFailures, name)
	mcpFailMu.Unlock()
}
