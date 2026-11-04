package server

import (
	"testing"
)

// agentRunSeconds 在读不到 DB / 读不到行时的兜底值必须是 1200（= 种子默认），
// 不能是 3600。
//
// 回归背景（2026-10-21）：兜底值曾是 3600。DB 读失败时所有 agent 的单次
// run 预算一起涨到 1 小时——而 3600s 实测出来的正是「4 个意图跑满一小时、
// 4.1 小时机时、零事实产出」。兜底值的作用恰恰是「DB 出问题时别让事情
// 变得更糟」，所以它必须跟种子默认走，不能跟「曾经有人改过的值」走。
func TestAgentRunSecondsFallbackMatchesSeedDefault(t *testing.T) {
	// 无 DB 的 Server：读不到任何配置 → 落到兜底。
	s := &Server{}
	got := s.agentRunSeconds("worker")
	if got != 1200 {
		t.Errorf("agentRunSeconds 兜底 = %d, want 1200（必须与种子默认一致）", got)
	}
	// 兜底值也不能是「不限时」——那等于把预算整个关掉。
	if got == 0 {
		t.Error("兜底值不能是 0（不限时）")
	}
}
