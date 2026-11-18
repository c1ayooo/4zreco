package server

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/config"
)

// U4（上游 v0.4.60）：技能速查块必须注入 system prompt——Skill 是元工具，模型
// 不被 system prompt 显式提醒就几乎不调（上游 56k 调用里 Skill 仅 8 次、任务 18
// 零次）。真 PG：装配 wireAgentAugment → 给 worker 绑定技能 → 速查块含绑定项。
func TestSkillIndexBlockCoversBindings(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, config.Paths{Skills: "../../skills", Data: t.TempDir(), Base: t.TempDir()})

	worker, err := s.m.pg.GetAgentByKey("worker")
	if err != nil {
		t.Fatal(err)
	}
	// 给 worker 绑两个 skill（模拟用户/默认绑定）。共享库：先快照原绑定，
	// 测试结束后恢复，不残留改动（AGENTS.md §2 共享库纪律）。
	orig, _ := s.m.pg.AgentSkillNames(worker.ID)
	t.Cleanup(func() { _ = s.m.pg.SetAgentSkillVisibility(worker.ID, orig) })
	if err := s.m.pg.SetAgentSkillVisibility(worker.ID, []string{"vuln-hunting", "web-attack-methods"}); err != nil {
		t.Fatal(err)
	}
	blk := agent.SkillIndexBlock("worker")
	if blk == "" {
		t.Fatal("worker 有绑定但速查块为空")
	}
	if !strings.Contains(blk, "vuln-hunting") || !strings.Contains(blk, "web-attack-methods") {
		t.Fatalf("速查块缺绑定项：%s", blk)
	}
	if !strings.Contains(blk, "Skill(") {
		t.Fatalf("速查块缺调用方式说明：%s", blk)
	}
	// 未知 agent key → 空块，不污染提示。（不依赖共享库的绑定状态——dev 库里
	// 任何内置 agent 都可能被用户绑过技能，goals 无绑定这个前提不成立。）
	if blk := agent.SkillIndexBlock("no-such-agent-key"); blk != "" {
		t.Fatalf("未知 agent key 不应有速查块：%s", blk)
	}
}
