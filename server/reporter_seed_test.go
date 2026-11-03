package server

import (
	"testing"

	"github.com/c1ayooo/4zreco/db"
)

// reporter 的 seed 走 settings flag 守卫「一次性」。flag=true 时直接 return，
// 意味着**agent 存在而触发器缺失**的情况下永远补不回来。
//
// 实测踩过（2026-10-21 全量重置）：TRUNCATE ... CASCADE 连带清了
// agent_triggers，reporter 的 report_finding 触发器消失，而 flag 还在 true。
// 结果：漏洞上报后不再自动触发报告 Agent → 流量证据没人去核对绑定 →
// 报告里的 HTTP 证据全缺（traffic_evidence_snapshots /
// finding_traffic_bindings 全是 0 条）。
//
// 修法：flag=true 时也走一遍「补齐缺失项」，已存在的部分不覆盖。
func TestSeedReporterAgentRepairsMissingTrigger(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// 隔离：备份 reporter 的触发器与 flag，测完还原。
	origTriggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	origFlag, _, _ := pg.GetSetting("reporter_agent_seed_v1")
	t.Cleanup(func() {
		for _, tr := range origTriggers {
			_ = pg.DeleteTrigger(tr.ID)
		}
		for _, tr := range origTriggers {
			_, _ = pg.CreateTrigger(&db.AgentTrigger{
				AgentKey:        tr.AgentKey,
				Enabled:         tr.Enabled,
				IntervalSec:     tr.IntervalSec,
				OnToolCall:      tr.OnToolCall,
				ToolNames:       tr.ToolNames,
				ToolCallMessage: tr.ToolCallMessage,
			})
		}
		_ = pg.SetSetting("reporter_agent_seed_v1", origFlag)
	})

	// 前置：reporter agent 存在、flag=true、触发器全部删掉
	if _, err := pg.GetAgentByKey("reporter"); err != nil {
		t.Skipf("reporter agent missing (%v) — skipping", err)
	}
	for _, tr := range origTriggers {
		if err := pg.DeleteTrigger(tr.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.SetSetting("reporter_agent_seed_v1", "true"); err != nil {
		t.Fatal(err)
	}
	if list, _ := pg.ListTriggersFor("reporter"); len(list) != 0 {
		t.Fatalf("precondition: triggers should be empty, got %d", len(list))
	}

	// 跑 seed —— flag 已是 true，旧实现会直接 return（触发器补不回来）
	s := &Server{m: &Manager{pg: pg}}
	s.seedReporterAgent()

	list, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tr := range list {
		if tr.OnToolCall && containsString(tr.ToolNames, "report_finding") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report_finding trigger was not repaired: %+v", list)
	}
}
