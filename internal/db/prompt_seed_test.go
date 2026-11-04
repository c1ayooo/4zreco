package db

import (
	"fmt"
	"testing"
	"time"
)

// SeedPromptVersioned 是"提示词改进能随版本下发"的机制，规则必须精确：
// 系统播种的可升级、用户手改的绝不覆盖。
func TestSeedPromptVersioned(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	key := fmt.Sprintf("t_prompt_%d", time.Now().UnixNano())
	var agentID int64
	if err := d.QueryRow(`INSERT INTO agents (key, name, role) VALUES ($1,$2,'worker') RETURNING id`, key, key).
		Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM agents WHERE id=$1`, agentID) })

	const v1 = "第一版内置提示词"
	const v2 = "第二版内置提示词"

	// 1) 空 → 播种
	up, err := d.SeedPromptVersioned(agentID, v1)
	if err != nil || !up {
		t.Fatalf("首次播种应写入，得到 upgraded=%v err=%v", up, err)
	}
	// 2) 内容未变 → 不重复写
	up, err = d.SeedPromptVersioned(agentID, v1)
	if err != nil || up {
		t.Fatalf("内容未变不应升级，得到 upgraded=%v err=%v", up, err)
	}
	// 3) 代码默认变了 → 升级，且旧版本进 history
	up, err = d.SeedPromptVersioned(agentID, v2)
	if err != nil || !up {
		t.Fatalf("系统播种的提示词应随代码升级，得到 upgraded=%v err=%v", up, err)
	}
	vers, err := d.ListPromptVersions(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 2 {
		t.Fatalf("应保留 2 个版本(历史可回溯)，得到 %d", len(vers))
	}
	var cur string
	if err := d.QueryRow(`SELECT p.template_text FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.id=$1`, agentID).
		Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur != v2 {
		t.Fatalf("当前版本应为新版，得到 %q", cur)
	}

	// 4) 用户手改后 → 永不覆盖
	if _, err := d.SavePrompt(agentID, "我自己改的提示词", "手动编辑", "ui"); err != nil {
		t.Fatal(err)
	}
	up, err = d.SeedPromptVersioned(agentID, "第三版内置提示词")
	if err != nil {
		t.Fatal(err)
	}
	if up {
		t.Fatal("用户编辑过的提示词不该被自动升级覆盖")
	}
	if err := d.QueryRow(`SELECT p.template_text FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.id=$1`, agentID).
		Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur != "我自己改的提示词" {
		t.Fatalf("用户内容被改动了：%q", cur)
	}
}
