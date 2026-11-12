package db

import (
	"fmt"
	"testing"
	"time"
)

// TestRenameConversationIfTitleCAS — 自动标题的 CAS 式防覆盖协议（DSN 门控，
// ZRECO_PG_DSN 缺省 skip，与同目录其他 PG 测试一致）：占位/初值可被异步标题
// 替换，用户手动改过的标题必须保留。
func TestRenameConversationIfTitleCAS(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	title := fmt.Sprintf("auto-title-cas-%d", time.Now().UnixNano())
	c, err := d.CreateConversation("mainagent", title, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(c.ID) })

	// 初值占位标题可被替换。
	if err := d.RenameConversationIfTitle(c.ID, "LLM 生成的标题", title); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetConversation(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || after.Title != "LLM 生成的标题" {
		t.Fatalf("placeholder not replaced: %+v", after)
	}

	// 手动改名后不可被覆盖。
	if _, err := d.UpdateConversation(c.ID, ConversationPatch{Title: strPtr("用户手动改的标题")}); err != nil {
		t.Fatal(err)
	}
	if err := d.RenameConversationIfTitle(c.ID, "迟到的自动标题", title); err != nil {
		t.Fatal(err)
	}
	after, err = d.GetConversation(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || after.Title != "用户手动改的标题" {
		t.Fatalf("manual title overwritten: %+v", after)
	}
}

func strPtr(s string) *string { return &s }
