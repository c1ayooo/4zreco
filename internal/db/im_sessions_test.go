package db

// im_sessions_test.go — IM 会话映射持久层的 DSN 门控测试（ZRECO_PG_DSN 缺省
// skip，与 hitl_test.go 同款门控）：Get/Upsert 往返、/new 轮换复写、user_id
// 空串落 NULL、会话删除级联清映射。

import (
	"testing"
)

func TestIMSessionUpsertGetRotateCascade(t *testing.T) {
	d := hitlTestDB(t)

	conv, err := d.CreateConversation("auto", "IM · test", nil)
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(conv.ID) })

	// 首绑：user_id 带值
	if err := d.UpsertIMSession("feishu", "chat-1", conv.ID, "ou_abc"); err != nil {
		t.Fatalf("UpsertIMSession: %v", err)
	}
	m, err := d.GetIMSession("feishu", "chat-1")
	if err != nil || m == nil {
		t.Fatalf("GetIMSession: m=%v err=%v", m, err)
	}
	if m.ConversationID != conv.ID || m.UserID != "ou_abc" || m.Platform != "feishu" || m.ChatID != "chat-1" {
		t.Fatalf("映射字段不回环: %+v", m)
	}

	// /new 轮换：复写 conversation_id、user_id 可为空串（落 NULL 读回空串）
	conv2, err := d.CreateConversation("auto", "IM · test 新", nil)
	if err != nil {
		t.Fatalf("CreateConversation 2: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(conv2.ID) })
	if err := d.UpsertIMSession("feishu", "chat-1", conv2.ID, ""); err != nil {
		t.Fatalf("UpsertIMSession rotate: %v", err)
	}
	m, err = d.GetIMSession("feishu", "chat-1")
	if err != nil || m == nil {
		t.Fatalf("GetIMSession after rotate: m=%v err=%v", m, err)
	}
	if m.ConversationID != conv2.ID || m.UserID != "" {
		t.Fatalf("轮换后映射不正确: %+v（旧会话 %d 保留但不再映射）", m, conv.ID)
	}

	// 不同 chat 互不影响
	if m2, err := d.GetIMSession("dingtalk", "chat-1"); err != nil || m2 != nil {
		t.Fatalf("不存在的映射应返回 nil,nil: m=%v err=%v", m2, err)
	}

	// 会话删除 → FK 级联清映射，下次该 chat 来消息自动开新会话
	if err := d.DeleteConversation(conv2.ID); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}
	if m3, err := d.GetIMSession("feishu", "chat-1"); err != nil || m3 != nil {
		t.Fatalf("级联删除后映射应消失: m=%v err=%v", m3, err)
	}
}
