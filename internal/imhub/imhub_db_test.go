package imhub

// imhub_db_test.go — 配置读写与掩码面的 DSN 门控测试（ZRECO_PG_DSN 缺省 skip，
// 与 internal/db 的门控测试同款）。验证：Load 零值回落、save/Load 往返、
// Payload 只回 *_set 不回明文、Apply 的 nil=不改 / ""=清除 指针语义。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	pgdb "github.com/c1ayooo/4zreco/internal/db"
)

func imhubTestDB(t *testing.T) *pgdb.DB {
	t.Helper()
	dsn, _, err := pgdb.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := pgdb.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestConfigLoadSavePayloadMasking(t *testing.T) {
	d := imhubTestDB(t)
	t.Cleanup(func() { _ = d.SetSetting(SettingIMBot, "") })
	_ = d.SetSetting(SettingIMBot, "")

	h := New(context.Background(), d, nil)

	// 首读零值回落：agent_key 缺省 auto。
	cfg := h.LoadConfig()
	if cfg.AgentKey != "auto" {
		t.Fatalf("首读 agent_key 应回落 auto: %q", cfg.AgentKey)
	}

	// 保存带明文凭据的配置（平台开关全关，ApplyConfig 不会拉起任何出站循环）。
	sec := "super-secret-value"
	off := false
	var agentID int64 = 1000002
	in := SettingsInput{
		AgentKey: ptrStr("pentest"),
		Feishu: &struct {
			Enabled   *bool   `json:"enabled"`
			AppID     *string `json:"app_id"`
			AppSecret *string `json:"app_secret"`
		}{Enabled: &off, AppID: ptrStr("cli_123"), AppSecret: &sec},
		Wecom: &struct {
			Enabled        *bool   `json:"enabled"`
			CorpID         *string `json:"corp_id"`
			CorpSecret     *string `json:"corp_secret"`
			AgentID        *int64  `json:"agent_id"`
			CallbackToken  *string `json:"callback_token"`
			EncodingAESKey *string `json:"encoding_aes_key"`
		}{Enabled: &off, CorpID: ptrStr("corp9"), CorpSecret: &sec, AgentID: &agentID},
	}
	if err := h.Apply(in); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// 往返：明文在存储里（不落日志、不进响应）。
	cfg = h.LoadConfig()
	if cfg.Feishu.AppSecret != sec || cfg.Feishu.AppID != "cli_123" || cfg.Feishu.Enabled {
		t.Fatalf("feishu 配置未往返: %+v", cfg.Feishu)
	}
	if cfg.Wecom.AgentID != agentID || cfg.Wecom.CorpID != "corp9" {
		t.Fatalf("wecom 配置未往返: %+v", cfg.Wecom)
	}
	if cfg.AgentKey != "pentest" {
		t.Fatalf("agent_key 未往返: %q", cfg.AgentKey)
	}

	// 掩码面：Payload 的 JSON 里绝不能出现明文，且 *_set 布尔在。
	raw, _ := json.Marshal(h.Payload())
	if strings.Contains(string(raw), sec) {
		t.Fatalf("Payload 泄漏了 App Secret 明文: %s", raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	fs := payload["feishu"].(map[string]any)
	if fs["app_secret_set"] != true || fs["app_id"] != "cli_123" {
		t.Fatalf("feishu 回显形状不对: %v", fs)
	}
	if _, has := fs["app_secret"]; has {
		t.Fatal("feishu 回显不应包含 app_secret 字段")
	}
	wc := payload["wecom"].(map[string]any)
	if wc["corp_secret_set"] != true {
		t.Fatalf("wecom 回显形状不对: %v", wc)
	}
	if !strings.HasSuffix(wc["callback_url"].(string), WecomCallbackPath) {
		t.Fatalf("callback_url 应以回调路径结尾: %v", wc["callback_url"])
	}

	// 指针语义：省略=不改；空串=清除。
	in2 := SettingsInput{
		Feishu: &struct {
			Enabled   *bool   `json:"enabled"`
			AppID     *string `json:"app_id"`
			AppSecret *string `json:"app_secret"`
		}{AppID: ptrStr("cli_changed")}, // Enabled/AppSecret 省略
	}
	if err := h.Apply(in2); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	cfg = h.LoadConfig()
	if cfg.Feishu.AppID != "cli_changed" || cfg.Feishu.AppSecret != sec || cfg.Feishu.Enabled {
		t.Fatalf("省略字段应保持不变: %+v", cfg.Feishu)
	}
	empty := ""
	in3 := SettingsInput{
		Feishu: &struct {
			Enabled   *bool   `json:"enabled"`
			AppID     *string `json:"app_id"`
			AppSecret *string `json:"app_secret"`
		}{AppSecret: &empty},
	}
	if err := h.Apply(in3); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	cfg = h.LoadConfig()
	if cfg.Feishu.AppSecret != "" {
		t.Fatalf("空串应清除凭据: %q", cfg.Feishu.AppSecret)
	}

	// enabled 显式往返：AppID 有值但 Secret 已空 → want 条件不满足，不会拉起循环。
	in4 := SettingsInput{
		Feishu: &struct {
			Enabled   *bool   `json:"enabled"`
			AppID     *string `json:"app_id"`
			AppSecret *string `json:"app_secret"`
		}{Enabled: boolPtr(true)},
	}
	if err := h.Apply(in4); err != nil {
		t.Fatalf("Apply 4: %v", err)
	}
	if cfg = h.LoadConfig(); !cfg.Feishu.Enabled {
		t.Fatalf("enabled 未往返: %+v", cfg.Feishu)
	}
}

func boolPtr(v bool) *bool { return &v }

func ptrStr(s string) *string { return &s }

// TestSessionCreationSingleflight 同一 chat 并发首条消息只建一个会话（2026-11-06
// 修复 4zrec 固有的双建竞态）：N 个 goroutine 并发走 sessionConversationLocked，
// 全部拿到同一会话，且会话映射一致。
func TestSessionCreationSingleflight(t *testing.T) {
	d := imhubTestDB(t)
	h := New(context.Background(), d, nil)
	const platform = "feishu"
	chatID := fmt.Sprintf("sf-%d", time.Now().UnixNano())

	const n = 8
	ids := make([]int64, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			conv := h.sessionConversationLocked(platform, chatID, "u1", Config{})
			if conv == nil {
				t.Errorf("goroutine %d: 开会话返回 nil", i)
				return
			}
			ids[i] = conv.ID
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("并发建会话分叉：ids[0]=%d ids[%d]=%d", ids[0], i, ids[i])
		}
	}
	m, err := d.GetIMSession(platform, chatID)
	if err != nil || m == nil {
		t.Fatalf("会话映射缺失: %v", err)
	}
	if m.ConversationID != ids[0] {
		t.Fatalf("映射指向 %d，与建会话 %d 不一致", m.ConversationID, ids[0])
	}
	// 清理：删会话级联掉 im_sessions
	if err := d.DeleteConversation(ids[0]); err != nil {
		t.Fatalf("清理会话: %v", err)
	}
}

// TestTelegramOffsetPersistence Telegram 轮询 offset 的 settings 持久化：
// 按 token 指纹分桶互不覆盖、未配置回落 0、save 后 load 往返一致。
func TestTelegramOffsetPersistence(t *testing.T) {
	d := imhubTestDB(t)
	h := New(context.Background(), d, nil)
	t.Cleanup(func() { _ = d.SetSetting(imTelegramOffsetsKey, "{}") })

	const fp1, fp2 = "fp-aaaa", "fp-bbbb"
	if got := h.loadTelegramOffset(fp1); got != 0 {
		t.Fatalf("未配置应回落 0，got %d", got)
	}
	h.saveTelegramOffset(fp1, 4242)
	h.saveTelegramOffset(fp2, 7)
	if got := h.loadTelegramOffset(fp1); got != 4242 {
		t.Fatalf("fp1 往返失败: got %d", got)
	}
	if got := h.loadTelegramOffset(fp2); got != 7 {
		t.Fatalf("fp2 往返失败: got %d", got)
	}
	h.saveTelegramOffset(fp1, 4243)
	if got := h.loadTelegramOffset(fp1); got != 4243 {
		t.Fatalf("覆盖写失败: got %d", got)
	}
	if got := h.loadTelegramOffset(fp2); got != 7 {
		t.Fatalf("覆盖写串桶: fp2 got %d", got)
	}
}
