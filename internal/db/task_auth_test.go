package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNormalizeTaskAuth 钉住校验与默认值：只校验启用中的配置；URL 必须
// http/https；方法/请求体格式/字段名有安全默认；用户密码必填。
func TestNormalizeTaskAuth(t *testing.T) {
	ok := &TaskAuthConfig{Enabled: true, LoginURL: "https://t.example.com/login", Username: "u", Password: "p"}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Method != "POST" || ok.ContentType != "json" || ok.UsernameField != "username" || ok.PasswordField != "password" {
		t.Fatalf("defaults missing: %+v", ok)
	}
	if !ok.HasPassword {
		t.Fatal("HasPassword must be derived")
	}

	bad := []*TaskAuthConfig{
		{Enabled: true, LoginURL: "ftp://t/login", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Method: "PUT", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", ContentType: "xml", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Username: "u"},
		{Enabled: true, LoginURL: "https://t/login", Password: "p"},
	}
	for _, b := range bad {
		if err := b.Normalize(); err == nil {
			t.Fatalf("expected error for %+v", b)
		}
	}
	// 关闭的配置不校验（可存草稿）。
	if err := (&TaskAuthConfig{Enabled: false, LoginURL: "not-a-url"}).Normalize(); err != nil {
		t.Fatal("disabled config must not be validated")
	}
}

// TestTaskAuthSecretsNotSerialized 是安全边界：任何 JSON 序列化（API 响应）
// 都不能出现 password / totp_secret；DB 存取走 DBValue 才带秘密。
func TestTaskAuthSecretsNotSerialized(t *testing.T) {
	a := &TaskAuthConfig{
		Enabled: true, LoginURL: "https://t/login", Username: "alice", Password: "s3cret",
		TOTPSecret: "GEZDGNBV", HasPassword: true, HasTOTP: true,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "GEZDGNBV") {
		t.Fatalf("API JSON leaked secrets: %s", raw)
	}

	dbRaw, err := a.DBValue()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dbRaw), "s3cret") || !strings.Contains(string(dbRaw), "GEZDGNBV") {
		t.Fatalf("DBValue must persist secrets: %s", dbRaw)
	}
	back := ParseTaskAuth(dbRaw)
	if back == nil || back.Password != "s3cret" || back.TOTPSecret != "GEZDGNBV" || !back.HasPassword || !back.HasTOTP {
		t.Fatalf("roundtrip failed: %+v", back)
	}
	if ParseTaskAuth([]byte("null")) != nil || ParseTaskAuth(nil) != nil {
		t.Fatal("empty config must parse to nil")
	}
}

// TestTaskAuthPromptBlock worker 需要明文密码才能登录，但块要有明确纪律：
// 报告不得写出密码/TOTP。
func TestTaskAuthPromptBlock(t *testing.T) {
	a := &TaskAuthConfig{Enabled: true, LoginURL: "https://t/login", Method: "POST", ContentType: "json",
		UsernameField: "user", PasswordField: "pass", Username: "alice", Password: "s3cret",
		SuccessStatus: 200, SuccessContains: "token"}
	a.HasPassword = true
	block := a.PromptBlock()
	for _, want := range []string{"https://t/login", "alice", "s3cret", "token", "不要在报告里写出密码"} {
		if !strings.Contains(block, want) {
			t.Fatalf("prompt block missing %q:\n%s", want, block)
		}
	}
	if (&TaskAuthConfig{}).PromptBlock() != "" {
		t.Fatal("disabled config must render empty block")
	}
}
