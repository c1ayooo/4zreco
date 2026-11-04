package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// TestTOTPCode 用 RFC 6238 SHA1 测试向量钉住实现（密钥 "12345678901234567890"
// 的 Base32 形式；T=59s 时 8 位码 94287082 → 6 位取后 6 位 287082）。
func TestTOTPCode(t *testing.T) {
	code, err := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("totp=%s want 287082", code)
	}
	if _, err := totpCode("not-base32!!!", time.Now()); err == nil {
		t.Fatal("invalid base32 must error")
	}
}

// TestRunAuthCheck 用本地 httptest 验证三种登录形态与成功判定，并确认结果
// 不回显密码（日志/详情都没有）。目标站点不需要真实网络。
func TestRunAuthCheck(t *testing.T) {
	var gotUser, gotPass, gotTOTP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stringsHasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			_ = r.ParseForm()
			gotUser, gotPass, gotTOTP = r.PostForm.Get("user"), r.PostForm.Get("pass"), r.PostForm.Get("totp")
		} else {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotUser, gotPass, gotTOTP = body["user"], body["pass"], body["totp"]
		}
		if gotUser == "alice" && gotPass == "s3cret" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"token":"ok-token"}`))
			return
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
	}))
	defer srv.Close()

	base := &db.TaskAuthConfig{
		Enabled: true, LoginURL: srv.URL + "/login", Method: "POST",
		ContentType: "json", UsernameField: "user", PasswordField: "pass",
		Username: "alice", Password: "s3cret", SuccessContains: "token",
	}
	res := runAuthCheck(base)
	if !res.OK || res.StatusCode != 200 {
		t.Fatalf("json login should pass: %+v", res)
	}
	if gotTOTP != "" {
		t.Fatal("totp must not be sent when unconfigured")
	}

	// 失败凭据：401 + 缺 token → 不通过，且详情不含密码。
	bad := *base
	bad.Password = "wrong-pass"
	res = runAuthCheck(&bad)
	if res.OK {
		t.Fatalf("bad credentials must fail: %+v", res)
	}
	if stringsContains(res.Detail, "wrong-pass") {
		t.Fatal("detail leaked password")
	}

	// form 形态
	form := *base
	form.ContentType = "form"
	res = runAuthCheck(&form)
	if !res.OK || gotUser != "alice" || gotPass != "s3cret" {
		t.Fatalf("form login should pass: %+v user=%s pass=%s", res, gotUser, gotPass)
	}

	// 未启用：明确说明而不是误判成功。
	off := db.TaskAuthConfig{}
	if res := runAuthCheck(&off); res.OK {
		t.Fatal("disabled config must not report ok")
	}
}

func stringsHasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
