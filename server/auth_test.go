package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

// testKey 构造一个装好签名 key 的 Server（atomic.Value 字段无法在字面量里
// 直接初始化，测试统一走这里）。
func testKey(k []byte) *Server {
	s := &Server{}
	s.jwtKey.Store(k)
	return s
}

// 登录防爆破：每 IP 10 分钟窗口内失败 5 次 → 锁 15 分钟；成功清零；
// 其他 IP 不受牵连；全局阈值兜底 XFF 伪造。
func TestLoginLimiterPerIPLockout(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginMaxFailsPerIP; i++ {
		l.recordFail("1.2.3.4")
	}
	ok, wait := l.allow("1.2.3.4")
	if ok {
		t.Fatal("连续失败后应锁定")
	}
	if wait <= 0 || wait > loginLockoutPerIP {
		t.Fatalf("锁定剩余时长=%v，应在 (0,%v] 内", wait, loginLockoutPerIP)
	}
	if ok, _ := l.allow("5.6.7.8"); !ok {
		t.Fatal("其他 IP 不应被牵连锁定")
	}
	l.recordSuccess("1.2.3.4")
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("成功登录后应清零解锁")
	}
}

// 成功后失败计数从零开始：不清零的话正常用户偶尔输错一次也会慢慢累积成锁。
func TestLoginLimiterSuccessResetsWindow(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		l.recordFail("9.9.9.9")
	}
	l.recordSuccess("9.9.9.9")
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		l.recordFail("9.9.9.9")
	}
	if ok, _ := l.allow("9.9.9.9"); !ok {
		t.Fatal("成功清零后未达阈值不应锁定")
	}
	l.recordFail("9.9.9.9")
	if ok, _ := l.allow("9.9.9.9"); ok {
		t.Fatal("清零后再次连续失败达阈值应锁定")
	}
}

// 全局兜底：每 IP 各失败 1 次、凑满全局阈值 → 全局锁定（含全新 IP）。
func TestLoginLimiterGlobalBackstop(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginGlobalMaxFails; i++ {
		l.recordFail(fmt.Sprintf("10.0.0.%d", i))
	}
	if ok, _ := l.allow("10.9.9.9"); ok {
		t.Fatal("达到全局失败阈值后，全新 IP 也应被全局锁定兜住")
	}
}

// /api/health 是唯一的未鉴权探活端点：响应体里绝不能出现 service 名与
// 版本号——那是公网测绘引擎最省事的 body 指纹。版本查询走鉴权的 /api/version。
func TestHealthResponseHasNoIdentity(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.health(w, httptest.NewRequest("GET", "/api/health", nil))
	body := w.Body.String()
	for _, banned := range []string{"4zreco", "4ZRECO", "version", "0.3"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Fatalf("health 响应包含指纹信息 %q: %s", banned, body)
		}
	}
	if !strings.Contains(body, "\"ok\":true") {
		t.Fatalf("health 应保留 ok 探活字段: %s", body)
	}
}

// 安全头中间件：nosniff / DENY / no-referrer 必在；/api/* 必带 no-store。
func TestSecurityHeadersApplied(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := securityHeaders(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/tasks", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("缺少 X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("缺少 X-Frame-Options: DENY")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("/api/* 缺少 Cache-Control: no-store")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("不应再放行任意跨域读取（ACAO 已移除）")
	}
}
