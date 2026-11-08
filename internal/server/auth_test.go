package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
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

// ---------- 注册失效性：已有账号时 init 必须失败 ----------

// 「仅首次可设」的最终兜底是 settings 主键约束：InsertSettingIfAbsent 的重复
// 插入（并发 init 的失败者）拿到 inserted=false 且绝不覆盖已有值。authInit 的
// race 输家走的就是这条腿。键带时间戳——共享库重跑不撞唯一约束（§1 的坑）。
func TestInsertSettingIfAbsentKeepsExistingValue(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	key := fmt.Sprintf("auth.test.insert_if_absent.%d", time.Now().UnixNano())
	inserted, err := m.pg.InsertSettingIfAbsent(key, "first")
	if err != nil || !inserted {
		t.Fatalf("首次插入应成功: inserted=%v err=%v", inserted, err)
	}
	inserted, err = m.pg.InsertSettingIfAbsent(key, "second")
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("重复插入应返回 inserted=false")
	}
	v, ok, err := m.pg.GetSetting(key)
	if err != nil || !ok || v != "first" {
		t.Fatalf("已有值不得被覆盖: v=%q ok=%v err=%v", v, ok, err)
	}
}

// 已有账号后注册入口必须失效：预置密码（SetSetting 幂等，共享库重跑安全）后
// 重放 init 必须 403、不签发 token、库中哈希原样保留。快速失败路径（GetSetting
// 命中）由本用例钉死；主键约束兜底由 TestInsertSettingIfAbsentKeepsExistingValue
// 钉死。预置哈希用 MinCost——本用例不走比对，只是占位。
func TestAuthInitRejectedWhenPasswordAlreadySet(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init",
		strings.NewReader(`{"password":"a different pass phrase"}`)))

	if w.Code != http.StatusForbidden {
		t.Fatalf("已有密码时 init 应 403，得到 %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("重放 init 不得签发 token: %s", w.Body.String())
	}
	// 防的是覆盖，不只是拒绝：库中哈希必须与预置值逐字节一致。
	stored, ok, err := m.pg.GetSetting(authPassKey)
	if err != nil || !ok || stored != string(hash) {
		t.Fatalf("已有哈希不得被覆盖: ok=%v err=%v", ok, err)
	}
}

// ---------- change-password 旧密码防爆破 ----------

// loginGuard 的失败动作按 -fail 后缀识别：端点接入防爆破只需取个 -fail 后缀的
// action 名。回归点：change-password 接入时若忘了记失败，限流就是摆设。
func TestLoginGuardRecordsFailForFailSuffixedActions(t *testing.T) {
	prev := loginLimit
	loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	defer func() { loginLimit = prev }()

	r := httptest.NewRequest("POST", "/api/auth/change-password", nil) // RemoteAddr=192.0.2.1
	w := httptest.NewRecorder()
	if !loginGuard(w, r, "change-password-fail") {
		t.Fatal("未锁定时应放行并记失败")
	}
	if n := len(loginLimit.fails["192.0.2.1"]); n != 1 {
		t.Fatalf("-fail 后缀 action 应记失败，实际 %d 笔", n)
	}
	// 补满阈值后，同 action 的请求应被 429 拦下。
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		loginLimit.recordFail("192.0.2.1")
	}
	w2 := httptest.NewRecorder()
	if loginGuard(w2, r, "change-password-fail") {
		t.Fatal("达到阈值后应拦截")
	}
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("应回 429，得到 %d", w2.Code)
	}
}

// 旧密码暴破必须与登录同池限流：token 是可能被偷的（7 天有效期），密码不该能
// 猜——持有效 token 的攻击者连错旧密码达阈值后，不再进入比对、直接 429，且
// 锁定期内猜测正确同样被拦（锁定不看猜测对错，与登录语义一致）。
func TestAuthChangePasswordOldPasswordBruteForceLocksOut(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	// 隔离全局限流器：失败计数不泄漏给其他用例，也不被它们污染。
	prev := loginLimit
	loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	defer func() { loginLimit = prev }()

	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{m: m}
	s.jwtKey.Store(key)
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}

	call := func(oldPass string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/auth/change-password",
			strings.NewReader(`{"old_password":"`+oldPass+`","new_password":"brand-new-passphrase"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.authChangePassword(w, req)
		return w
	}

	for i := 0; i < loginMaxFailsPerIP; i++ {
		if w := call("wrong-guess"); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误旧密码应 401，得到 %d: %s", i+1, w.Code, w.Body.String())
		}
	}
	if w := call("wrong-guess"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("阈值后应 429（不再进入旧密码比对），得到 %d: %s", w.Code, w.Body.String())
	}
	if w := call("correct horse battery"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("锁定期内正确密码也应 429，得到 %d: %s", w.Code, w.Body.String())
	}
}
