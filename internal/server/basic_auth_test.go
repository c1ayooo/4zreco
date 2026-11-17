package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/c1ayooo/4zreco/internal/config"
)

type basicAuthMemoryStore struct {
	raw string
	err error
}

func (m *basicAuthMemoryStore) GetSetting(string) (string, bool, error) {
	return m.raw, m.raw != "", m.err
}
func (m *basicAuthMemoryStore) SetSettingContext(ctx context.Context, _ string, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.err != nil {
		return m.err
	}
	m.raw = value
	return nil
}

func basicAuthTestServer(t *testing.T) (*Server, *basicAuthMemoryStore) {
	t.Helper()
	store := &basicAuthMemoryStore{}
	s := &Server{}
	s.jwtKey.Store([]byte("test-only-signing-key-32-characters"))
	if err := s.basicAuth.load(store); err != nil {
		t.Fatal(err)
	}
	return s, store
}

func saveBasicAuthForTest(s *Server, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.saveBasicAuthSettings(w, httptest.NewRequest("PUT", "/api/settings/basic-auth", strings.NewReader(body)))
	return w
}

// blockedBasicAuthStore 在 SetSettingContext 里挂起，模拟数据库写阻塞：验证保存
// 不阻塞请求快照、取消请求能释放保存互斥锁。
type blockedBasicAuthStore struct {
	basicAuthSettingsStore
	started  chan basicAuthConfig
	release  chan struct{}
	contexts chan context.Context
}

func (b *blockedBasicAuthStore) SetSettingContext(ctx context.Context, key, value string) error {
	var cfg basicAuthConfig
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return err
	}
	b.started <- cfg
	if b.contexts != nil {
		b.contexts <- ctx
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.basicAuthSettingsStore.SetSettingContext(ctx, key, value)
}

func TestBasicAuthBlockedSaveDoesNotBlockRequests(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			s, store := basicAuthTestServer(t)
			body := `{"enabled":false,"username":"entry","password":"original-pass"}`
			if enabled {
				body = `{"enabled":true,"username":"entry","password":"original-pass"}`
			}
			initial := saveBasicAuthForTest(s, body)
			if initial.Code != http.StatusOK {
				t.Fatal(initial.Body.String())
			}
			before := s.basicAuth.snapshot()
			blocked := &blockedBasicAuthStore{basicAuthSettingsStore: store, started: make(chan basicAuthConfig, 2), release: make(chan struct{})}
			s.basicAuth.mu.Lock()
			s.basicAuth.store = blocked
			s.basicAuth.mu.Unlock()
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
			t.Cleanup(release)
			first := make(chan *httptest.ResponseRecorder, 1)
			go func() { first <- saveBasicAuthForTest(s, `{"username":"new-entry"}`) }()
			select {
			case <-blocked.started:
			case <-time.After(time.Second):
				t.Fatal("save did not reach database")
			}
			// Exercise every kind of request sharing the gate while persistence waits.
			reads := make(chan error, 1)
			go func() {
				if s.basicAuth.snapshot() != before {
					reads <- errors.New("uncommitted settings became visible")
					return
				}
				h := s.requireBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
				for _, path := range []string{"/", "/_next/static/app.js", "/api/tasks", "/api/health"} {
					r := httptest.NewRequest(http.MethodGet, path, nil)
					if enabled {
						r.AddCookie(initial.Result().Cookies()[0])
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != http.StatusNoContent {
						reads <- errors.New("request rejected while old configuration is still active")
						return
					}
				}
				// Handler() 形态的最小等价物：门启用时 /api/health 必须仍可达（豁免）。
				mux := http.NewServeMux()
				mux.HandleFunc("GET /api/health", s.health)
				root := http.NewServeMux()
				root.Handle("/api/", securityHeaders(s.requireAuth(mux)))
				root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
				w := httptest.NewRecorder()
				root.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/health", nil))
				if w.Code != http.StatusOK {
					reads <- errors.New("health handler unavailable during save")
					return
				}
				reads <- nil
			}()
			select {
			case err := <-reads:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("database save blocked configuration reads and HTTP requests")
			}
			// A concurrent partial update must wait and preserve the first update.
			second := make(chan *httptest.ResponseRecorder, 1)
			go func() { second <- saveBasicAuthForTest(s, `{"enabled":true}`) }()
			select {
			case <-blocked.started:
				t.Fatal("concurrent saves reached persistence together")
			case <-time.After(50 * time.Millisecond):
			}
			release()
			for _, done := range []chan *httptest.ResponseRecorder{first, second} {
				select {
				case response := <-done:
					if response.Code != http.StatusOK {
						t.Fatal(response.Body.String())
					}
				case <-time.After(time.Second):
					t.Fatal("save did not finish after database release")
				}
			}
			cfg := s.basicAuth.snapshot()
			if cfg.Username != "new-entry" || !cfg.Enabled || cfg.PasswordHash != before.PasswordHash {
				t.Fatal("concurrent partial save lost a committed update")
			}
		})
	}
}

func TestBasicAuthBlockedSaveRespectsRequestCancellation(t *testing.T) {
	s, store := basicAuthTestServer(t)
	before := s.basicAuth.snapshot()
	blocked := &blockedBasicAuthStore{basicAuthSettingsStore: store, started: make(chan basicAuthConfig, 1), release: make(chan struct{}), contexts: make(chan context.Context, 1)}
	s.basicAuth.mu.Lock()
	s.basicAuth.store = blocked
	s.basicAuth.mu.Unlock()
	t.Cleanup(func() { close(blocked.release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodPut, "/api/settings/basic-auth", strings.NewReader(`{"username":"new-entry"}`)).WithContext(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.saveBasicAuthSettings(w, r)
		done <- w
	}()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("save did not reach database")
	}
	writeContext := <-blocked.contexts
	deadline, bounded := writeContext.Deadline()
	if !bounded || time.Until(deadline) > 10*time.Second {
		t.Fatal("database write has no bounded deadline")
	}
	cancel()
	select {
	case w := <-done:
		if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
			t.Fatalf("canceled save must fail without issuing a cookie: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("database save ignored request cancellation")
	}
	if s.basicAuth.snapshot() != before || store.raw != "" {
		t.Fatal("canceled save changed the committed settings")
	}
	// A canceled save must also release the save mutex for a later update.
	s.basicAuth.mu.Lock()
	s.basicAuth.store = store
	s.basicAuth.mu.Unlock()
	w := saveBasicAuthForTest(s, `{"username":"later-entry"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("later save failed: %s", w.Body.String())
	}
}

// minimalAuthRoot 复刻 Handler() 的分层（门 → securityHeaders → requireAuth → mux，
// 页面路径走占位 handler），供门状态机与 JWT 的组合回归用。
func minimalAuthRoot(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/version", s.version)
	mux.HandleFunc("GET /api/basic-auth/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/settings/basic-auth", s.getBasicAuthSettings)
	api := securityHeaders(s.requireAuth(mux))
	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	return s.requireBasicAuth(root)
}

func TestBasicAuthGate(t *testing.T) {
	s, _ := basicAuthTestServer(t)
	h := s.requireBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != 204 {
		t.Fatal("must default to disabled")
	}
	w = saveBasicAuthForTest(s, `{"enabled":true,"username":"entry","password":"密码:test-pass"}`)
	if w.Code != 200 {
		t.Fatalf("enable: %s", w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	if _, ok := verifyJWT(cookie.Value, s.currentJWTKey()); ok {
		t.Fatal("gate cookie accepted as admin JWT")
	}
	adminJWT, _ := signJWT(s.currentJWTKey())
	for _, tc := range []struct {
		name, path, user, pass, bearer string
		cookie                         *http.Cookie
		want                           int
	}{
		{name: "page challenge", path: "/", want: 401},
		{name: "login challenge", path: "/login", want: 401},
		{name: "asset challenge", path: "/_next/static/app.js", want: 401},
		{name: "auth API challenge", path: "/api/auth/status", want: 401},
		{name: "check challenge", path: "/api/basic-auth/check", want: 401},
		// /api/health 是无信息探活端点，门启用时豁免（监控探测不被挑战）。
		{name: "health exempt", path: "/api/health", want: 204},
		{name: "health prefix not exempt", path: "/api/health/anything", want: 401},
		{name: "wrong password", path: "/login", user: "entry", pass: "wrong", want: 401},
		{name: "wrong user", path: "/login", user: "wrong", pass: "密码:test-pass", want: 401},
		{name: "correct Unicode credentials", path: "/login", user: "entry", pass: "密码:test-pass", want: 204},
		{name: "gate cookie and bearer", path: "/api/tasks", cookie: cookie, bearer: adminJWT, want: 204},
		{name: "admin JWT cannot bypass gate", path: "/api/tasks", bearer: adminJWT, want: 401},
		{name: "tampered cookie", path: "/login", cookie: &http.Cookie{Name: basicAuthCookie, Value: cookie.Value + "x"}, want: 401},
		{name: "admin JWT is not gate cookie", path: "/login", cookie: &http.Cookie{Name: basicAuthCookie, Value: adminJWT}, want: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			if tc.user != "" {
				r.SetBasicAuth(tc.user, tc.pass)
			}
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			if tc.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if w.Code == 401 {
				wantChallenge := !strings.HasPrefix(tc.path, "/api/") || tc.path == "/api/basic-auth/check"
				if got := w.Header().Get("WWW-Authenticate"); (got != "") != wantChallenge {
					t.Fatalf("browser challenge=%q, want challenge=%v", got, wantChallenge)
				}
				if w.Header().Get("X-Zreco-Auth") != "basic" {
					t.Fatal("missing gate failure marker")
				}
			}
		})
	}
	// Passing the outer gate must not grant access to the inner admin API.
	root := minimalAuthRoot(s)
	r := httptest.NewRequest("GET", "/api/settings/basic-auth", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("gate cookie bypassed admin authentication")
	}
	r.Header.Set("Authorization", "Bearer "+adminJWT)
	w = httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("gate + JWT rejected: %s", w.Body.String())
	}
}

func TestBasicAuthSettingsPersistenceAndRevocation(t *testing.T) {
	s, store := basicAuthTestServer(t)
	w := saveBasicAuthForTest(s, `{"enabled":true,"username":"entry","password":"test-pass"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	oldCookie := w.Result().Cookies()[0]
	before := s.basicAuth.snapshot()
	if strings.Contains(w.Body.String(), "password_hash") || strings.Contains(store.raw, "test-pass") {
		t.Fatal("password leaked")
	}
	if bcrypt.CompareHashAndPassword([]byte(before.PasswordHash), []byte("test-pass")) != nil {
		t.Fatal("password not hashed")
	}
	var restarted basicAuthGate
	if err := restarted.load(store); err != nil || restarted.snapshot() != before {
		t.Fatalf("restart lost config: %v", err)
	}
	w = saveBasicAuthForTest(s, `{"enabled":false,"password":""}`)
	if w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("disable failed")
	}
	w = saveBasicAuthForTest(s, `{"enabled":true,"password":""}`)
	if w.Code != 200 || s.basicAuth.snapshot().PasswordHash != before.PasswordHash {
		t.Fatal("blank password must preserve hash")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(oldCookie)
	if s.validBasicAuthCookie(r, s.basicAuth.snapshot()) {
		t.Fatal("old cookie survived disable/re-enable")
	}
	cookie := w.Result().Cookies()[0]
	w = saveBasicAuthForTest(s, `{"username":"new-entry","password":"new-pass-123"}`)
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	if w.Code != 200 || s.validBasicAuthCookie(r, s.basicAuth.snapshot()) {
		t.Fatal("credential change did not revoke cookie")
	}
	before = s.basicAuth.snapshot()
	store.err = errors.New("DB unavailable")
	w = saveBasicAuthForTest(s, `{"enabled":false}`)
	if w.Code != 503 || s.basicAuth.snapshot() != before {
		t.Fatal("failed save changed live config")
	}
}

func TestBasicAuthValidationAndLoadFailures(t *testing.T) {
	s, _ := basicAuthTestServer(t)
	for _, body := range []string{
		`{"enabled":true}`, `{"enabled":true,"username":"entry"}`,
		`{"username":"bad:name"}`, `{"username":"bad\nname"}`, `{"password":"short"}`,
		`{"password":"` + strings.Repeat("a", 73) + `"}`, `not-json`,
	} {
		if w := saveBasicAuthForTest(s, body); w.Code != 400 {
			t.Fatalf("body=%s status=%d", body, w.Code)
		}
	}
	for _, store := range []*basicAuthMemoryStore{
		{err: errors.New("unavailable")}, {raw: `not-json`}, {raw: `{"enabled":true}`},
		{raw: `{"enabled":true,"username":"entry","revision":"v1","password_hash":"invalid"}`},
	} {
		var gate basicAuthGate
		if err := gate.load(store); err == nil {
			t.Fatal("invalid persisted config did not fail closed")
		}
	}
}

func TestBasicAuthExpiredCookieAndSecureFlag(t *testing.T) {
	s, _ := basicAuthTestServer(t)
	w := saveBasicAuthForTest(s, `{"enabled":true,"username":"entry","password":"test-pass"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cfg := s.basicAuth.snapshot()
	for _, expires := range []*jwt.NumericDate{nil, jwt.NewNumericDate(time.Now().Add(-time.Minute))} {
		token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject: cfg.Revision, Audience: jwt.ClaimStrings{basicAuthAudience}, ExpiresAt: expires,
		}).SignedString(s.basicAuthSigningKey())
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: basicAuthCookie, Value: token})
		if s.validBasicAuthCookie(r, cfg) {
			t.Fatal("expired or unbounded cookie accepted")
		}
	}
	r := httptest.NewRequest("GET", "https://example.test/login", nil)
	w = httptest.NewRecorder()
	if err := s.setBasicAuthCookie(w, r, cfg); err != nil {
		t.Fatal(err)
	}
	if !w.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS cookie is not Secure")
	}
	var public map[string]any
	w = httptest.NewRecorder()
	s.getBasicAuthSettings(w, r)
	if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if len(public) != 3 || public["password_set"] != true {
		t.Fatalf("bad public settings: %v", public)
	}
}

// An expired gate must be recoverable without discarding the independent admin
// session. API failures must never open native Basic dialogs themselves.
func TestBasicAuthExpiredSessionRecovery(t *testing.T) {
	s, _ := basicAuthTestServer(t)
	w := saveBasicAuthForTest(s, `{"enabled":true,"username":"entry","password":"entry-password"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cfg := s.basicAuth.snapshot()
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: cfg.Revision, Audience: jwt.ClaimStrings{basicAuthAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).SignedString(s.basicAuthSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	adminJWT, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	h := minimalAuthRoot(s)
	for _, path := range []string{"/api/version", "/api/settings/basic-auth"} {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", "Bearer "+adminJWT)
			r.AddCookie(&http.Cookie{Name: basicAuthCookie, Value: expired})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 || w.Header().Get("X-Zreco-Auth") != "basic" || w.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("API must signal recovery without a browser challenge: %d %v", w.Code, w.Header())
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal("gate failure must not cache or change the admin session")
			}
		})
	}
	// Reloading the current document can use Basic authorization, while the
	// admin JWT stays in its cookie for subsequent API requests.
	r := httptest.NewRequest("GET", "/function/tasks/", nil)
	r.AddCookie(&http.Cookie{Name: "4zreco_token", Value: adminJWT})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("document navigation must still prompt for Basic authentication")
	}
	r = httptest.NewRequest("GET", "/api/basic-auth/check", nil)
	r.SetBasicAuth("entry", "entry-password")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || len(w.Result().Cookies()) != 1 {
		t.Fatalf("reauthentication failed: %d %s", w.Code, w.Body.String())
	}
	renewed := w.Result().Cookies()[0]
	r = httptest.NewRequest("GET", "/api/version", nil)
	r.AddCookie(renewed)
	r.Header.Set("Authorization", "Bearer "+adminJWT)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("original admin session did not recover: %d %s", w.Code, w.Body.String())
	}
}

// TestBasicAuthPostgresLoginFlowPG 走真 PG：保存配置→重启加载→登录流过门。
// 无 DSN 时 skip（与 core_test.go 同款门控）。
func TestBasicAuthPostgresLoginFlowPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	for _, key := range []string{basicAuthKey, authPassKey} {
		old, exists, err := m.pg.GetSetting(key)
		if err != nil {
			t.Fatal(err)
		}
		defer func(key, old string, exists bool) {
			if exists {
				_ = m.pg.SetSetting(key, old)
			} else {
				_, _ = m.pg.Exec("DELETE FROM settings WHERE key=$1", key)
			}
		}(key, old, exists)
	}
	if err := m.pg.SetSetting(basicAuthKey, `{"enabled":false}`); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	// 两个 Server 的后台 worker（task-archive 轮询从共享库领归档任务、往 m.dir/tasks
	// 写 staging 文件）生命周期由 ctx 驱动。若测试结束不取消，worker 与 t.TempDir 的
	// RemoveAll 赛跑，偶发 "TempDir RemoveAll cleanup: directory not empty" 假失败。
	// 先取消 ctx 并等 worker 退出，再放行 TempDir 清理（defer LIFO：本函数先于
	// 上方 settings 恢复与 m.Close 执行，且都在 t.Cleanup 的 TempDir 清理之前）。
	var s, restarted *Server
	ctx, cancelServers := context.WithCancel(context.Background())
	defer func() {
		cancelServers()
		s.archiveWG.Wait()
		if restarted != nil {
			restarted.archiveWG.Wait()
		}
	}()
	s = New(ctx, m, config.Paths{Skills: td, Data: td, Base: td})
	adminJWT, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	body := `{"enabled":true,"username":"entry","password":"entry-password"}`
	r := httptest.NewRequest("PUT", "/api/settings/basic-auth", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || s.basicAuth.snapshot().Enabled {
		t.Fatal("unauthenticated settings write succeeded")
	}
	r = httptest.NewRequest("PUT", "/api/settings/basic-auth", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+adminJWT)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}

	// 模拟重启：新 Server 从同一 PG 加载门配置（同一 ctx，测试结束时一并取消）。
	restarted = New(ctx, m, config.Paths{Skills: t.TempDir(), Data: t.TempDir(), Base: t.TempDir()})
	rh := restarted.Handler()
	loginBody := `{"username":"4ZRECO","password":"admin-password"}`
	r = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(loginBody))
	w = httptest.NewRecorder()
	rh.ServeHTTP(w, r)
	if w.Code != 401 || w.Header().Get("X-Zreco-Auth") != "basic" || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("login must fail with a recoverable gate error after restart")
	}
	r = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(loginBody))
	r.SetBasicAuth("entry", "entry-password")
	w = httptest.NewRecorder()
	rh.ServeHTTP(w, r)
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil || w.Code != 200 {
		t.Fatalf("Basic Auth + existing login failed: %d %s", w.Code, w.Body.String())
	}
	if _, ok := verifyJWT(login.Token, restarted.currentJWTKey()); !ok {
		t.Fatal("login token did not verify")
	}
	cookie := w.Result().Cookies()[0]
	r = httptest.NewRequest("PUT", "/api/settings/basic-auth", strings.NewReader(`{"enabled":false}`))
	r.AddCookie(cookie)
	r.Header.Set("Authorization", "Bearer "+login.Token)
	w = httptest.NewRecorder()
	rh.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("disable with gate cookie and JWT: %d %s", w.Code, w.Body.String())
	}
}
