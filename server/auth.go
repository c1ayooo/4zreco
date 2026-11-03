package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// currentJWTKey 原子读取当前签名 key（改密码轮换后立即变化）。
func (s *Server) currentJWTKey() []byte {
	if v, ok := s.jwtKey.Load().([]byte); ok {
		return v
	}
	return nil
}

// rotateJWTKey 生成新 key 原子替换并落盘：**所有已签发 token 立即失效**。
// 改密码必须轮换——否则公网上泄露的旧 token 能一直用到 7 天自然过期，
// 「改密码踢掉攻击者」就成了一句空话。
func (s *Server) rotateJWTKey() error {
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(filepath.Join(s.keyDir, jwtKeyFilename), buf, 0o600); err != nil {
		return fmt.Errorf("write jwt key: %w", err)
	}
	s.jwtKey.Store(buf)
	log.Printf("[auth] JWT key 已轮换（改密码），全部旧会话失效")
	return nil
}

// clientIP 提取客户端 IP：反代部署下取 X-Forwarded-For 首段（部署手册要求
// 反代覆写该头），直连时取 RemoteAddr。XFF 可伪造，所以限流器另有全局限
// 作为兜底——伪造无限个 IP 也撞不穿全局阈值。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLimiter 是登录/初始化接口的进程级防爆破闸门：
//   - 每 IP：10 分钟窗口内失败 5 次 → 锁 15 分钟；
//   - 全局：1 分钟窗口内失败 30 次 → 全局锁 5 分钟（兜 XFF 伪造与分布式低速）。
//
// 内存态即可：重启清零只影响攻击者的等待时间，不影响正确性。
// 返回 (允许, 剩余锁定时长)。
type loginLimiter struct {
	mu          sync.Mutex
	fails       map[string][]time.Time // ip → 失败时间序列（滑动窗口）
	lockedUntil map[string]time.Time   // ip → 锁定截止
	globalFails []time.Time
	globalUntil time.Time
}

var loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}

const (
	loginMaxFailsPerIP   = 5
	loginFailWindow      = 10 * time.Minute
	loginLockoutPerIP    = 15 * time.Minute
	loginGlobalMaxFails  = 30
	loginGlobalWindow    = time.Minute
	loginGlobalLockout   = 5 * time.Minute
	loginFailureMinDelay = 300 * time.Millisecond // 失败响应的人为下限，抹平时序差
)

func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if until, ok := l.lockedUntil[ip]; ok && now.Before(until) {
		return false, until.Sub(now)
	}
	if now.Before(l.globalUntil) {
		return false, l.globalUntil.Sub(now)
	}
	// 惰性清理过期窗口，防 map 随扫描流量无限增长。
	for k, until := range l.lockedUntil {
		if now.After(until) && len(l.fails[k]) == 0 {
			delete(l.lockedUntil, k)
		}
	}
	return true, 0
}

func (l *loginLimiter) recordFail(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// per-IP 滑动窗口。
	f := append(l.fails[ip], now)
	cut := now.Add(-loginFailWindow)
	i := 0
	for i < len(f) && f[i].Before(cut) {
		i++
	}
	f = f[i:]
	l.fails[ip] = f
	if len(f) >= loginMaxFailsPerIP {
		l.lockedUntil[ip] = now.Add(loginLockoutPerIP)
		l.fails[ip] = nil
	}
	// 全局滑动窗口。
	l.globalFails = append(l.globalFails, now)
	gcut := now.Add(-loginGlobalWindow)
	j := 0
	for j < len(l.globalFails) && l.globalFails[j].Before(gcut) {
		j++
	}
	l.globalFails = l.globalFails[j:]
	if len(l.globalFails) >= loginGlobalMaxFails {
		l.globalUntil = now.Add(loginGlobalLockout)
		l.globalFails = nil
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
	delete(l.lockedUntil, ip)
}

// loginGuard 统一包住 login/init 的防爆破语义：超限直接 429，失败记一笔并
// 人为拖慢响应。返回 false 表示已写响应、调用方直接 return。
func loginGuard(w http.ResponseWriter, r *http.Request, action string) bool {
	ip := clientIP(r)
	if ok, wait := loginLimit.allow(ip); !ok {
		log.Printf("[auth] %s 限流触发 ip=%s 剩余=%s", action, ip, wait.Truncate(time.Second))
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return false
	}
	if action == "login-fail" {
		loginLimit.recordFail(ip)
		log.Printf("[auth] 登录失败 ip=%s", ip)
		time.Sleep(loginFailureMinDelay)
	}
	return true
}

// signJWT issues a 7-day HS256 token for user 4ZRECO.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "4ZRECO",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return err == nil && t.Valid
}

// sseQueryTokenPaths 是唯一接受 ?token= 查询参数的端点白名单：浏览器 EventSource
// 无法带 Authorization 头,这些 URL 直连的 SSE 流端点历史上靠 query token 认证。
// 其余任何路径不再从 query 取 token（N1 收敛）——token 会进访问日志/X-Forwarded 头/
// Referer,能走 cookie（前端已配好）的路径不该把这个风险留着。EventSource 同源默认带
// cookie,query 只是 cookie 不可用时的后备。side-questions 的 events 端点带请求 id,
// 由 queryTokenAllowed 里的前缀+后缀判断覆盖。
var sseQueryTokenPaths = map[string]bool{
	"/api/exploration/activity/stream": true,
	"/api/logs/stream":                 true,
	"/api/update/stream":               true,
}

// queryTokenAllowed reports whether ?token= may be trusted for this request:
// only the four URL-direct SSE stream endpoints (see sseQueryTokenPaths).
func queryTokenAllowed(r *http.Request) bool {
	if sseQueryTokenPaths[r.URL.Path] {
		return true
	}
	// side-questions events 按请求 id 动态:/api/side-questions/<id>/events
	return strings.HasPrefix(r.URL.Path, "/api/side-questions/") && strings.HasSuffix(r.URL.Path, "/events")
}

// extractToken reads the JWT from Authorization: Bearer header, or the
// 4zreco_token cookie. ?token= query is only honored on the SSE stream endpoints
// (queryTokenAllowed) — elsewhere the token would leak into access logs and
// Referer headers without giving up anything the cookie doesn't already do.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("4zreco_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if queryTokenAllowed(r) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		if !verifyJWT(tok, s.currentJWTKey()) {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "init") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.currentJWTKey()) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	// 轮换签名 key：旧密码可能已经泄露（改密码本身往往就是怀疑泄露的动作），
	// 不轮换的话用旧 token 的会话全部存活到自然过期。
	if err := s.rotateJWTKey(); err != nil {
		// 密码已改成功、轮换失败：不回滚（密码改了比没改安全），但要显式告警。
		log.Printf("[auth] 改密码后 JWT key 轮换失败: %v（旧 token 仍然有效，请重启服务强制轮换）", err)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "login") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Username != "4ZRECO" && req.Username != "ARTEX" { // v0.4.19 改名：兼容旧用户名
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		loginGuard(w, r, "login-fail")
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	loginLimit.recordSuccess(clientIP(r))
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
