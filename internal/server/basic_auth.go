package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// 可选 HTTP Basic Auth 访问门（移植自 ARTEX 0.3.29 A4）。与 requireAuth（JWT）分层：
// 门在外层先挑战，JWT 在内层做管理身份。配置存 settings 键 auth.http_basic
// （{enabled, username, password_hash(bcrypt), revision}），每次保存轮换 revision
// 使旧门 cookie 全部失效。判定逻辑纯 Go，不感知 eino。
const (
	basicAuthKey         = "auth.http_basic"
	basicAuthCookie      = "4zreco_basic_auth"
	basicAuthAudience    = "4zreco-basic-auth"
	basicAuthTTL         = 12 * time.Hour
	basicAuthSaveTimeout = 10 * time.Second
)

type basicAuthConfig struct {
	Enabled      bool   `json:"enabled"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Revision     string `json:"revision"`
}

type basicAuthSettingsStore interface {
	GetSetting(string) (string, bool, error)
	SetSettingContext(context.Context, string, string) error
}

// Keep one atomic configuration in the DB and publish it only after a successful
// save. Requests use the in-memory snapshot, avoiding a DB read for every request.
type basicAuthGate struct {
	saveMu sync.Mutex // serializes persistence without blocking request snapshots
	mu     sync.RWMutex
	cfg    basicAuthConfig
	store  basicAuthSettingsStore
}

func (g *basicAuthGate) load(store basicAuthSettingsStore) error {
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	raw, ok, err := store.GetSetting(basicAuthKey)
	if err != nil {
		return err
	}
	var cfg basicAuthConfig
	if ok {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return fmt.Errorf("invalid HTTP Basic Auth configuration")
		}
	}
	if cfg.Enabled {
		if !validBasicUsername(cfg.Username) || cfg.Revision == "" {
			return fmt.Errorf("incomplete HTTP Basic Auth configuration")
		}
		if _, err := bcrypt.Cost([]byte(cfg.PasswordHash)); err != nil {
			return fmt.Errorf("invalid HTTP Basic Auth password hash")
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg, g.store = cfg, store
	return nil
}

func (g *basicAuthGate) snapshot() basicAuthConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cfg
}

func validBasicUsername(username string) bool {
	return strings.TrimSpace(username) != "" && len(username) <= 128 &&
		!strings.Contains(username, ":") && strings.IndexFunc(username, unicode.IsControl) == -1
}

// basicAuthSigningKey 从 JWT 签名 key（s.currentJWTKey，改密码即轮换）HMAC 派生。
// 独立派生保证门 cookie 永远不能当管理员 JWT 用（audience 也不同）。
func (s *Server) basicAuthSigningKey() []byte {
	m := hmac.New(sha256.New, s.currentJWTKey())
	m.Write([]byte("4zreco/http-basic-auth/session/v1"))
	return m.Sum(nil)
}

func (s *Server) validBasicAuthCookie(r *http.Request, cfg basicAuthConfig) bool {
	cookie, err := r.Cookie(basicAuthCookie)
	if err != nil || cfg.Revision == "" {
		return false
	}
	claims := &jwt.RegisteredClaims{}
	_, err = jwt.ParseWithClaims(cookie.Value, claims, func(*jwt.Token) (any, error) {
		return s.basicAuthSigningKey(), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithAudience(basicAuthAudience), jwt.WithSubject(cfg.Revision))
	return err == nil
}

func (s *Server) setBasicAuthCookie(w http.ResponseWriter, r *http.Request, cfg basicAuthConfig) error {
	cookie := &http.Cookie{
		Name: basicAuthCookie, Path: "/", HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	}
	if cfg.Enabled {
		now := time.Now()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject: cfg.Revision, Audience: jwt.ClaimStrings{basicAuthAudience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(basicAuthTTL)),
		}).SignedString(s.basicAuthSigningKey())
		if err != nil {
			return err
		}
		cookie.Value, cookie.MaxAge = token, int(basicAuthTTL.Seconds())
	}
	http.SetCookie(w, cookie)
	return nil
}

// requireBasicAuth 是最外层访问门：未启用直接放行；启用后合法凭据（门 cookie 或
// Basic 用户名/密码）放行。豁免 /api/health（无信息探活端点，供监控探测）与
// CORS 预检——预检不携带凭据，业务 handler 一律不会为它执行。
// /api/basic-auth/check 不豁免：它就是凭据换门 cookie 的入口——无凭据时被门
// 挑战（回 WWW-Authenticate），带 Basic 凭据时发 cookie 后放行。
// 其余 API 路径失败时回 X-Zreco-Auth: basic 而不带 WWW-Authenticate：后台请求
// 走 Bearer 认证，用 Basic 挑战它们会把浏览器陷进原生弹窗循环；由前端刷新当前
// 页一次来只续外层会话。
func (s *Server) requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.basicAuth.snapshot()
		if !cfg.Enabled || (r.Method == "OPTIONS" && strings.HasPrefix(r.URL.Path, "/api/")) ||
			r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if s.validBasicAuthCookie(r, cfg) {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || len(password) > maxPasswordBytes || username != cfg.Username ||
			bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)) != nil {
			w.Header().Set("X-Zreco-Auth", "basic")
			// 页面路径与 /api/basic-auth/check 回 WWW-Authenticate：前者是浏览器
			// 原生弹窗的入口（门启用时静态前端壳也被门拦），后者是凭据换 cookie
			// 的入口；其余 API 路径只回 X-Zreco-Auth 标记，由前端接管。
			if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/basic-auth/check" {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted", charset="UTF-8"`)
			}
			writeErr(w, http.StatusUnauthorized, "请先完成 HTTP Basic Auth 验证")
			return
		}
		// Browser API requests already use Authorization: Bearer. A separate
		// HttpOnly cookie keeps the gate satisfied without replacing that header.
		if err := s.setBasicAuthCookie(w, r, cfg); err != nil {
			writeErr(w, 500, "认证会话生成失败")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func basicAuthPublicSettings(cfg basicAuthConfig) map[string]any {
	return map[string]any{"enabled": cfg.Enabled, "username": cfg.Username, "password_set": cfg.PasswordHash != ""}
}

// GET /api/settings/basic-auth — 公开视图（不含 password_hash）。
func (s *Server) getBasicAuthSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, basicAuthPublicSettings(s.basicAuth.snapshot()))
}

// PUT /api/settings/basic-auth — 保存门配置。每次保存轮换 revision：旧门 cookie
// 全部失效，包括停用/重新启用；刚保存的管理员拿新 cookie 保持会话。
func (s *Server) saveBasicAuthSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  *bool   `json:"enabled"`
		Username *string `json:"username"`
		Password string  `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	g := &s.basicAuth
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	g.mu.RLock()
	cfg, store := g.cfg, g.store
	g.mu.RUnlock()
	if store == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Username != nil {
		cfg.Username = strings.TrimSpace(*req.Username)
	}
	if (cfg.Enabled || cfg.Username != "") && !validBasicUsername(cfg.Username) {
		writeErr(w, 400, "Basic Auth 用户名不能为空、超过 128 字节或包含冒号及控制字符")
		return
	}
	if req.Password != "" {
		if msg := validatePassword(req.Password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "密码加密失败")
			return
		}
		cfg.PasswordHash = string(hash)
	}
	if cfg.Enabled && cfg.PasswordHash == "" {
		writeErr(w, 400, "请先设置 Basic Auth 密码")
		return
	}
	cfg.Revision = uuid.NewString()
	data, err := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(r.Context(), basicAuthSaveTimeout)
	defer cancel()
	if err != nil || store.SetSettingContext(ctx, basicAuthKey, string(data)) != nil {
		writeErr(w, 503, "Basic Auth 配置保存失败，请重试")
		return
	}
	// Hashing, persistence and response output never hold the request mutex.
	// Publish only committed settings; requests keep using the previous snapshot
	// until this short critical section completes.
	g.mu.Lock()
	g.cfg = cfg
	g.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	// Keep the administrator who just saved the settings in their session.
	if err := s.setBasicAuthCookie(w, r, cfg); err != nil {
		writeErr(w, 500, "认证会话生成失败")
		return
	}
	writeJSON(w, 200, basicAuthPublicSettings(cfg))
}
