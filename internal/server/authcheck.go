package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// totpCode 按 RFC 6238 生成当前时间窗的 6 位动态码（HMAC-SHA1，30s）。
// 只需支持标准登录场景：Base32 密钥（忽略空格与大小写）。
func totpCode(secret string, at time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("TOTP 密钥不是合法的 Base32：%w", err)
	}
	counter := uint64(at.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// authCheckResult 是登录自检的结果（不回显任何凭据）。
type authCheckResult struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code,omitempty"`
	Matched    bool   `json:"matched"` // 命中成功判定条件
	Detail     string `json:"detail"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	UsedTOTP   bool   `json:"used_totp,omitempty"`
	CheckedAt  string `json:"checked_at"`
}

// runAuthCheck 用任务配置的登录凭据发一次真实登录请求并判定是否成功。
// 判定规则与 worker prompt 里给的一致：SuccessStatus（0=不校验）与
// SuccessContains 都满足才算成功；都没配时以 2xx/3xx 作为成功。
// 返回详情时不带密码/TOTP/响应正文（只给状态码与命中说明）。
func runAuthCheck(cfg *db.TaskAuthConfig) authCheckResult {
	res := authCheckResult{CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	start := time.Now()
	if cfg == nil || !cfg.Enabled {
		res.Detail = "未配置登录凭据"
		return res
	}
	fields := map[string]string{
		cfg.UsernameField: cfg.Username,
		cfg.PasswordField: cfg.Password,
	}
	for k, v := range cfg.ExtraFields {
		fields[k] = v
	}
	if cfg.HasTOTP {
		code, err := totpCode(cfg.TOTPSecret, time.Now())
		if err != nil {
			res.Detail = err.Error()
			return res
		}
		res.UsedTOTP = true
		// 动态码字段名未单独配置时按常见命名填 totp/code/otp。
		names := []string{"totp", "otp", "code"}
		placed := false
		for _, n := range names {
			if _, exists := fields[n]; !exists {
				fields[n] = code
				placed = true
				break
			}
		}
		_ = placed
	}

	var req *http.Request
	var err error
	if cfg.Method == "GET" {
		q := url.Values{}
		for k, v := range fields {
			q.Set(k, v)
		}
		u := cfg.LoginURL
		if strings.Contains(u, "?") {
			u += "&" + q.Encode()
		} else {
			u += "?" + q.Encode()
		}
		req, err = http.NewRequest(http.MethodGet, u, nil)
	} else if cfg.ContentType == "form" {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		req, err = http.NewRequest(http.MethodPost, cfg.LoginURL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		body, _ := json.Marshal(fields)
		req, err = http.NewRequest(http.MethodPost, cfg.LoginURL, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		res.Detail = "构造登录请求失败：" + err.Error()
		return res
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Detail = "登录请求失败：" + err.Error()
		return res
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))

	statusOK := cfg.SuccessStatus == 0 || resp.StatusCode == cfg.SuccessStatus
	if cfg.SuccessStatus == 0 {
		statusOK = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	containsOK := cfg.SuccessContains == "" || strings.Contains(string(body), cfg.SuccessContains)
	res.Matched = statusOK && containsOK
	res.OK = res.Matched
	switch {
	case res.OK && cfg.SuccessStatus > 0:
		res.Detail = fmt.Sprintf("登录成功（HTTP %d，命中成功状态码）", resp.StatusCode)
	case res.OK && cfg.SuccessContains != "":
		res.Detail = fmt.Sprintf("登录成功（HTTP %d，响应包含判定串）", resp.StatusCode)
	case res.OK:
		res.Detail = fmt.Sprintf("登录成功（HTTP %d）", resp.StatusCode)
	default:
		parts := []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
		if cfg.SuccessStatus > 0 && resp.StatusCode != cfg.SuccessStatus {
			parts = append(parts, fmt.Sprintf("与期望状态码 %d 不符", cfg.SuccessStatus))
		}
		if cfg.SuccessContains != "" && !containsOK {
			parts = append(parts, "响应未包含判定串 "+strconv.Quote(cfg.SuccessContains))
		}
		res.Detail = "登录未通过：" + strings.Join(parts, "，")
	}
	return res
}

// taskAuthCheck 对任务配置的登录凭据做一次真实登录自检。
// POST /api/tasks/{id}/auth-check
func (s *Server) taskAuthCheck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || s.m.PG() == nil {
		writeErr(w, 400, "invalid task id")
		return
	}
	t, err := s.m.PG().GetTask(id)
	if err != nil || t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if t.AuthConfig == nil || !t.AuthConfig.Enabled {
		writeErr(w, 400, "该任务未配置登录凭据")
		return
	}
	writeJSON(w, 200, runAuthCheck(t.AuthConfig))
}
