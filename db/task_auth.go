package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// TaskAuthConfig 是任务的「目标登录凭据」配置（v0.4.8，借鉴 Shannon 的
// authentication 模型）：worker 拿到它先登录、再在会话内测试；创建后可
// 触发一次登录自检，凭据不可用时在开扫前就知道，而不是让 worker 盲探。
//
// 安全边界：Password / TOTPSecret 标记 json:"-"——任何 API 响应都不会回传
// 秘密；DB 存取走 DBValue（显式带秘密）。HasPassword/HasTOTP 是只读派生标记，
// 让前端知道"配过密码"而不暴露内容。
type TaskAuthConfig struct {
	Enabled         bool              `json:"enabled"`
	LoginURL        string            `json:"login_url"`
	Method          string            `json:"method"`       // POST|GET
	ContentType     string            `json:"content_type"` // json|form
	UsernameField   string            `json:"username_field,omitempty"`
	PasswordField   string            `json:"password_field,omitempty"`
	Username        string            `json:"username,omitempty"`
	Password        string            `json:"-"`
	HasPassword     bool              `json:"has_password,omitempty"`
	TOTPSecret      string            `json:"-"`
	HasTOTP         bool              `json:"has_totp,omitempty"`
	ExtraFields     map[string]string `json:"extra_fields,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	SuccessStatus   int               `json:"success_status,omitempty"`   // 0=不校验状态码
	SuccessContains string            `json:"success_contains,omitempty"` // 响应体包含即视为成功
}

// authWire 是 DB 存储形态：TaskAuthConfig 的 json:"-" 面向 API，DB 必须显式
// 带上 password / totp_secret 两个秘密字段。
type authWire struct {
	TaskAuthConfig
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

// DBValue 序列化含秘密字段的 JSON（写 tasks.auth_config）。
func (a *TaskAuthConfig) DBValue() ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(authWire{TaskAuthConfig: *a, Password: a.Password, TOTPSecret: a.TOTPSecret})
}

// ParseTaskAuth 解析 DB 里的 auth_config；空/nil 返回 nil。解析成功时派生
// HasPassword/HasTOTP 供前端展示。
func ParseTaskAuth(raw []byte) *TaskAuthConfig {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil
	}
	var w authWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil
	}
	a := w.TaskAuthConfig
	a.Password = w.Password
	a.TOTPSecret = w.TOTPSecret
	a.HasPassword = a.Password != ""
	a.HasTOTP = a.TOTPSecret != ""
	return &a
}

// Normalize 校验并补默认值。只校验启用中的配置：关闭的配置保留原样（便于
// 用户先存草稿再启用）。
func (a *TaskAuthConfig) Normalize() error {
	if a == nil || !a.Enabled {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(a.LoginURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("登录地址必须是完整的 http/https URL")
	}
	a.LoginURL = strings.TrimSpace(a.LoginURL)
	a.Method = strings.ToUpper(strings.TrimSpace(a.Method))
	if a.Method == "" {
		a.Method = "POST"
	}
	if a.Method != "POST" && a.Method != "GET" {
		return fmt.Errorf("登录方法只支持 POST / GET")
	}
	a.ContentType = strings.ToLower(strings.TrimSpace(a.ContentType))
	if a.ContentType == "" {
		a.ContentType = "json"
	}
	if a.ContentType != "json" && a.ContentType != "form" {
		return fmt.Errorf("登录请求体只支持 json / form")
	}
	if strings.TrimSpace(a.UsernameField) == "" {
		a.UsernameField = "username"
	}
	if strings.TrimSpace(a.PasswordField) == "" {
		a.PasswordField = "password"
	}
	if strings.TrimSpace(a.Username) == "" || a.Password == "" {
		return fmt.Errorf("启用登录配置时用户名与密码都必须填写")
	}
	if a.SuccessStatus != 0 && (a.SuccessStatus < 100 || a.SuccessStatus > 599) {
		return fmt.Errorf("成功状态码需在 100–599 之间（0 表示不校验）")
	}
	a.HasPassword = a.Password != ""
	a.HasTOTP = strings.TrimSpace(a.TOTPSecret) != ""
	return nil
}

// PromptBlock 渲染成注入 worker system prompt 的文本块。中性描述、不打印
// 密码明文——凭据以「字段清单 + 值」形式给出，worker 直接用它登录。
func (a *TaskAuthConfig) PromptBlock() string {
	if a == nil || !a.Enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n━━ 目标登录凭据（任务级配置）━━\n")
	b.WriteString("目标站点已配置登录凭据，测试前先用它登录并在会话内保持认证状态；不要在报告里写出密码或 TOTP 密钥。\n")
	b.WriteString("登录地址：" + a.LoginURL + "\n")
	b.WriteString("请求方法：" + a.Method + "，请求体格式：" + a.ContentType + "\n")
	b.WriteString("用户名字段：" + a.UsernameField + " = " + a.Username + "\n")
	b.WriteString("密码字段：" + a.PasswordField + " = " + a.Password + "\n")
	if a.HasTOTP {
		b.WriteString("TOTP 密钥（Base32）：" + a.TOTPSecret + "（按当前时间生成 6 位动态码填入动态码字段）\n")
	}
	if len(a.ExtraFields) > 0 {
		keys := make([]string, 0, len(a.ExtraFields))
		for k := range a.ExtraFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("附加表单字段：")
		for i, k := range keys {
			if i > 0 {
				b.WriteString("，")
			}
			b.WriteString(k + "=" + a.ExtraFields[k])
		}
		b.WriteString("\n")
	}
	if len(a.Headers) > 0 {
		b.WriteString("附加请求头：")
		first := true
		for k, v := range a.Headers {
			if !first {
				b.WriteString("，")
			}
			first = false
			b.WriteString(k + ": " + v)
		}
		b.WriteString("\n")
	}
	if a.SuccessStatus > 0 {
		b.WriteString(fmt.Sprintf("成功判定：响应状态码 %d", a.SuccessStatus))
		if a.SuccessContains != "" {
			b.WriteString(fmt.Sprintf("，且响应体包含 %q", a.SuccessContains))
		}
		b.WriteString("\n")
	} else if a.SuccessContains != "" {
		b.WriteString(fmt.Sprintf("成功判定：响应体包含 %q\n", a.SuccessContains))
	}
	b.WriteString("登录成功后从响应头/响应体提取会话凭证（Set-Cookie/token），后续请求携带它。登录失败时如实记录失败原因，不要猜测其他凭据。")
	return b.String()
}
