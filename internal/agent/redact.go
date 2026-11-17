package agent

// 观测面凭据打码（F3 凭据纪律，2026-11-13 体检修复）。工具输入 JSON 经 capture
// 全文落 trace/activity；键名落在敏感清单下的字符串值在观测面替换为 ******，
// 执行面（execOne → guard 链 → 工具本体）拿到的仍是原文。打码纪律参照
// tools_zombie_proton.go 的输出打码先例（凭据明文只进 evidence，不进 trace）。
//
// 键名打码覆盖不到「凭据藏在值里」的携带形态——auth_request 的 curl 命令
// （-H 'Authorization: Bearer …' / -u 'user:pass' / -H 'Cookie: …'）、后续 Bash
// 调用 input 的 command 键、工具输出原文——这些走值形态打码（maskCredentialText）：
// 认头值、curl 单引号参数、URL userinfo、内嵌 JSON 敏感键、表单字段。两层都只动
// 观测面，模型所见（DTO master / 工具返回值）不受影响。

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// credentialInputKeys 是敏感键清单：精确匹配、大小写不敏感（api_key/apikey
// 并列覆盖 snake 与连写命名）。只匹配字符串值；非字符串值原样保留。
var credentialInputKeys = map[string]bool{
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"api_key":       true,
	"apikey":        true,
	"access_token":  true,
	"refresh_token": true,
	"authorization": true,
	"credential":    true,
}

// maskedValue 是打码后的占位值（与 zombie/proton 输出打码同一形态）。
const maskedValue = "******"

// maxMaskDepth 是键值打码的最大递归深度（根算第 1 层）；更深的结构不再下钻。
const maxMaskDepth = 4

// maskSensitiveInput 把输入 JSON 中敏感键下的字符串值替换为 ******，并对全部
// 字符串叶子做值形态打码（见 maskCredentialText）。只在有命中时重编码（无命中
// 原样返回，观测文本与模型所发逐字节一致）；非 JSON 原样返回。重编码经
// json.Number 保数字字面量、关 HTML 转义，非敏感字段的内容不变（对象键序按
// Go map 序重排——展示用文本，可接受）。
func maskSensitiveInput(in string) string {
	if !strings.ContainsAny(in, "{[") {
		return in // 快路径：纯命令/URL 不含 JSON 结构，无需解析
	}
	var value any
	d := json.NewDecoder(bytes.NewReader([]byte(in)))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return in
	}
	if !maskSensitiveValue(value, 1) {
		return in
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return in
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// maskSensitiveValue 就地打码一个已解码 JSON 值，返回是否命中。depth 1 = 根；
// 超过 maxMaskDepth 的层不再处理。map/slice 是引用语义，嵌套改动就地生效。
func maskSensitiveValue(v any, depth int) bool {
	if depth > maxMaskDepth {
		return false
	}
	hit := false
	switch t := v.(type) {
	case map[string]any:
		for k, elem := range t {
			if s, ok := elem.(string); ok {
				if credentialInputKeys[strings.ToLower(k)] {
					t[k] = maskedValue
					hit = true
					continue
				}
				// 键名不在清单内的字符串叶子也做值形态打码——凭据可能藏在
				// command/header/body 等任意键的值里（auth_request → Bash 的
				// curl 命令正是这条路径）。
				if masked := maskCredentialText(s); masked != s {
					t[k] = masked
					hit = true
				}
				continue
			}
			if maskSensitiveValue(elem, depth+1) {
				hit = true
			}
		}
	case []any:
		for _, elem := range t {
			if maskSensitiveValue(elem, depth+1) {
				hit = true
			}
		}
	}
	return hit
}

// ---- 值形态打码 ----
//
// 键名打码的前置：凭据不以敏感键出现、而是以「可执行的携带形态」藏在字符串值
// 或工具输出原文里。这里认的是形状不是键名，只动观测面文本。

var (
	// curl 单引号参数（buildAuthCurl 的 q() 转义形态：内容含 ' 写作 '\''）。
	// RE2 线性匹配，无回溯风险。
	reCurlU = regexp.MustCompile(`(?:-u|--user)\s+'((?:[^']|'\\'')*)'`)
	reCurlH = regexp.MustCompile(`(?:-H|--header)\s+'((?:[^']|'\\'')*)'`)
	// 自由文本里的认证头值行（响应头不会带 Authorization，误伤面是「引用了
	// 请求头」的内容——按纪律本就该打码）。
	reAuthzLine = regexp.MustCompile(`(?i)((?:proxy-)?authorization\s*:\s*(?:bearer|basic|token|digest|ntlm|negotiate)?\s*)[^\s'",;{}]{4,}`)
	// URL userinfo（http://user:pass@host — 凭据形态的 URL）。
	reURLUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s:@/]+:[^\s@/]+@`)
	// 内嵌 JSON 的敏感键（--data-raw '{"password":"…"}' 嵌在命令字符串里时，
	// 结构化键名打码够不着——对文本层再认一遍同样的键）。
	reJSONKeyInline = regexp.MustCompile(`(?i)("(?:access_token|refresh_token|api_key|apikey|password|passwd|secret|credential|authorization|token)"\s*:\s*")[^"]*(")`)
	// 表单/查询串字段（password=hunter2、?token=…）。
	reFormField = regexp.MustCompile(`(?i)((?:access_token|refresh_token|api_key|apikey|password|passwd|secret|credential|token)=)[^&\s'"]{2,}`)
)

// curlAuthHeaders 是 -H 参数里按凭据处置的头名（请求方向的认证头）。Set-Cookie
// 等响应头不在列——扫描输出里的响应头是观测内容，不是本进程发出的凭据。
var curlAuthHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"x-api-key":           true,
}

// maskCredentialText 对任意观测文本做值形态打码，无命中逐字节原样返回。
// 只替换凭据形态的子串，其余内容（含页面上恰好出现的同名键）不动。
func maskCredentialText(s string) string {
	out := s
	if strings.Contains(out, "curl") {
		out = reCurlU.ReplaceAllStringFunc(out, maskCurlQuotedArg)
		out = reCurlH.ReplaceAllStringFunc(out, maskCurlHeaderArg)
	}
	if strings.Contains(out, "uthorization") { // Authorization / authorization / PROXY-AUTHORIZATION
		out = reAuthzLine.ReplaceAllString(out, "${1}******")
	}
	if strings.Contains(out, "://") {
		out = reURLUserinfo.ReplaceAllString(out, "${1}******@")
	}
	if strings.Contains(out, `"`) {
		out = reJSONKeyInline.ReplaceAllString(out, "${1}******${2}")
	}
	if strings.Contains(out, "=") {
		out = reFormField.ReplaceAllString(out, "${1}******")
	}
	return out
}

// maskCurlQuotedArg 打码 -u/--user 的单引号参数整体（user:pass 就是凭据本体）。
func maskCurlQuotedArg(match string) string {
	i := strings.Index(match, "'")
	if i < 0 {
		return match // 不可达：正则保证有引号
	}
	return match[:i] + "'******'"
}

// maskCurlHeaderArg 只打码 -H/--header 参数中认证头的值部分；普通头
// （Content-Type 等）原样保留。
func maskCurlHeaderArg(match string) string {
	i := strings.Index(match, "'")
	j := strings.LastIndex(match, "'")
	if i < 0 || j <= i {
		return match // 不可达：正则保证成对引号
	}
	content := match[i+1 : j]
	colon := strings.Index(content, ":")
	if colon < 0 || !curlAuthHeaders[strings.ToLower(strings.TrimSpace(content[:colon]))] {
		return match
	}
	return match[:i+1] + content[:colon+1] + " ******" + match[j:]
}
