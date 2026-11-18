package vulnintel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// nuclei JSONL 结果结构化（第三批 J7，结构照抄 Jingwei v1.6.5 `scanner/nuclei.go`，
// 解析与脱敏按本地口径实现）。
//
// 为什么本地需要它：`scan_with_nuclei` 只组命令不执行，Bash 跑完输出的是 nuclei 的
// JSONL 原始行。直接把这堆行贴进对话既费 token 又容易被 Cookie/Authorization 污染
// 观测面，还无法按模板/端点去重——报告与 finding 需要的是"哪些模板在哪个端点命中，
// 严重度分布如何，重复几次"。

// NucleiResult 是一条 nuclei 命中。JSON tag 与 nuclei -json 输出保持一致（上游同名）。
type NucleiResult struct {
	TemplateID string         `json:"template_id"`
	Name       string         `json:"name"`
	Severity   string         `json:"severity"`
	Host       string         `json:"host"`
	MatchedAt  string         `json:"matched_at"`
	Type       string         `json:"type"`
	Timestamp  string         `json:"timestamp"`
	Curl       string         `json:"curl_command,omitempty"`
	Request    string         `json:"request,omitempty"`
	Response   string         `json:"response,omitempty"`
	Extracted  []string       `json:"extracted,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// NucleiParseStats 是解析汇总，供工具直接回给模型。
type NucleiParseStats struct {
	Lines      int            `json:"lines"`      // 非空行总数
	Parsed     int            `json:"parsed"`     // 成功解析的行数
	Skipped    int            `json:"skipped"`    // 坏行数
	SkippedAt  []string       `json:"skipped_at"` // 前 3 条坏行摘要（行号 + 片段）
	Duplicates int            `json:"duplicates"` // 被去重合并的重复命中数
	Severity   map[string]int `json:"severity"`   // 去重后的严重度分布
}

// PacketText 把线上抓到的字节渲染成 PostgreSQL text 列与 DOCX 报告都装得下的文本：
// NUL 丢弃，非法 UTF-8 字节转 \xNN 转义。二进制协议响应（MySQL/Redis/TLS）与 GBK
// 页面正因不可解码才值得留档，所以转义而不是压成 U+FFFD。
//
// 逐字移植自 Jingwei v1.6.5 `scanner/nuclei.go` 的 PacketText。
func PacketText(s string) string {
	if s == "" || utf8.ValidString(s) {
		return strings.ReplaceAll(s, "\x00", "")
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if s[i] == 0 {
				i++
				continue
			}
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// secretHeaderRE 命中 HTTP 报文里承载凭据的头（行首形态与 curl -H 'Cookie: ...'
// 这种夹在命令参数里的形态都要覆盖，故允许任意前缀，只要求头名前是行首/空白/引号）。
var secretHeaderRE = regexp.MustCompile(`(?im)((?:^|[\s'"])(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|token)[ \t]*:[ \t]*)[^\r\n'"]+`)

// RedactSecrets 把报文里的凭据头值整段抹成 ***（保留头名，便于判断"带了认证"）。
// 规则与方案标注一致：导出件抹整段 userinfo/头的值，不回显任何凭据明文。
func RedactSecrets(s string) string {
	if s == "" {
		return ""
	}
	return secretHeaderRE.ReplaceAllString(s, `${1}***`)
}

// sanitizeResult 对一条命中做 UTF-8 安全化 + 凭据脱敏。
func sanitizeResult(r *NucleiResult) {
	r.Name = PacketText(r.Name)
	r.Host = PacketText(r.Host)
	r.MatchedAt = PacketText(r.MatchedAt)
	r.Curl = RedactSecrets(PacketText(r.Curl))
	r.Request = RedactSecrets(PacketText(r.Request))
	r.Response = RedactSecrets(PacketText(r.Response))
	for i := range r.Extracted {
		r.Extracted[i] = PacketText(r.Extracted[i])
	}
	for k, v := range r.Raw {
		if s, ok := v.(string); ok {
			r.Raw[k] = RedactSecrets(PacketText(s))
		}
	}
}

// ParseNucleiJSONL 解析 nuclei 的 JSONL 输出：
//   - 空行忽略；坏行计数并继续（不因一行坏掉丢整批结果）
//   - 按 template_id + matched_at 去重（同模板同端点多次命中合并，保留首条）
//   - 每条做 UTF-8 安全化与 Cookie/Authorization 脱敏
//
// text 为空时返回空结果（不是错误——nuclei 无命中时输出为空）。
func ParseNucleiJSONL(text string) ([]NucleiResult, NucleiParseStats, error) {
	stats := NucleiParseStats{Severity: map[string]int{}}
	text = strings.TrimPrefix(text, "\ufeff")
	if strings.TrimSpace(text) == "" {
		return nil, stats, nil
	}
	seen := map[string]bool{}
	var out []NucleiResult
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		stats.Lines++
		var r NucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			stats.Skipped++
			if len(stats.SkippedAt) < 3 {
				stats.SkippedAt = append(stats.SkippedAt, fmt.Sprintf("第 %d 行: %s", stats.Lines, truncateRunes(line, 80)))
			}
			continue
		}
		// 极少数行是 nuclei 的进度/告警 JSON（无 template_id）——按坏行计数更诚实。
		if strings.TrimSpace(r.TemplateID) == "" && strings.TrimSpace(r.Name) == "" {
			stats.Skipped++
			if len(stats.SkippedAt) < 3 {
				stats.SkippedAt = append(stats.SkippedAt, fmt.Sprintf("第 %d 行: 非命中行", stats.Lines))
			}
			continue
		}
		sanitizeResult(&r)
		key := strings.ToLower(r.TemplateID) + "\x00" + strings.ToLower(strings.TrimSpace(firstNonEmpty(r.MatchedAt, r.Host)))
		if seen[key] {
			stats.Duplicates++
			continue
		}
		seen[key] = true
		stats.Parsed++
		sev := strings.ToLower(strings.TrimSpace(r.Severity))
		if sev == "" {
			sev = "unknown"
		}
		stats.Severity[sev]++
		out = append(out, r)
	}
	return out, stats, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "…"
}
