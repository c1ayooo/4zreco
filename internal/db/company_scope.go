package db

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ParsedScope is one parsed asset-scope entry. Its kind selects Domain, Net, or Value.
// Used internally by the company scope parsers and CompanyStore.
type ParsedScope struct {
	Kind   string // "domain" | "ip" | "cidr" | "icp" | "keyword"
	Domain string // normalized registrable/root domain (kind=domain)
	Net    string // normalized CIDR, single IP as /32 or /128 (kind=ip|cidr)
	Value  string // normalized text (kind=icp|keyword)
	Raw    string // original input line
}

// ScopeInput is the structured API form for a company scope rule. Empty Kind
// uses the same automatic classification as the single-textarea UI.
type ScopeInput struct {
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value"`
}

// NormalizeICP removes every Unicode whitespace character and folds case. ICP
// matching intentionally performs no fuzzy or punctuation normalization.
func NormalizeICP(value string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(value)))
}

func normalizeKeyword(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func looksLikeIPAddress(value string) bool {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	if strings.Count(value, ":") >= 2 {
		// Require an IPv6-looking prefix. This still catches malformed values such
		// as 2001:db8::zz without treating ordinary colon-delimited keywords as IPs.
		parts := strings.Split(value, ":")
		validSegments := 0
		for _, part := range parts {
			if part == "" {
				if validSegments > 0 || strings.HasPrefix(value, "::") {
					return true
				}
				continue
			}
			if len(part) > 4 {
				return false
			}
			for _, r := range part {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
					return false
				}
			}
			validSegments++
			if validSegments >= 2 {
				return true
			}
		}
		return false
	}
	if !strings.Contains(value, ".") {
		return false
	}
	for _, r := range value {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// ParseScopeInput validates an explicitly typed rule. Legacy callers can omit
// Kind and use the same automatic classification as the single-textarea UI.
func ParseScopeInput(input ScopeInput) (ParsedScope, error) {
	kind := strings.ToLower(strings.TrimSpace(input.Kind))
	raw := strings.TrimSpace(input.Value)
	if kind == "" {
		return ParseAutoScopeLine(raw)
	}
	switch kind {
	case "domain", "ip", "cidr":
		rule, err := ParseScopeLine(raw)
		if err != nil {
			return rule, err
		}
		if rule.Kind != kind {
			return ParsedScope{Kind: kind, Raw: raw}, fmt.Errorf("%q 不是有效的 %s 范围", raw, kind)
		}
		return rule, nil
	case "icp":
		value := NormalizeICP(raw)
		if value == "" {
			return ParsedScope{Kind: kind, Raw: raw}, fmt.Errorf("ICP 不能为空")
		}
		return ParsedScope{Kind: kind, Value: value, Raw: raw}, nil
	case "keyword":
		value := normalizeKeyword(raw)
		if value == "" {
			return ParsedScope{Kind: kind, Raw: raw}, fmt.Errorf("企业关键词不能为空")
		}
		return ParsedScope{Kind: kind, Value: value, Raw: raw}, nil
	default:
		return ParsedScope{Kind: kind, Raw: raw}, fmt.Errorf("不支持的范围类型: %s", kind)
	}
}

// ParseAutoScopeLine classifies one untyped textarea line. Network-looking and
// domain-looking values remain strict so malformed ranges do not silently become
// Agent keywords; all other non-empty text is a keyword.
func ParseAutoScopeLine(line string) (ParsedScope, error) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return ParsedScope{}, fmt.Errorf("空行")
	}

	if _, _, err := net.ParseCIDR(raw); err == nil {
		return ParseScopeLine(raw)
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ParseScopeLine(raw)
	}
	if slash := strings.LastIndexByte(raw, '/'); slash > 0 {
		address := strings.TrimSpace(raw[:slash])
		if net.ParseIP(address) != nil || looksLikeIPAddress(address) {
			return ParsedScope{Raw: raw}, fmt.Errorf("无效 CIDR: %s", raw)
		}
	}

	if looksLikeIPAddress(raw) {
		return ParsedScope{Raw: raw}, fmt.Errorf("无效 IP: %s", raw)
	}

	looksLikeDomain := strings.Contains(raw, "://") ||
		(strings.Contains(raw, ".") && strings.IndexFunc(raw, unicode.IsSpace) < 0)
	if looksLikeDomain {
		return ParseScopeLine(raw)
	}
	// 备案号本身不含点号（如 京ICP备12345678号-1）。带点的文本多半掺了域名或版本号，
	// 按 ICP 存下来只会得到一条永远匹配不上任何资产的死规则 —— ICP 归属走的是精确
	// 相等比较（见 companies.go 的 kind='icp' 归属查询），所以这类文本归为关键词。
	lower := strings.ToLower(raw)
	if !strings.ContainsAny(raw, ".．。") &&
		(strings.Contains(lower, "icp") || strings.Contains(raw, "备案")) {
		return ParseScopeInput(ScopeInput{Kind: "icp", Value: raw})
	}
	return ParseScopeInput(ScopeInput{Kind: "keyword", Value: raw})
}

func scopeHostname(raw string) (string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", fmt.Errorf("主机名为空")
	}
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	} else if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" {
		if err == nil {
			err = fmt.Errorf("缺少主机名")
		}
		return "", err
	}
	host := strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), ".")
	if host == "" {
		return "", fmt.Errorf("主机名为空")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	host, err = idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(host)
	if len(host) > 253 {
		return "", fmt.Errorf("域名超过 253 个字符")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("域名至少需要两个标签")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("域名标签无效")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", fmt.Errorf("域名包含无效字符")
			}
		}
	}
	return host, nil
}

// ParseScopeLine classifies and validates one scope line (root domain / IP /
// CIDR). Guardrails reject bare TLDs and over-broad networks so a rule can never
// swallow the internet. IP ranges must be expressed as CIDR.
func ParseScopeLine(line string) (ParsedScope, error) {
	raw := strings.TrimSpace(line)
	r := ParsedScope{Raw: raw}
	if raw == "" {
		return r, fmt.Errorf("空行")
	}
	// 域名通配符：前导 "*." 是语法糖 —— domain 规则的匹配语义本就是「根域及全部
	// 子域」（company_scope 归属与 project_scope 继承任务范围都按 root_domain 相等
	// 比较），"*.example.com" 与 "example.com" 等价，剥掉前缀走普通域名解析即可。
	// 其余形态没有对应的匹配语义，显式拒绝而不是存进永远命不中的死规则：
	// 深层通配（*.api.example.com）因为资产的 root_domain 恒为 eTLD+1，匹配不上；
	// 通配 IP/网段、中间通配、多层通配均无意义。
	wildcard := strings.HasPrefix(raw, "*.")
	if wildcard {
		sub := strings.TrimPrefix(raw, "*.")
		if strings.Contains(sub, "*") {
			return r, fmt.Errorf("只支持前导 *. 通配: %s", r.Raw)
		}
		if net.ParseIP(sub) != nil || looksLikeIPAddress(sub) {
			return r, fmt.Errorf("通配符仅支持域名: %s", r.Raw)
		}
		if _, _, err := net.ParseCIDR(sub); err == nil {
			return r, fmt.Errorf("通配符仅支持域名: %s", r.Raw)
		}
		raw = sub
	}
	// CIDR first because URL parsing treats its slash as a path separator.
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones < 16 {
			return r, fmt.Errorf("网段过宽(IPv4 需 >= /16): %s", raw)
		}
		if bits == 128 && ones < 32 {
			return r, fmt.Errorf("网段过宽(IPv6 需 >= /32): %s", raw)
		}
		r.Kind, r.Net = "cidr", ipnet.String()
		return r, nil
	}
	// Single IP.
	if ip := net.ParseIP(raw); ip != nil {
		r.Kind = "ip"
		if ip.To4() != nil {
			r.Net = ip.String() + "/32"
		} else {
			r.Net = ip.String() + "/128"
		}
		return r, nil
	}
	host, err := scopeHostname(raw)
	if err != nil {
		return r, fmt.Errorf("无法识别为有效域名/IP/CIDR: %s", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		r.Kind = "ip"
		if ip.To4() != nil {
			r.Net = ip.String() + "/32"
		} else {
			r.Net = ip.String() + "/128"
		}
		return r, nil
	}
	if looksLikeIPAddress(host) {
		return r, fmt.Errorf("无效 IP: %s", raw)
	}
	if strings.Contains(raw, "-") && strings.Count(raw, ".") >= 6 {
		return r, fmt.Errorf("IP 段请用 CIDR 表示(如 1.2.3.0/24): %s", raw)
	}
	// Domain (registrable). Reject bare TLDs / public suffixes.
	d := DomainKey(host)
	if suf, icann := publicsuffix.PublicSuffix(d); icann && suf == d {
		return r, fmt.Errorf("不能用裸 TLD 作为范围: %s", raw)
	}
	// 通配只接受注册域级别：子域级通配剥掉 "*." 后得到的域名 ≠ 其 eTLD+1，
	// 而 domain 规则匹配的是 root_domain 相等，这类规则永远命中不了任何资产。
	if wildcard {
		if root, _ := RootDomain(d); root != d {
			return r, fmt.Errorf("通配符仅支持注册域级别(如 *.example.com): %s", r.Raw)
		}
	}
	r.Kind, r.Domain = "domain", d
	return r, nil
}
