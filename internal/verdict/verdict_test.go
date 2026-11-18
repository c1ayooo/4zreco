package verdict

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		id, name string
		tags     []string
		want     Class
	}{
		{"CVE-2021-44228", "Apache Log4j2 RCE", nil, ClassDeserialization}, // jndi/log4j 优先于 rce
		{"sqli-error-based", "SQL injection", nil, ClassSQLi},
		{"xss-reflected", "Reflected XSS", nil, ClassXSS},
		{"ssrf-basic", "Server-Side Request Forgery", nil, ClassSSRF},
		{"cmdi-echo", "Command injection", nil, ClassCommandInject},
		{"upload-form", "Arbitrary File Upload", nil, ClassFileUpload},
		{"idor-user", "IDOR", nil, ClassAuthBypass},
		{"exposure-backup", "Backup file disclosure", nil, ClassInfoLeak},
		{"tech-detect", "Tech detection", []string{"tech"}, ClassGeneric},
		{"custom", "", []string{"sqli"}, ClassSQLi}, // tags 也参与判定
	}
	for _, tc := range cases {
		if got := Classify(tc.id, tc.name, tc.tags); got != tc.want {
			t.Errorf("Classify(%q,%q,%v)=%q, want %q", tc.id, tc.name, tc.tags, got, tc.want)
		}
	}
}

func TestParseMatcherProfile(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want *MatcherProfile
	}{
		{"no matchers", "id: x\ninfo:\n  name: N\n", nil},
		{"status only", "matchers:\n  - type: status\n    status:\n      - 200\n", &MatcherProfile{HasStatus: true, StatusOnly: true}},
		{"word", "matchers:\n  - type: word\n    words: [a]\n", &MatcherProfile{HasWord: true}},
		{"status+word", "matchers:\n  - type: status\n  - type: word\n", &MatcherProfile{HasStatus: true, HasWord: true}},
		{"regex", "  - type: regex\n", &MatcherProfile{HasRegex: true}},
		{"dsl", "  - type: dsl\n", &MatcherProfile{HasDSL: true}},
		{"other kind", "  - type: xpath\n", &MatcherProfile{HasOther: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseMatcherProfile(tc.yaml)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want %+v, got nil", *tc.want)
			}
			if *got != *tc.want {
				t.Errorf("got %+v, want %+v", *got, *tc.want)
			}
		})
	}
}

func TestAssessStrongEvidenceConfirmed(t *testing.T) {
	d := Assess(Observation{
		TemplateID: "sqli-boolean", Name: "SQL injection", Type: "http",
		StatusCode: 200, Response: "admin=1&user=root",
		Extracted: []string{"root"},
		Matcher:   &MatcherProfile{HasWord: true},
	})
	if d.Verdict != Confirmed {
		t.Fatalf("强证据应判 confirmed，得到 %q（reasons=%v）", d.Verdict, d.Reasons)
	}
	if d.Class != ClassSQLi {
		t.Errorf("class=%q", d.Class)
	}
	if len(d.Checks) == 0 {
		t.Error("checks 不应为空")
	}
	if d.NeedsManualReview() {
		t.Error("confirmed 不应要求人工复核")
	}
}

func TestAssessNeedsReview(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		want Class
		hint string // 期望 reasons 里出现的关键词
	}{
		{
			name: "5xx 无法区分",
			obs: Observation{TemplateID: "CVE-2024-0001", Name: "SQL injection", Type: "http",
				StatusCode: 500, Response: "error", Extracted: []string{"x"}},
			want: ClassSQLi, hint: "5xx",
		},
		{
			name: "缺响应正文",
			obs: Observation{TemplateID: "xss-check", Name: "Reflected XSS", Type: "http",
				StatusCode: 200, Extracted: []string{"alert(1)"}},
			want: ClassXSS, hint: "响应正文",
		},
		{
			name: "仅状态码匹配无提取",
			obs: Observation{TemplateID: "tech", Name: "Tech detect", Type: "http",
				StatusCode: 200, Response: "ok",
				Matcher: &MatcherProfile{HasStatus: true, StatusOnly: true}},
			want: ClassGeneric, hint: "状态码",
		},
		{
			name: "XSS 无反射位置",
			obs: Observation{TemplateID: "xss-check", Name: "Reflected XSS", Type: "http",
				StatusCode: 200, Response: "<html>ok</html>",
				Matcher: &MatcherProfile{HasDSL: true}},
			want: ClassXSS, hint: "反射",
		},
		{
			name: "信息泄露响应过短",
			obs: Observation{TemplateID: "exposure-check", Name: "Sensitive file exposure", Type: "http",
				StatusCode: 200, Response: "ok",
				Matcher: &MatcherProfile{HasWord: true}},
			want: ClassInfoLeak, hint: "过短",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Assess(tc.obs)
			if d.Verdict != NeedsReview {
				t.Fatalf("verdict=%q, want needs_review", d.Verdict)
			}
			if d.Class != tc.want {
				t.Errorf("class=%q, want %q", d.Class, tc.want)
			}
			if len(d.Reasons) == 0 {
				t.Fatal("reasons 为空")
			}
			if !strings.Contains(strings.Join(d.Reasons, " "), tc.hint) {
				t.Errorf("reasons 缺关键词 %q：%v", tc.hint, d.Reasons)
			}
			if !d.NeedsManualReview() {
				t.Error("needs_review 应返回 NeedsManualReview=true")
			}
		})
	}
}

// 非 HTTP 结果（tcp/dns）没有响应正文是正常的，不应因此降级。
func TestAssessNonHTTPIgnoresEmptyResponse(t *testing.T) {
	d := Assess(Observation{
		TemplateID: "tcp-weak", Name: "Weak protocol", Type: "network",
		StatusCode: 0, Matcher: &MatcherProfile{HasDSL: true},
	})
	if d.Verdict != Confirmed {
		t.Fatalf("network 命中无正文应可确认，得到 %q（%v）", d.Verdict, d.Reasons)
	}
}

func TestChecklistCopiesDefaults(t *testing.T) {
	a := Checklist(ClassSQLi)
	if len(a) == 0 {
		t.Fatal("checklist 为空")
	}
	a[0] = "mutated"
	b := Checklist(ClassSQLi)
	if strings.EqualFold(b[0], "mutated") {
		t.Fatal("Checklist 与默认切片共享底层数组")
	}
}

// WAF 绕过永不自动确认：命中只说明载荷进入了未被拦截的响应。
func TestBypassReview(t *testing.T) {
	d := BypassReview()
	if d.Verdict != NeedsReview {
		t.Fatalf("verdict=%q, want needs_review", d.Verdict)
	}
	if d.Class != ClassWAFBypass {
		t.Fatalf("class=%q", d.Class)
	}
	joined := strings.Join(d.Checks, " ")
	if !strings.Contains(joined, "验证码") && !strings.Contains(joined, "拦截") {
		t.Errorf("复核清单应提示拦截页/验证码风险：%q", joined)
	}
	if !strings.Contains(joined, "重放") && !strings.Contains(joined, "对照") {
		t.Errorf("复核清单应要求对照重放：%q", joined)
	}
}
