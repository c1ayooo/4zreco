package agent

// F3 观测面凭据打码的单测（2026-11-13 体检修复）。

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

func TestMaskSensitiveInputMasksListedKeysCaseInsensitive(t *testing.T) {
	in := `{"user":"alice","Password":"hunter2","TOKEN":"tok-1","ApiKey":"ak-2",
		"api_key":"ak-3","access_token":"at-4","refresh_token":"rt-5",
		"authorization":"Bearer zzz","credential":"c-6","secret":"s-7","passwd":"p-8"}`
	out := maskSensitiveInput(in)
	for _, want := range []string{`"Password":"******"`, `"TOKEN":"******"`, `"ApiKey":"******"`,
		`"api_key":"******"`, `"access_token":"******"`, `"refresh_token":"******"`,
		`"authorization":"******"`, `"credential":"******"`, `"secret":"******"`, `"passwd":"******"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("masked output missing %s: %s", want, out)
		}
	}
	// 非敏感字段保留、凭据原文不出现。
	if strings.Contains(out, "hunter2") || strings.Contains(out, "tok-1") || strings.Contains(out, "Bearer zzz") {
		t.Fatalf("plaintext credential survived masking: %s", out)
	}
	if !strings.Contains(out, `"user":"alice"`) {
		t.Fatalf("non-sensitive field lost: %s", out)
	}
}

func TestMaskSensitiveInputDepthLimit(t *testing.T) {
	// 第 4 层的 password 打码。
	shallow := `{"a":{"b":{"c":{"password":"deep4"}}}}`
	if out := maskSensitiveInput(shallow); !strings.Contains(out, `"password":"******"`) {
		t.Fatalf("depth-4 key not masked: %s", out)
	}
	// 第 5 层起不再下钻。
	deep := `{"a":{"b":{"c":{"d":{"password":"deep5"}}}}}`
	if out := maskSensitiveInput(deep); !strings.Contains(out, `"password":"deep5"`) {
		t.Fatalf("depth-5 key must stay untouched (深度≤4): %s", out)
	}
}

func TestMaskSensitiveInputArraysAndNonStrings(t *testing.T) {
	in := `{"creds":[{"token":"t1"},{"password":"p1"}],"token":123,"note":"keep <b>html</b>"}`
	out := maskSensitiveInput(in)
	if !strings.Contains(out, `"token":"******"`) || !strings.Contains(out, `"password":"******"`) {
		t.Fatalf("keys inside array objects not masked: %s", out)
	}
	if strings.Contains(out, "t1") || strings.Contains(out, "p1") {
		t.Fatalf("plaintext survived: %s", out)
	}
	if !strings.Contains(out, `"token":123`) {
		t.Fatalf("non-string value under a sensitive key must stay: %s", out)
	}
	if !strings.Contains(out, `"note":"keep <b>html</b>"`) {
		t.Fatalf("non-sensitive text must be preserved verbatim (no HTML escaping): %s", out)
	}
}

func TestMaskSensitiveInputPassthrough(t *testing.T) {
	// 无命中的 JSON：逐字节原样返回（含键序与大整数）。
	plain := `{"b":2,"a":12345678901234567890,"command":"nmap -sV 10.0.0.1"}`
	if out := maskSensitiveInput(plain); out != plain {
		t.Fatalf("no-hit JSON must be byte-identical:\n got %s\nwant %s", out, plain)
	}
	// 非 JSON：原样返回。
	for _, s := range []string{"curl -sS http://x", "", "{broken", "[1,2"} {
		if out := maskSensitiveInput(s); out != s {
			t.Fatalf("non-JSON must pass through: %q -> %q", s, out)
		}
	}
	// 打码产物必须是合法 JSON（敏感值已替换）。
	valid := maskSensitiveInput(`{"nested":{"token":"x"}}`)
	if !strings.Contains(valid, `"token":"******"`) || strings.Contains(valid, `"x"`) {
		t.Fatalf("masked output malformed: %s", valid)
	}
}

// capture 泵侧：tool_use 活动的 Detail/Summary 与中断渲染（runTrace）都吃打码后
// 的输入。trace 条目的打码断言在 internal/intercept 的 StartMasked 测试里。
func TestCaptureToolUseObservationSurfaceMasked(t *testing.T) {
	input := `{"url":"http://x","header":"Authorization: Bearer stand-in","password":"hunter2"}`
	events := func(yield func(harness.Event, error) bool) {
		yield(harness.Event{Kind: harness.KindToolUse, ToolUse: &llm.ContentBlock{
			Type: llm.BlockToolUse, ID: "call-1", Name: "auth_request", Input: []byte(input),
		}}, nil)
		yield(harness.Event{Kind: harness.KindToolResult, ToolResult: &llm.ContentBlock{
			Type: llm.BlockToolResult, ToolUseID: "call-1",
		}}, nil)
	}
	p := newCapturePump(context.Background(), "打码", nil, nil)
	defer p.finish()
	if _, _, err := p.drain(events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range p.recordedActivities() {
		if a.Kind != "tool_use" {
			continue
		}
		found = true
		if strings.Contains(a.Detail, "hunter2") || strings.Contains(a.Summary, "hunter2") {
			t.Fatalf("plaintext password in activity observation: summary=%q detail=%q", a.Summary, a.Detail)
		}
		if !strings.Contains(a.Detail, `"password":"******"`) {
			t.Fatalf("masked placeholder missing in detail: %q", a.Detail)
		}
	}
	if !found {
		t.Fatal("no tool_use activity recorded")
	}
	if strings.Contains(p.lastTool.input, "hunter2") {
		t.Fatalf("plaintext password in runTrace (中断渲染泄漏): %q", p.lastTool.input)
	}
}

// ---- 值形态打码（F3 残留收口：键名打码覆盖不到的携带形态）----

func TestMaskCredentialTextCurlAuthShapes(t *testing.T) {
	// auth_request 产物（buildAuthCurl 形态）：Bearer 头、Cookie 头、-u 账号密码。
	cmd := "curl -sS -i --max-time 20 -X 'GET' 'http://10.0.0.1/admin' " +
		"-H 'Authorization: Bearer eyJhbGci.payload.sig' -H 'Cookie: SESSIONID=abc123def' " +
		"-u 'admin:hunter2' -H 'Content-Type: application/json'"
	out := maskCredentialText(cmd)
	for _, leak := range []string{"eyJhbGci", "abc123def", "hunter2"} {
		if strings.Contains(out, leak) {
			t.Fatalf("plaintext credential survived: %q", leak)
		}
	}
	for _, want := range []string{
		"-H 'Authorization: ******'", "-H 'Cookie: ******'", "-u '******'",
		"-H 'Content-Type: application/json'", "'http://10.0.0.1/admin'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("masked command missing %q: %s", want, out)
		}
	}
}

func TestMaskCredentialTextCurlEscapedQuoteAndLongFlags(t *testing.T) {
	// q() 的单引号转义（密码含 ' → '\''）也要整体吃掉。
	out := maskCredentialText(`curl -u 'admin:hun'\''ter2' http://x`)
	if strings.Contains(out, "ter2") || !strings.Contains(out, "-u '******'") {
		t.Fatalf("escaped-quote -u not fully masked: %s", out)
	}
	// 长选项形态同样覆盖。
	out = maskCredentialText(`curl --header 'Authorization: Basic YWRTaW46cHc=' --user 'svc:pw1' http://x`)
	if strings.Contains(out, "YWRTaW4") || strings.Contains(out, "svc:pw1") {
		t.Fatalf("long-form curl args not masked: %s", out)
	}
}

func TestMaskCredentialTextShapes(t *testing.T) {
	cases := []struct{ name, in, mustGone, mustKeep string }{
		{"自由文本认证头", "响应里带着请求侧的 Authorization: Bearer abc.def.ghi 头", "abc.def.ghi", "Authorization: Bearer ******"},
		{"URL userinfo", "redirect 到 http://admin:secret@10.0.0.1:8080/login", "admin:secret@", "http://******@10.0.0.1:8080/login"},
		{"内嵌 JSON 敏感键", `--data-raw '{"username":"admin","password":"hunter2"}'`, "hunter2", `"password":"******"`},
		{"表单字段", "curl --data-raw 'user=admin&password=hunter2&theme=dark' http://x/login", "hunter2", "user=admin&password=******"},
		{"查询串 token", "抓到 ?access_token=eyJzzz&next=/home", "eyJzzz", "access_token=******"},
	}
	for _, c := range cases {
		out := maskCredentialText(c.in)
		if strings.Contains(out, c.mustGone) {
			t.Fatalf("%s: plaintext survived: %s", c.name, out)
		}
		if !strings.Contains(out, c.mustKeep) {
			t.Fatalf("%s: expected %q in %s", c.name, c.mustKeep, out)
		}
	}
}

func TestMaskCredentialTextPassthrough(t *testing.T) {
	// 普通文本逐字节原样：普通头、响应 Set-Cookie（响应头不是本进程发出的凭据）、
	// 无凭据 URL。
	plain := "HTTP/1.1 200 OK\nSet-Cookie: SID=xyz; Path=/\n" +
		`curl -H 'Content-Type: application/json' http://10.0.0.1/api?theme=dark`
	if out := maskCredentialText(plain); out != plain {
		t.Fatalf("non-credential text must be byte-identical:\n got %s\nwant %s", out, plain)
	}
}

func TestMaskSensitiveInputMasksShapesInsideStringValues(t *testing.T) {
	// 键名不在清单内、但值里带着 curl 凭据（auth_request → Bash 的真实路径）。
	in := `{"command":"curl -sS -u 'admin:hunter2' -H 'Authorization: Bearer eyJzzz' http://x","body":"password=hunter2"}`
	out := maskSensitiveInput(in)
	for _, leak := range []string{"hunter2", "eyJzzz"} {
		if strings.Contains(out, leak) {
			t.Fatalf("plaintext credential survived in string value: %s", out)
		}
	}
	if !strings.Contains(out, "-u '******'") {
		t.Fatalf("-u shape missing: %s", out)
	}
	// 无命中的 JSON 仍逐字节原样（值形态打码不引入误伤）。
	plain := `{"command":"nmap -sV 10.0.0.1","url":"http://x?a=1"}`
	if out := maskSensitiveInput(plain); out != plain {
		t.Fatalf("no-hit JSON must stay byte-identical:\n got %s\nwant %s", out, plain)
	}
}

// capture 泵输出面：tool_result 活动（Detail/Summary）吃打码后的文本。
func TestCaptureToolResultObservationMasked(t *testing.T) {
	resultText := `{"run_with_bash":"curl -sS -u 'admin:hunter2' -H 'Authorization: Bearer eyJzzz' http://x","auth_kind":"token"}`
	tr := llm.ToolResultText("call-2", resultText, false)
	events := func(yield func(harness.Event, error) bool) {
		yield(harness.Event{Kind: harness.KindToolUse, ToolUse: &llm.ContentBlock{
			Type: llm.BlockToolUse, ID: "call-2", Name: "auth_request", Input: []byte(`{"asset_id":1,"url":"http://x"}`),
		}}, nil)
		yield(harness.Event{Kind: harness.KindToolResult, ToolResult: &tr}, nil)
	}
	p := newCapturePump(context.Background(), "输出打码", nil, nil)
	defer p.finish()
	if _, _, err := p.drain(events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range p.recordedActivities() {
		if a.Kind != "tool_result" {
			continue
		}
		found = true
		for _, leak := range []string{"hunter2", "eyJzzz"} {
			if strings.Contains(a.Detail, leak) || strings.Contains(a.Summary, leak) {
				t.Fatalf("plaintext credential in tool_result activity: summary=%q detail=%q", a.Summary, a.Detail)
			}
		}
		if !strings.Contains(a.Detail, "-u '******'") {
			t.Fatalf("masked placeholder missing in tool_result detail: %q", a.Detail)
		}
	}
	if !found {
		t.Fatal("no tool_result activity recorded")
	}
}
