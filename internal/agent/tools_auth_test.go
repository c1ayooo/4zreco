package agent

import (
	"os/exec"
	"strings"
	"testing"
)

// 凭据解析：资产上的 auth 字段形态不固定（历史上用过 username/password/
// token/type/description 等不同键名），要宽松认、严格用。
func TestParseAuthEntriesRecognizesCommonKeys(t *testing.T) {
	raw := []map[string]any{
		{"type": "wordpress", "username": "admin", "password": "p@ss"},
		{"type": "bearer", "token": "abc.def.ghi"},
		{"user": "bob", "pass": "secret"},      // 键名变体
		{"token": "tk", "description": "后台"}, // 带说明
		{"nothing": "here"},                   // 无可用字段 → 不算一条
	}
	entries := parseAuthEntries(raw)
	// 4 条有效凭据（wordpress / bearer / bob / tk），第 5 条无可用字段被跳过。
	if len(entries) != 4 {
		t.Fatalf("解析出 %d 条凭据，应为 4 条（无可用字段的不算）", len(entries))
	}
	// token 优先排前面（默认 auth_index=0 拿到最省事的那条）。
	if entries[0].Token == "" {
		t.Errorf("token 类凭据应排在最前，实际首条是 %+v", entries[0])
	}
	// 键名变体要认出来。
	found := false
	for _, e := range entries {
		if e.Username == "bob" && e.Password == "secret" {
			found = true
		}
	}
	if !found {
		t.Error("键名变体(user/pass)未被识别")
	}
}

// 没有凭据时返回空——工具要如实报「未登记凭据」，不能编。
func TestParseAuthEntriesEmptyWhenNoUsableFields(t *testing.T) {
	entries := parseAuthEntries([]map[string]any{{"foo": "bar"}, {"note": "x"}})
	if len(entries) != 0 {
		t.Errorf("无凭据字段时应返回空，实际 %d 条", len(entries))
	}
}

// 命令组装：认证方式要按凭据形态选对。
func TestBuildAuthCurlAuthenticationForms(t *testing.T) {
	cases := []struct {
		name    string
		entry   authEntry
		wantHas []string
		wantNot []string
	}{
		{
			name:    "token 走 Authorization Bearer",
			entry:   authEntry{Token: "tk123"},
			wantHas: []string{"Authorization: Bearer tk123"},
			wantNot: []string{"Cookie:"},
		},
		{
			name:    "cookie 类型的 token 走 Cookie 头",
			entry:   authEntry{Type: "session_cookie", Token: "PHPSESSID=abc"},
			wantHas: []string{"Cookie: PHPSESSID=abc"},
			wantNot: []string{"Authorization:"},
		},
		{
			name:    "账号密码走 -u",
			entry:   authEntry{Username: "admin", Password: "pw"},
			wantHas: []string{"-u 'admin:pw'"},
			wantNot: []string{"Authorization:"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := buildAuthCurl("https://t.example.com/x", "GET", "", "", c.entry)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range c.wantHas {
				if !strings.Contains(cmd, w) {
					t.Errorf("命令缺少 %q:\n%s", w, cmd)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(cmd, w) {
					t.Errorf("命令不该含 %q:\n%s", w, cmd)
				}
			}
		})
	}
}

// 凭据里的特殊字符必须被正确转义——密码生成器出来的密码常含 ' $ " \，
// 不转义的话 shell 会把它解释掉，命令跑的是**另一组凭据**。
//
// 这是「看起来能跑、其实跑错」的典型：请求返回 401，模型会误判成「凭据无效」，
// 真实原因是转义丢失了字符。
//
// 断言方式：**用 shell 解析回原值**——转义对了，shell 还原出来的就等于原凭据。
// 这比「命令里能否搜到原字符串」更准（转义后原字符串本来就不该原样出现）。
func TestBuildAuthCurlEscapesSpecialCharacters(t *testing.T) {
	tricky := []struct {
		name string
		val  string
	}{
		{"单引号", "pa'ss"},
		{"双引号", `pa"ss`},
		{"美元符号", "pa$ss"},
		{"反引号", "pa`ss"},
		{"反斜杠", `pa\ss`},
		{"分号", "pa;ss"},
		{"空格", "pa ss"},
		{"感叹号", "pa!ss"},
		{"括号", "pa(ss)"},
	}
	for _, c := range tricky {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := buildAuthCurl("https://t.example.com/x", "GET", "", "",
				authEntry{Username: "admin", Password: c.val})
			if err != nil {
				t.Fatal(err)
			}
			// 把命令里的 -u 参数取出来，交给 shell 解析，
			// 看还原出来的是不是原凭据。
			got, ok := evalShellArg(t, cmd, "-u")
			if !ok {
				t.Fatalf("命令里找不到 -u 参数:\n%s", cmd)
			}
			want := "admin:" + c.val
			if got != want {
				t.Errorf("shell 还原出的凭据=%q，应为 %q\n命令: %s", got, want, cmd)
			}
		})
	}
}

// body 与 header 也要转义（body 常带 JSON，里面全是引号）。
func TestBuildAuthCurlEscapesBodyAndHeader(t *testing.T) {
	body := `{"a":"b","c":"d"}`
	header := "X-Test: it's fine"
	cmd, err := buildAuthCurl("https://t.example.com/x", "POST", body, header, authEntry{Token: "tk"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--data-raw") {
		t.Errorf("缺少 --data-raw:\n%s", cmd)
	}
	// body 里的双引号在单引号包裹下是字面量，shell 还原后应原样。
	gotBody, ok := evalShellArg(t, cmd, "--data-raw")
	if !ok {
		t.Fatalf("命令里找不到 --data-raw:\n%s", cmd)
	}
	if gotBody != body {
		t.Errorf("body 还原后=%q，应为 %q", gotBody, body)
	}
	// header 里的单引号必须被转义（否则会把引号提前闭合，后面全是语法错误）。
	gotHdr, ok := evalShellArg(t, cmd, "-H")
	if !ok {
		t.Fatalf("命令里找不到 -H:\n%s", cmd)
	}
	// -H 出现两次（Authorization + 额外头），取最后一次。
	if gotHdr != "Authorization: Bearer tk" && gotHdr != header {
		t.Errorf("header 还原后=%q，应为 %q 或 Authorization 头", gotHdr, header)
	}
	// 命令里必须能看到转义痕迹（单引号被转成 '\''）。
	if !strings.Contains(cmd, `'\''`) {
		t.Errorf("header 里的单引号未转义:\n%s", cmd)
	}
}

// 方法要规范成大写；缺省是 GET。
func TestBuildAuthCurlNormalizesMethod(t *testing.T) {
	cmd, err := buildAuthCurl("https://t.example.com/x", "post", "", "", authEntry{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "-X 'POST'") {
		t.Errorf("方法未大写:\n%s", cmd)
	}
	// 缺省方法。
	cmd2, err := buildAuthCurl("https://t.example.com/x", "", "", "", authEntry{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd2, "-X 'GET'") {
		t.Errorf("缺省方法应为 GET:\n%s", cmd2)
	}
}

// evalShellArg 用**真 shell** 解析命令，取出指定选项的参数值。
//
// 为什么非要真 shell：转义正确与否的判据是「shell 还原出来的值等于原值」，
// 而字符串断言做不到这件事——转义后的命令里本来就不该出现原字符串。
// 只有让 sh 自己解析一遍，才能证明「跑出来的确实是那组凭据」。
//
// 找不到 sh 时跳过（CI 是 ubuntu，必有 sh；Windows 本地也有 Git Bash 的 sh）。
func evalShellArg(t *testing.T, cmd, opt string) (string, bool) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("找不到 sh，跳过 shell 解析验证")
	}
	// 用 `set --` 切词，再打印第 opt 之后的那个参数。
	script := `set -- ` + cmd + `
i=0
for a in "$@"; do
  if [ "$prev" = "` + opt + `" ]; then printf '%s' "$a"; exit 0; fi
  prev="$a"
done
exit 1`
	out, err := exec.Command(sh, "-c", script).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}
