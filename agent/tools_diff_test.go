package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/c1ayooo/4zreco/intercept"
)

// 差分的核心判据：只留**结构性**差异，滤掉噪声。
func TestDiffResponseDetectsKeySetDifference(t *testing.T) {
	bodyA := `{"id":1,"name":"a","secret_field":"x"}`
	bodyB := `{"id":1,"name":"a"}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.KeysOnlyInA) != 1 || d.KeysOnlyInA[0] != "secret_field" {
		t.Errorf("应识别出只在 A 侧的键，实际 %v", d.KeysOnlyInA)
	}
	if d.SameShape {
		t.Error("键集合不同，SameShape 应为 false")
	}
	if !d.Enumerable {
		t.Error("键集合不同应支持可枚举判断")
	}
}

// 键顺序不同是 JSON 语义相同——不能算差异。
func TestDiffResponseIgnoresKeyOrder(t *testing.T) {
	bodyA := `{"a":1,"b":2,"c":3}`
	bodyB := `{"c":3,"b":2,"a":1}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if !d.SameShape {
		t.Error("键顺序不同不应改变形状")
	}
	if len(d.ValueDiffs) != 0 {
		t.Errorf("键顺序不同不应产生值差异，实际 %v", d.ValueDiffs)
	}
	if d.Enumerable {
		t.Error("仅键顺序不同不应支持可枚举判断")
	}
}

// 时间戳/trace id 这类噪声要滤掉——否则每次请求都会"有差异"。
func TestDiffResponseFiltersNoiseValues(t *testing.T) {
	bodyA := `{"created_at":"2026-10-22T10:00:00Z","trace":"a1b2c3d4e5f60718293a4b5","id":1}`
	bodyB := `{"created_at":"2026-10-22T10:00:03Z","trace":"f6e5d4c3b2a1908776655443","id":1}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.ValueDiffs) != 0 {
		t.Errorf("噪声字段不应产生值差异，实际 %v", d.ValueDiffs)
	}
	if len(d.NoiseKeys) != 2 {
		t.Errorf("应标出 2 个噪声字段，实际 %v", d.NoiseKeys)
	}
}

// **单边**像噪声不算噪声——那说明另一边的值是有意义的差异。
func TestDiffResponseOneSidedNoiseIsRealDifference(t *testing.T) {
	bodyA := `{"id":"2026-10-22T10:00:00Z"}`
	bodyB := `{"id":"42"}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.ValueDiffs) != 1 {
		t.Errorf("单边噪声应算真实差异，实际 %d 条: %v", len(d.ValueDiffs), d.ValueDiffs)
	}
	if len(d.NoiseKeys) != 0 {
		t.Errorf("单边噪声不应进噪声清单，实际 %v", d.NoiseKeys)
	}
}

// 类型变了是结构差异——模型必须看得见（数字 1 变成字符串 "1"）。
func TestDiffResponseTypeChangeIsDifference(t *testing.T) {
	d := diffResponse(200, 200, `{"id":1}`, `{"id":"1"}`)
	if len(d.ValueDiffs) != 1 {
		t.Fatalf("类型变化应产生值差异，实际 %d 条", len(d.ValueDiffs))
	}
	vd := d.ValueDiffs[0]
	if vd.KindA != "number" || vd.KindB != "string" {
		t.Errorf("类型标注错误: %s -> %s", vd.KindA, vd.KindB)
	}
}

// 嵌套对象/数组的值要正确比较——map 逐字节比会因迭代顺序误判。
func TestDiffResponseComparesNestedStructures(t *testing.T) {
	same := diffResponse(200, 200, `{"o":{"x":1,"y":2}}`, `{"o":{"y":2,"x":1}}`)
	if len(same.ValueDiffs) != 0 {
		t.Errorf("嵌套对象键序不同不应算差异，实际 %v", same.ValueDiffs)
	}
	diff := diffResponse(200, 200, `{"o":{"x":1}}`, `{"o":{"x":2}}`)
	if len(diff.ValueDiffs) != 1 {
		t.Errorf("嵌套对象值不同应算 1 条差异，实际 %d 条", len(diff.ValueDiffs))
	}
}

// 凭据类字段的值要抹掉——响应体里常有 token，不能原样进报告/图谱。
func TestDiffResponseMasksSensitiveValues(t *testing.T) {
	d := diffResponse(200, 200, `{"access_token":"aaa111","id":1}`, `{"access_token":"bbb222","id":2}`)

	var found bool
	for _, vd := range d.ValueDiffs {
		if vd.Key == "access_token" {
			found = true
			if !vd.Sensitive {
				t.Error("access_token 应标记为敏感")
			}
			if vd.PreviewA != "***" || vd.PreviewB != "***" {
				t.Errorf("敏感值未抹掉: %q / %q", vd.PreviewA, vd.PreviewB)
			}
		}
	}
	if !found {
		t.Fatalf("access_token 应出现在值差异里，实际 %v", d.ValueDiffs)
	}
}

// 敏感键的判定不能误伤：monkey / keyword 这类含 "key" 的业务字段不是凭据。
func TestSensitiveKeyDoesNotOverMatch(t *testing.T) {
	notSensitive := []string{"monkey", "keyword", "user", "name", "id", "cache_key", "sort_key", "session_count", "session_duration"}
	for _, k := range notSensitive {
		if isSensitiveKey(k) {
			t.Errorf("%q 不应被判为敏感键", k)
		}
	}
	sensitive := []string{
		"token", "access_token", "accessToken", "refreshToken",
		"password", "passwd", "pwd", "passphrase",
		"api_key", "apiKey", "APIKey", "API_KEY", "secret_key", "client_secret",
		"sessionId", "session_id", "auth_header", "authorization", "cookie",
		"jwt", "credentials", "private_key",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("%q 应被判为敏感键", k)
		}
	}
}

// 状态码未知时不能拿 0==0 冒充"状态码相同"。
func TestDiffResponseUnknownStatusIsNotSameStatus(t *testing.T) {
	d := diffResponse(0, 0, `{"a":1}`, `{"a":1}`)
	if d.StatusKnown {
		t.Error("两边都没状态码时 StatusKnown 应为 false")
	}
	if d.Enumerable {
		t.Error("状态码未知且结构相同时不应判定可枚举")
	}
	if !strings.Contains(d.Note, "状态码未知") {
		t.Errorf("提示应说明状态码未知，实际 %q", d.Note)
	}
}

// 非 JSON 响应（HTML/文本）只能比长度与相等性。
func TestDiffResponseNonJSON(t *testing.T) {
	d := diffResponse(200, 404, "<html>a</html>", "<html>b</html>")
	if d.SameShape {
		t.Error("非 JSON 且内容不同，SameShape 应为 false")
	}
	if !d.Enumerable {
		t.Error("状态码不同应支持可枚举判断")
	}
}

// stripHTTPHeader：curl -i 保存的完整响应要能剥头并取出状态码。
func TestStripHTTPHeader(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	body, status := stripHTTPHeader(raw)
	if status != 200 {
		t.Errorf("状态码应为 200，实际 %d", status)
	}
	if body != `{"a":1}` {
		t.Errorf("响应体剥离错误: %q", body)
	}

	// 没有 HTTP 头（纯响应体）时原样返回，状态码未知。
	body2, status2 := stripHTTPHeader(`{"a":1}`)
	if status2 != 0 {
		t.Errorf("无 HTTP 头时状态码应为 0，实际 %d", status2)
	}
	if body2 != `{"a":1}` {
		t.Errorf("无 HTTP 头时不应改动内容: %q", body2)
	}
}

// 文件模式：工具读文件直接算 diff，不联网、不写脚本。
func TestDiffResponsesFileModeComputesDiffInProcess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":1,"extra":"leak"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"id":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	in, _ := json.Marshal(map[string]any{"file_a": "a.json", "file_b": "b.json"})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("工具报错: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	diff, ok := out["diff"].(map[string]any)
	if !ok {
		t.Fatalf("返回里没有 diff 字段: %v", out)
	}
	keys, _ := diff["keys_only_in_a"].([]any)
	if len(keys) != 1 || keys[0] != "extra" {
		t.Errorf("应识别出 only-in-A 的键 extra，实际 %v", diff["keys_only_in_a"])
	}
	// 文件模式不该产生命令——不联网。
	if _, has := out["run_with_bash"]; has {
		t.Error("文件模式不应返回 run_with_bash（不联网）")
	}
}

// URL 模式：没有工作目录时应明确报错并给出替代方案，而不是静默失败。
func TestDiffResponsesURLModeRequiresWorkingDir(t *testing.T) {
	ts := &ToolSet{}
	tool := ts.diffResponses()
	// 不绑定工作目录。
	in, _ := json.Marshal(map[string]any{"url_a": "https://a.test/x", "url_b": "https://a.test/y"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("没有工作目录时应报错，实际 %v", res.Content)
	}
	msg := toolResultText(t, res)
	if !strings.Contains(msg, "工作目录") {
		t.Errorf("错误提示应说明工作目录问题，实际 %q", msg)
	}
}

// URL 模式：有工作目录时应写出脚本并返回一条可执行命令。
func TestDiffResponsesURLModeWritesScript(t *testing.T) {
	dir := t.TempDir()
	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	in, _ := json.Marshal(map[string]any{
		"url_a": "https://a.test/x", "url_b": "https://a.test/y",
		"header_a": "Authorization: Bearer tk",
	})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("工具报错: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	cmd, _ := out["run_with_bash"].(string)
	if cmd == "" {
		t.Fatalf("应返回命令，实际 %v", out)
	}
	scriptPath, _ := out["script_path"].(string)
	if scriptPath == "" {
		t.Fatal("应返回脚本路径")
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("脚本应已写出: %v", err)
	}
	// 响应体落在工作目录，不落 /tmp。
	if !strings.Contains(cmd, "resp_a_body") || !strings.Contains(cmd, "resp_b_body") {
		t.Errorf("命令应引用工作目录下的响应体文件: %s", cmd)
	}
	// 产物必须落在【本次 run 的工作目录】里，而不是固定的 /tmp 路径。
	//
	// 断言方式：命令里的响应体路径必须在工作目录下。
	// 不能断言"命令里不含 /tmp"——Linux 上 t.TempDir() 本身就是 /tmp/...，
	// 那样断言会把测试临时目录也判成违规（CI 上就是这么挂的）。
	if !strings.Contains(cmd, dir) {
		t.Errorf("响应体文件应落在工作目录 %s 下: %s", dir, cmd)
	}
	// 也不该用固定的 /tmp 路径（那正是平台规约禁止的"中间产物落 /tmp"）。
	for _, fixed := range []string{"/tmp/resp_a_body", "/tmp/resp_b_body", "/tmp/resp_diff.py"} {
		if strings.Contains(cmd, fixed) {
			t.Errorf("中间产物不应落在固定路径 %s: %s", fixed, cmd)
		}
	}
	// 认证头要转义。
	if !strings.Contains(cmd, "'Authorization: Bearer tk'") {
		t.Errorf("认证头应被单引号包裹: %s", cmd)
	}
}

// 两份实现（Go 侧 diffResponse 与 Python 侧脚本）必须等价——
// URL 模式实际跑的是脚本，文件模式跑的是 Go 代码，行为不一致会让模型困惑。
//
// 断言方式：**真跑 python** 拿它的输出，与 Go 侧结果逐字段比。
func TestDiffScriptMatchesGoImplementation(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteDiffScript(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		a    string
		b    string
		sa   int
		sb   int
	}{
		{"键集合不同", `{"id":1,"extra":"x"}`, `{"id":1}`, 200, 200},
		{"键序不同", `{"a":1,"b":2}`, `{"b":2,"a":1}`, 200, 200},
		{"噪声字段", `{"t":"2026-10-22T10:00:00Z","id":1}`, `{"t":"2026-10-22T10:00:09Z","id":1}`, 200, 200},
		{"类型变化", `{"id":1}`, `{"id":"1"}`, 200, 200},
		{"状态码不同", `{"id":1}`, `{"id":1}`, 200, 403},
		{"凭据字段", `{"token":"aaa","id":1}`, `{"token":"bbb","id":2}`, 200, 200},
		{"单边噪声", `{"id":"2026-10-22T10:00:00Z"}`, `{"id":"42"}`, 200, 200},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fa := filepath.Join(dir, "case_a.json")
			fb := filepath.Join(dir, "case_b.json")
			if err := os.WriteFile(fa, []byte(c.a), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fb, []byte(c.b), 0o644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(python, scriptPath, fa, fb,
				itoa(c.sa), itoa(c.sb))
			raw, err := cmd.Output()
			if err != nil {
				t.Fatalf("python 执行失败: %v", err)
			}
			var pyOut map[string]any
			if err := json.Unmarshal(raw, &pyOut); err != nil {
				t.Fatalf("python 输出不是 JSON: %v\n%s", err, raw)
			}
			goOut := diffResponse(c.sa, c.sb, c.a, c.b)

			// 逐字段比：键集合、噪声清单、值差异条数与内容、可枚举判定。
			pyKeysA := stringsOf(pyOut["keys_only_in_a"])
			pyKeysB := stringsOf(pyOut["keys_only_in_b"])
			if !equalStrings(pyKeysA, goOut.KeysOnlyInA) {
				t.Errorf("only-in-A 不一致: python=%v go=%v", pyKeysA, goOut.KeysOnlyInA)
			}
			if !equalStrings(pyKeysB, goOut.KeysOnlyInB) {
				t.Errorf("only-in-B 不一致: python=%v go=%v", pyKeysB, goOut.KeysOnlyInB)
			}
			pyNoise := stringsOf(pyOut["noise_keys"])
			if !equalStrings(pyNoise, goOut.NoiseKeys) {
				t.Errorf("噪声清单不一致: python=%v go=%v", pyNoise, goOut.NoiseKeys)
			}
			pyDiffs, _ := pyOut["value_diffs"].([]any)
			if len(pyDiffs) != len(goOut.ValueDiffs) {
				t.Errorf("值差异条数不一致: python=%d go=%d", len(pyDiffs), len(goOut.ValueDiffs))
			} else {
				for i := range pyDiffs {
					pd, _ := pyDiffs[i].(map[string]any)
					gd := goOut.ValueDiffs[i]
					if pd["key"] != gd.Key {
						t.Errorf("第 %d 条差异的键不一致: python=%v go=%v", i, pd["key"], gd.Key)
					}
					if pd["kind_a"] != gd.KindA || pd["kind_b"] != gd.KindB {
						t.Errorf("第 %d 条差异的类型不一致: python=%v/%v go=%s/%s",
							i, pd["kind_a"], pd["kind_b"], gd.KindA, gd.KindB)
					}
					if pd["preview_a"] != gd.PreviewA || pd["preview_b"] != gd.PreviewB {
						t.Errorf("第 %d 条差异的预览不一致: python=%v/%v go=%q/%q",
							i, pd["preview_a"], pd["preview_b"], gd.PreviewA, gd.PreviewB)
					}
				}
			}
			if pyOut["enumerable"] != goOut.Enumerable {
				t.Errorf("可枚举判定不一致: python=%v go=%v", pyOut["enumerable"], goOut.Enumerable)
			}
			if pyOut["same_shape"] != goOut.SameShape {
				t.Errorf("形状判定不一致: python=%v go=%v", pyOut["same_shape"], goOut.SameShape)
			}
		})
	}
}

// Python 侧也要能剥 HTTP 头并取状态码。
func TestDiffScriptStripsHTTPHeader(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteDiffScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	f := filepath.Join(dir, "h.txt")
	if err := os.WriteFile(f, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "h2.txt")
	if err := os.WriteFile(other, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, scriptPath, f, other).Output()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("输出不是 JSON: %v\n%s", err, out)
	}
	if m["status_a"] != float64(201) {
		t.Errorf("应从 HTTP 头取到状态码 201，实际 %v", m["status_a"])
	}
	if m["same_shape"] != true {
		t.Errorf("剥头后内容相同，same_shape 应为 true，实际 %v", m["same_shape"])
	}
}

// diff_responses 必须进到三个工具集——
// 它是 vuln-hunting 三个维度的共同基础，少绑一个 agent 就少一条挖掘路径。
func TestDiffResponsesRegisteredInAllToolSets(t *testing.T) {
	ts := NewToolSet(nil, "")
	has := func(list []actool.CoreTool) bool {
		for _, c := range list {
			if c.Name() == "diff_responses" {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools()) {
		t.Error("worker 工具集里没有 diff_responses")
	}
	if !has(ts.PlannerTools()) {
		t.Error("planner 工具集里没有 diff_responses")
	}
	if !has(ts.MainAgentTools()) {
		t.Error("mainagent 工具集里没有 diff_responses")
	}
	if !has(ts.AllDomainTools()) {
		t.Error("AllDomainTools 里没有 diff_responses")
	}
}

// 端到端：真起一个 HTTP 服务（存在/不存在两个端点），用真实 curl 取回响应存成文件，
// 再调 diff_responses 验证完整链路。
//
// 为什么要有这一条：前面几条测的都是「构造好的输入 → 算出的差异」，
// 抓不到「存下来的文件根本不是它以为的样子」这类问题——比如 curl 存的是
// 完整响应（含 HTTP 头），而工具当成纯响应体，那状态码就永远解析不出来。
func TestDiffResponsesEndToEndWithRealHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/1001": // 存在
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"id":1001,"name":"bob","email":"bob@x.com","role":"admin"}`)
		case "/user/999999": // 不存在
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not found"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	// 用 curl 取回响应（模拟 agent 的真实动作：curl -i 存完整响应）。
	for _, c := range []struct{ name, id string }{
		{"exists.txt", "1001"},
		{"missing.txt", "999999"},
	} {
		out := filepath.Join(dir, c.name)
		cmd := exec.Command("curl", "-sS", "-i", "-o", out, srv.URL+"/user/"+c.id)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("curl 不可用: %v %s", err, b)
		}
	}

	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})
	in, _ := json.Marshal(map[string]any{"file_a": "exists.txt", "file_b": "missing.txt"})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("工具报错: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	diff, _ := out["diff"].(map[string]any)

	// 状态码必须从 HTTP 头解析出来（curl -i 存的是完整响应）。
	if diff["status_a"] != float64(200) {
		t.Errorf("A 状态码应为 200，实际 %v", diff["status_a"])
	}
	if diff["status_b"] != float64(404) {
		t.Errorf("B 状态码应为 404，实际 %v", diff["status_b"])
	}
	if diff["status_known"] != true {
		t.Error("状态码应被识别为已知")
	}
	if diff["same_status"] != false {
		t.Error("状态码应不同")
	}
	// 键集合不同 → 可枚举。
	keysA := stringsOf(diff["keys_only_in_a"])
	if len(keysA) != 4 {
		t.Errorf("A 侧应多出 4 个键，实际 %v", keysA)
	}
	if diff["enumerable"] != true {
		t.Error("应判定可枚举")
	}
}

// --- 小工具 ---

// pythonCommand 定位 python3（找不到就跳过需要真跑 python 的测试）。
func pythonCommand(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("找不到 python，跳过脚本对照测试")
	return ""
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// toolResultText 取工具结果的文本内容。
func toolResultText(t *testing.T, res actool.Result) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// toolResultJSON 解析工具结果的 JSON。
func toolResultJSON(t *testing.T, res actool.Result) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &m); err != nil {
		t.Fatalf("工具结果不是 JSON: %v\n%s", err, toolResultText(t, res))
	}
	return m
}

func stringsOf(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
