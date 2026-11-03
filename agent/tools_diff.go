package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/c1ayooo/4zreco/intercept"
)

// 响应差分工具：把两个 HTTP 响应的**结构性差异**算出来。
//
// ## 为什么需要它
//
// vuln-hunting 的三个核心维度靠的都是同一个动作——**对比**：
//
//   - **越权**：拿 A 身份访问对象 X、拿 B 身份访问对象 X，比响应差异
//     （A 拿到 200 + 数据、B 拿到 403/空 → 越权成立）
//   - **可枚举**：对 id=1..N 逐个请求，比「存在」与「不存在」的响应差异
//     （状态码/长度/JSON 键集合不同 → 可枚举）
//   - **状态机**：同一接口在不同状态下调用，比响应差异（前置状态没校验）
//
// 现状是模型每次都要**手写 python 做 diff**——既要写对（JSON 键序、空值、
// 嵌套结构、时间戳这类噪声都要滤掉），又费 token，而且写出来的东西不可复用。
//
// ## 两种用法
//
//   A) **文件模式**：模型已经用 curl 把两个响应存成文件（工作目录下的相对路径），
//      工具**直接读文件算 diff**——不联网、不写脚本、不发请求。
//   B) **URL 模式**：还没取响应。工具在**本次 run 的工作目录**里写出差分脚本，
//      返回一条「取两段响应 + 做差分」的命令交给 Bash 执行。
//      走 Bash 是刻意的：请求经过记录代理、经过审批管控、留痕——与平台其他
//      出网动作同一套语义。工具自己发请求会绕过整条管控链。
//
// ## 判据
//
// 差异**本身不是漏洞**——时间戳、请求 id、随机 nonce、长度微小的差异都是噪声。
// 工具做的是**把噪声滤掉、只留结构性差异**，让模型判断「这个差异是不是有意义」。
//
// 滤掉的东西（明确的噪声清单）：
//   - 键**顺序**不同（JSON 语义相同）
//   - 值只在**非结构位置**不同：时间戳、trace id、请求 id、随机串
//   - 键的**增删**会保留（这是最有信息量的差异——多了个字段往往就是越权）
//
// 不滤的：状态码、JSON 键集合、值的类型、响应体整体长度。

// diffArgs 是工具入参。
type diffArgs struct {
	FileA   string `json:"file_a"`
	FileB   string `json:"file_b"`
	URLA    string `json:"url_a"`
	URLB    string `json:"url_b"`
	HeaderA string `json:"header_a"`
	HeaderB string `json:"header_b"`
	StatusA int    `json:"status_a"`
	StatusB int    `json:"status_b"`
}

// responseDiff 是两段响应之间的结构性差异。
type responseDiff struct {
	// StatusA / StatusB 是两个响应的 HTTP 状态码（0 = 未知）。
	StatusA int `json:"status_a"`
	StatusB int `json:"status_b"`
	// StatusKnown 为 true 表示状态码确实拿到了（不是「两边都没给」）。
	// 为 false 时 SameStatus 无意义——不能拿 0==0 冒充「状态码相同」。
	StatusKnown bool `json:"status_known"`
	// SameStatus 为 true 表示状态码相同（仅 StatusKnown 为 true 时有意义）。
	SameStatus bool `json:"same_status"`
	// LenA / LenB 是响应体字节数。
	LenA int `json:"len_a"`
	LenB int `json:"len_b"`
	// KeysOnlyInA / KeysOnlyInB 是只出现在一侧的 JSON 顶层键。
	KeysOnlyInA []string `json:"keys_only_in_a"`
	KeysOnlyInB []string `json:"keys_only_in_b"`
	// SameShape 为 true 表示两边的 JSON 顶层键集合完全相同（结构一致）。
	SameShape bool `json:"same_shape"`
	// ValueDiffs 是同名字段里值不同的项（值本身截断）。
	ValueDiffs []ValueDiff `json:"value_diffs"`
	// NoiseKeys 是被判定为噪声（值形似时间戳/id/随机串）而略过的字段。
	NoiseKeys []string `json:"noise_keys"`
	// Enumerable 为 true 表示这组差异**支持「可枚举」判断**——
	// 状态码不同或键集合不同，且不是纯长度差。
	Enumerable bool `json:"enumerable"`
	// Note 是给模型的一句话提示（该看什么）。
	Note string `json:"note"`
}

// ValueDiff 是同名字段的值差异。
type ValueDiff struct {
	Key string `json:"key"`
	// KindA / KindB 是值的类型名（string/number/bool/null/object/array）。
	KindA string `json:"kind_a"`
	KindB string `json:"kind_b"`
	// PreviewA / PreviewB 是截断后的值预览（敏感值会被抹掉）。
	PreviewA string `json:"preview_a"`
	PreviewB string `json:"preview_b"`
	// Sensitive 为 true 表示该字段的值被判定为敏感（凭据类），预览已抹掉。
	Sensitive bool `json:"sensitive"`
}

// diffResponse 算两个响应的结构性差异。
func diffResponse(statusA, statusB int, bodyA, bodyB string) responseDiff {
	d := responseDiff{
		StatusA: statusA, StatusB: statusB,
		StatusKnown: statusA != 0 || statusB != 0,
		SameStatus: statusA == statusB,
		LenA:       len(bodyA), LenB: len(bodyB),
	}
	objA, okA := parseJSONObject(bodyA)
	objB, okB := parseJSONObject(bodyB)

	if okA && okB {
		keysA := sortedKeys(objA)
		keysB := sortedKeys(objB)
		setA := map[string]bool{}
		for _, k := range keysA {
			setA[k] = true
		}
		setB := map[string]bool{}
		for _, k := range keysB {
			setB[k] = true
		}
		for _, k := range keysA {
			if !setB[k] {
				d.KeysOnlyInA = append(d.KeysOnlyInA, k)
			}
		}
		for _, k := range keysB {
			if !setA[k] {
				d.KeysOnlyInB = append(d.KeysOnlyInB, k)
			}
		}
		d.SameShape = len(d.KeysOnlyInA) == 0 && len(d.KeysOnlyInB) == 0

		// 逐键比值。
		for _, k := range keysA {
			if !setB[k] {
				continue
			}
			va, vb := objA[k], objB[k]
			if sameJSONValue(va, vb) {
				continue
			}
			if looksLikeNoise(va) && looksLikeNoise(vb) {
				d.NoiseKeys = append(d.NoiseKeys, k)
				continue
			}
			vd := ValueDiff{
				Key:      k,
				KindA:    jsonKind(va),
				KindB:    jsonKind(vb),
				PreviewA: valuePreview(va),
				PreviewB: valuePreview(vb),
			}
			if isSensitiveKey(k) {
				vd.Sensitive = true
				vd.PreviewA = "***"
				vd.PreviewB = "***"
			}
			d.ValueDiffs = append(d.ValueDiffs, vd)
		}
	} else {
		// 非 JSON（HTML/文本）：只能比长度与是否相等。
		d.SameShape = strings.TrimSpace(bodyA) == strings.TrimSpace(bodyB)
	}

	sort.Strings(d.KeysOnlyInA)
	sort.Strings(d.KeysOnlyInB)
	sort.Strings(d.NoiseKeys)

	// 可枚举判定：状态码不同，或键集合不同——纯长度微差不算。
	// 状态码未知时不参与判定（不能拿 0==0 冒充「状态码相同」）。
	d.Enumerable = (d.StatusKnown && !d.SameStatus) ||
		len(d.KeysOnlyInA) > 0 || len(d.KeysOnlyInB) > 0

	switch {
	case !d.StatusKnown:
		d.Note = "**状态码未知**（未提供且响应里没有 HTTP 头）——先看键集合差异；" +
			"若要判断可枚举，请带上状态码或用 curl -i 保存完整响应。"
	case !d.SameStatus:
		d.Note = "状态码不同——若一个是 200 另一个是 403/404，且**同一个身份**访问的，" +
			"说明该对象对当前身份可见性不同（横向越权或可枚举）。"
	case len(d.KeysOnlyInA) > 0 || len(d.KeysOnlyInB) > 0:
		d.Note = "键集合不同——多出来的字段往往就是**本不该看到的字段**（越权拿到的数据）。" +
			"看多出来的键是什么。"
	case len(d.ValueDiffs) > 0:
		d.Note = "结构相同但值不同——若差异字段是权限/状态类（role/status/owner/level），" +
			"说明同一接口对不同对象返回了不同内容（越权）。若值是业务数据本身，说明正常。"
	default:
		d.Note = "无结构性差异（差异都在噪声字段里）——这两次请求的响应在语义上等价。"
	}
	return d
}

// parseJSONObject 尝试把 body 解析成 JSON 对象。
func parseJSONObject(body string) (map[string]any, bool) {
	body = strings.TrimSpace(body)
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return nil, false
	}
	return m, true
}

// sortedKeys 返回排序后的键。
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameJSONValue 判断两个 JSON 值是否相等。
//
// **类型敏感**：数字 1 与字符串 "1" 不相等（fmt.Sprintf 比较会把它们判成相等，
// 那是错的——模型会把「字段类型变了」这个结构差异漏掉）。对象/数组用 DeepEqual
// （map 的 fmt 输出顺序随机，逐字节比会误判）。
func sameJSONValue(a, b any) bool {
	if jsonKind(a) != jsonKind(b) {
		return false
	}
	switch av := a.(type) {
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case nil:
		return true
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	default:
		return reflect.DeepEqual(a, b)
	}
}

// noiseValuePatterns 是「值长得像噪声」的判据。
//
// 匹配的是**值的形态**而不是键名——因为时间戳/id 这类字段的键名五花八门
// （created_at / ts / requestId / _id / trace…），按键名过滤会漏。
var noiseValuePatterns = []string{
	`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`, // ISO 时间戳
	`^\d{10,13}$`, // 毫秒/秒级时间戳
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, // UUID
	`^[0-9a-f]{16,}$`,            // 长十六进制（trace id / hash）
	`^[A-Za-z0-9+/]{20,}={0,2}$`, // base64 串
}

// noiseValueRe 由 noiseValuePatterns 编译（包级初始化，避免每次调用重编译）。
var noiseValueRe = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(noiseValuePatterns))
	for _, p := range noiseValuePatterns {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}()

// looksLikeNoise 判断一个值是否「形似噪声」。
//
// 只有**两边都**像噪声才算噪声差异（单边像噪声说明另一边的值是有意义的）。
func looksLikeNoise(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, re := range noiseValueRe {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// sensitiveWords 是「这个词本身就足以判定为凭据」。
//
// 刻意**不含** `key` 与 `session`：
//   - 裸 `key` 多半是业务字段（cache_key / sort_key / object_key / key_id）
//   - 裸 `session` 同理（session_count / session_duration）
// 误判的代价是**有害**的：真值被抹掉，模型看不到差异内容就下不了判断。
// 这两个词靠下面的限定规则处理（api_key / session_id）。
var sensitiveWords = map[string]bool{
	"token": true, "jwt": true, "password": true, "passwd": true, "pwd": true,
	"passphrase": true, "secret": true, "credential": true, "credentials": true,
	"cookie": true, "authorization": true,
	// 全大写连写形态（APIKEY / SECRETKEY）——分词后是一个整词。
	"apikey": true, "secretkey": true, "privatekey": true, "accesskey": true,
	"authkey": true, "sessionkey": true, "clientsecret": true,
}

// keyQualifiers 是「key 前面带上这些词才算凭据」的限定词。
var keyQualifiers = map[string]bool{
	"api": true, "secret": true, "private": true, "access": true,
	"encryption": true, "signing": true, "master": true, "client": true,
	"app": true, "csrf": true, "xsrf": true, "auth": true,
}

// sensitiveSuffixes 是「session/auth 后面带上这些词才算凭据」的后缀。
// session_count / session_duration 不在其中——那是业务计数，不是凭据。
var sensitiveSuffixes = map[string]bool{
	"id": true, "key": true, "token": true, "value": true,
	"secret": true, "header": true, "credential": true,
}

// isSensitiveKey 判断键名是否像凭据类。
func isSensitiveKey(k string) bool {
	words := splitKeyWords(k)
	for i, w := range words {
		if sensitiveWords[w] {
			return true
		}
		if w == "key" && i > 0 && keyQualifiers[words[i-1]] {
			return true
		}
		if (w == "session" || w == "auth") && i+1 < len(words) && sensitiveSuffixes[words[i+1]] {
			return true
		}
	}
	return false
}

// splitKeyWords 把一个键名拆成小写单词。
//
// 分词点有三类，缺一不可：
//   - 分隔符：access_token → [access, token]
//   - 驼峰转折：accessToken → [access, token]
//   - 大写串末尾接小写：APIKey → [api, key]
//
// 末尾的数字被剥掉（token2 → token）——很多后端给字段加序号。
func splitKeyWords(k string) []string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.TrimRight(string(cur), "0123456789"))
			cur = cur[:0]
		}
	}
	runes := []rune(k)
	for i, ch := range runes {
		if ch == '_' || ch == '-' || ch == '.' || ch == ' ' {
			flush()
			continue
		}
		if unicode.IsUpper(ch) && len(cur) > 0 {
			prev := cur[len(cur)-1]
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			// 大写串后面接小写 → 在当前字母前断（APIKey → API | Key）
			if unicode.IsUpper(prev) && unicode.IsLower(next) {
				flush()
			} else if !unicode.IsUpper(prev) {
				// 常规驼峰（accessToken → access | Token）
				flush()
			}
		}
		cur = append(cur, ch)
	}
	flush()
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, strings.ToLower(p))
	}
	return out
}

// jsonKind 返回 JSON 值的类型名。
func jsonKind(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "unknown"
	}
}

// valuePreview 生成值的预览（截断到 60 字符）。
func valuePreview(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// diffResponses 组装一条 diff 命令（或直接算出 diff）交给模型。
//
// **只组命令/只读文件，不自己发请求**——与 scan_with_nuclei、auth_request 同一个
// 模式。请求一律由 Bash 发出，于是流量录制、审批管控、审计全部自动生效；
// 平台自己发请求会绕过整条管控链。
//
// 两种模式：
//   a) 文件模式（file_a/file_b）：工具读文件直接算——零网络、零脚本。
//   b) URL 模式（url_a/url_b）：工具在工作目录写出差分脚本，返回一条
//      「取两段响应 + 做差分」的命令。
func (t *ToolSet) diffResponses() actool.CoreTool {
	return readTool(
		"diff_responses",
		"对比两个 HTTP 响应的**结构性差异**（越权/可枚举/状态机三类判断的共同基础）。\n"+
			"用法二选一：\n"+
			"  A) 已把两个响应存成文件 → 给 file_a / file_b（工作目录下的相对路径，"+
			"也接受绝对路径；用 curl -i 保存的完整响应会自动剥掉 HTTP 头并取出状态码）\n"+
			"  B) 还没取 → 给 url_a / url_b（+ 可选 header_a/header_b），工具会生成"+
			"「取两段响应并做差分」的命令，交给 Bash 执行\n"+
			"输出：状态码是否相同、JSON 顶层键集合的差集（**只在一侧有的键往往就是越权拿到的字段**）、"+
			"同名字段的值差异（值像时间戳/id 的已标为噪声略过、凭据类字段的值已抹掉）、"+
			"以及「这组差异是否支持可枚举」的判断。\n"+
			"**差异本身不是漏洞**——工具已滤掉时间戳/trace id/随机串这类噪声，剩下的要你结合语义判断。",
		obj(map[string]any{
			"file_a":   str("响应 A 的文件路径（已取好的响应体；相对路径相对于本次 run 的工作目录）"),
			"file_b":   str("响应 B 的文件路径"),
			"url_a":    str("响应 A 的 URL（未取响应时用）"),
			"url_b":    str("响应 B 的 URL"),
			"header_a": str("请求 A 的认证头（如 'Authorization: Bearer xxx'，可选）"),
			"header_b": str("请求 B 的认证头（可选）"),
			"status_a": intp("响应 A 的状态码（知道就填，可选）"),
			"status_b": intp("响应 B 的状态码（可选）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a diffArgs
			_ = json.Unmarshal(in, &a)

			hasFiles := strings.TrimSpace(a.FileA) != "" && strings.TrimSpace(a.FileB) != ""
			hasURLs := strings.TrimSpace(a.URLA) != "" && strings.TrimSpace(a.URLB) != ""
			if !hasFiles && !hasURLs {
				return actool.Errorf("要给 file_a+file_b（已有响应文件）或 url_a+url_b（还没取）"), nil
			}

			workDir := intercept.ReviewWorkingDirectory(ctx)

			if hasFiles {
				// 文件已在手边：直接读文件算 diff（不联网、不写脚本）。
				bodyA, statusA, err := readResponseFile(workDir, a.FileA)
				if err != nil {
					return actool.Errorf("读取响应 A 失败: " + err.Error()), nil
				}
				bodyB, statusB, err := readResponseFile(workDir, a.FileB)
				if err != nil {
					return actool.Errorf("读取响应 B 失败: " + err.Error()), nil
				}
				// 模型显式给了状态码就以它为准（文件头里的可能有中间层改写）。
				if a.StatusA != 0 {
					statusA = a.StatusA
				}
				if a.StatusB != 0 {
					statusB = a.StatusB
				}
				d := diffResponse(statusA, statusB, bodyA, bodyB)
				return jsonResult(map[string]any{
					"diff":   d,
					"source": fmt.Sprintf("已读文件 %s / %s", a.FileA, a.FileB),
					"note": "输出是 JSON：状态码、键集合差集、值差异（噪声已滤、凭据已抹）、" +
						"是否支持可枚举。**差异本身不是漏洞**——结合语义判断" +
						"（多出来的键常是越权拿到的数据）。",
				})
			}

			// 还没取响应：需要工作目录来放差分脚本。
			if workDir == "" {
				return actool.Errorf("本次 run 没有绑定工作目录，无法写出差分脚本——" +
					"请改用文件模式（先用 Bash 取好两个响应并存成文件，再给 file_a/file_b）"), nil
			}
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				return actool.Errorf("创建工作目录失败: " + err.Error()), nil
			}
			scriptPath, err := WriteDiffScript(workDir)
			if err != nil {
				return actool.Errorf("写出差分脚本失败: " + err.Error()), nil
			}
			cmd := buildDiffScript(a, scriptPath, workDir)
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"script_path":   scriptPath,
				"note": "用 Bash 工具执行上面这条命令（会取两次响应并做结构化差分）。输出是 JSON。" +
					"**差异本身不是漏洞**——结合语义判断。",
			})
		},
	)
}

// readResponseFile 读一个响应文件，返回（响应体, 状态码）。
//
// 容错：文件若是 `curl -i` 保存的完整响应（含 HTTP 头），剥掉头部、
// 从状态行取状态码。若模型显式给了状态码，以它为准。
func readResponseFile(workDir, p string) (string, int, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", 0, fmt.Errorf("路径为空")
	}
	full := p
	if !filepath.IsAbs(p) {
		if workDir == "" {
			return "", 0, fmt.Errorf("没有绑定工作目录，无法解析相对路径 %q；请给绝对路径", p)
		}
		full = filepath.Join(workDir, p)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", 0, err
	}
	body, status := stripHTTPHeader(string(b))
	return body, status, nil
}

// stripHTTPHeader 剥掉响应文件开头的 HTTP 头，返回（响应体, 状态码）。
//
// 状态码取不到时返回 0（= 未知），不猜。
func stripHTTPHeader(raw string) (string, int) {
	trimmed := strings.TrimLeft(raw, " \t\r\n")
	if !strings.HasPrefix(trimmed, "HTTP/") {
		return raw, 0
	}
	// 状态行: HTTP/1.1 200 OK
	firstNL := strings.IndexAny(trimmed, "\r\n")
	if firstNL < 0 {
		return raw, 0
	}
	statusLine := trimmed[:firstNL]
	fields := strings.Fields(statusLine)
	status := 0
	if len(fields) >= 2 {
		if n, err := strconv.Atoi(fields[1]); err == nil {
			status = n
		}
	}
	rest := trimmed[firstNL:]
	// 找头与体的分隔（空行）
	for _, sep := range []string{"\r\n\r\n", "\n\n", "\r\r"} {
		if i := strings.Index(rest, sep); i >= 0 {
			return rest[i+len(sep):], status
		}
	}
	return raw, status
}

// diffScriptName 是差分脚本在 Agent 工作目录里的文件名。
//
// 脚本由平台在运行时写出（见 WriteDiffScript），agent 只管执行。
const diffScriptName = "resp_diff.py"

// buildDiffScript 生成「取两段响应 + 做差分」的 shell 命令。
//
// 三个关键点：
//   - 响应体落到**工作目录**下的文件（不是 /tmp——平台规约：中间产物不落 /tmp）。
//   - 状态码由 curl 的 -w '%{http_code}' 拿到，作为脚本参数传入。
//   - URL/认证头都做 POSIX 单引号转义——认证头里常带引号。
func buildDiffScript(a diffArgs, scriptPath, workDir string) string {
	bodyA := filepath.Join(workDir, "resp_a_body")
	bodyB := filepath.Join(workDir, "resp_b_body")
	fetch := func(url, header, out string) string {
		parts := []string{"curl", "-sS", "--max-time", "20", "-o", quoteShell(out), "-w", "%{http_code}", quoteShell(url)}
		if strings.TrimSpace(header) != "" {
			parts = append(parts, "-H", quoteShell(header))
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprintf(
		"S=$(%s) ; T=$(%s) ; python3 %s %s %s \"$S\" \"$T\"",
		fetch(a.URLA, a.HeaderA, bodyA),
		fetch(a.URLB, a.HeaderB, bodyB),
		quoteShell(scriptPath), quoteShell(bodyA), quoteShell(bodyB))
}

// quoteShell 用 POSIX 单引号包裹一个值（内部单引号按 '\'' 转义）。
func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// WriteDiffScript 把差分脚本写到工作目录，返回脚本路径。
//
// 脚本用标准库 json（无第三方依赖），做与 Go 侧 diffResponse 同一件事：
// 算状态码/键集合差集/值差异，并滤掉噪声字段、抹掉凭据类字段的值。
//
// 两份实现必须等价——agent/tools_diff_test.go 里有真跑 python 的对照测试。
func WriteDiffScript(dir string) (string, error) {
	path := filepath.Join(dir, diffScriptName)
	if err := os.WriteFile(path, []byte(diffScriptSource), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// diffScriptSource 是差分脚本的源码（与 Go 侧逻辑等价）。
const diffScriptSource = `#!/usr/bin/env python3
"""响应结构化差分（4ZRECO agent 工具 diff_responses 的执行端）。

用法: resp_diff.py <文件A> <文件B> [状态码A] [状态码B]
文件内容是响应体（或 curl -i 的完整响应，会自动剥头）；状态码可选。
输出 JSON: 状态码、键集合差集、值差异（滤掉时间戳/id 类噪声、抹掉凭据类字段）、是否可枚举。
"""
import json, re, sys

NOISE = [
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    re.compile(r"^\d{10,13}$"),
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    re.compile(r"^[0-9a-f]{16,}$"),
    re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
]
SENSITIVE_WORDS = {
    "token", "jwt", "password", "passwd", "pwd", "passphrase", "secret",
    "credential", "credentials", "cookie", "authorization",
    "apikey", "secretkey", "privatekey", "accesskey", "authkey",
    "sessionkey", "clientsecret",
}
KEY_QUALIFIERS = {
    "api", "secret", "private", "access", "encryption", "signing",
    "master", "client", "app", "csrf", "xsrf", "auth",
}
SENSITIVE_SUFFIXES = {
    "id", "key", "token", "value", "secret", "header", "credential",
}


def split_words(k):
    """把键名拆成小写单词：分隔符 / 驼峰转折 / 大写串接小写 都是断点。"""
    parts, cur = [], []

    def flush():
        if cur:
            parts.append("".join(cur).rstrip("0123456789"))
            del cur[:]

    runes = list(k)
    for i, ch in enumerate(runes):
        if ch in "_-. ":
            flush()
            continue
        if ch.isupper() and cur:
            prev = cur[-1]
            nxt = runes[i + 1] if i + 1 < len(runes) else ""
            if prev.isupper() and nxt.islower():
                flush()
            elif not prev.isupper():
                flush()
        cur.append(ch)
    flush()
    return [p.lower() for p in parts if p]


def is_sensitive_key(k):
    words = split_words(k)
    for i, w in enumerate(words):
        if w in SENSITIVE_WORDS:
            return True
        if w == "key" and i > 0 and words[i - 1] in KEY_QUALIFIERS:
            return True
        if w in ("session", "auth") and i + 1 < len(words) and words[i + 1] in SENSITIVE_SUFFIXES:
            return True
    return False


def load(p):
    try:
        with open(p, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def strip_http_header(raw):
    t = raw.lstrip(" \t\r\n")
    if not t.startswith("HTTP/"):
        return raw, 0
    i = t.find("\n")
    if i < 0:
        return raw, 0
    fields = t[:i].split()
    status = 0
    if len(fields) >= 2:
        try:
            status = int(fields[1])
        except ValueError:
            status = 0
    rest = t[i:]
    for sep in ("\r\n\r\n", "\n\n", "\r\r"):
        j = rest.find(sep)
        if j >= 0:
            return rest[j + len(sep):], status
    return raw, status


def as_obj(s):
    s = s.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        v = json.loads(s)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def kind(v):
    if v is None: return "null"
    if isinstance(v, bool): return "bool"
    if isinstance(v, (int, float)): return "number"
    if isinstance(v, str): return "string"
    if isinstance(v, dict): return "object"
    if isinstance(v, list): return "array"
    return "unknown"


def same_value(a, b):
    if kind(a) != kind(b):
        return False
    if kind(a) == "number":
        return float(a) == float(b)
    return a == b


def is_noise(v):
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return False
    return any(r.match(s) for r in NOISE)


def preview(v, limit=60):
    s = str(v)
    return s if len(s) <= limit else s[:limit] + "…"


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "用法: resp_diff.py <文件A> <文件B> [状态码A] [状态码B]"}))
        return 1
    sa = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    sb = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    raw_a, raw_b = load(sys.argv[1]), load(sys.argv[2])
    a, st_a = strip_http_header(raw_a)
    b, st_b = strip_http_header(raw_b)
    if sa == 0:
        sa = st_a
    if sb == 0:
        sb = st_b
    status_known = sa != 0 or sb != 0
    out = {
        "status_a": sa, "status_b": sb,
        "status_known": status_known,
        "same_status": sa == sb,
        "len_a": len(a), "len_b": len(b),
        "keys_only_in_a": [], "keys_only_in_b": [],
        "same_shape": False, "value_diffs": [], "noise_keys": [],
    }
    oa, ob = as_obj(a), as_obj(b)
    if oa is not None and ob is not None:
        ka, kb = set(oa), set(ob)
        out["keys_only_in_a"] = sorted(ka - kb)
        out["keys_only_in_b"] = sorted(kb - ka)
        out["same_shape"] = not out["keys_only_in_a"] and not out["keys_only_in_b"]
        for k in sorted(ka & kb):
            va, vb = oa[k], ob[k]
            if same_value(va, vb):
                continue
            if is_noise(va) and is_noise(vb):
                out["noise_keys"].append(k)
                continue
            d = {"key": k, "kind_a": kind(va), "kind_b": kind(vb),
                 "preview_a": preview(va), "preview_b": preview(vb)}
            if is_sensitive_key(k):
                d["sensitive"] = True
                d["preview_a"] = d["preview_b"] = "***"
            out["value_diffs"].append(d)
    else:
        out["same_shape"] = a.strip() == b.strip()
    out["enumerable"] = ((status_known and not out["same_status"])
                         or bool(out["keys_only_in_a"]) or bool(out["keys_only_in_b"]))
    if not status_known:
        out["note"] = "状态码未知——先看键集合差异；若要判断可枚举，请带上状态码或用 curl -i 保存完整响应"
    elif not out["same_status"]:
        out["note"] = "状态码不同——若是同一身份访问不同对象，可能是越权或可枚举"
    elif out["keys_only_in_a"] or out["keys_only_in_b"]:
        out["note"] = "键集合不同——多出来的字段常是本不该看到的数据（越权）"
    elif out["value_diffs"]:
        out["note"] = "结构相同值不同——看差异字段是否为权限/状态类"
    else:
        out["note"] = "无结构性差异"
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
`
