package agent

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// toolLogHooks 把「谁在什么任务下调用了什么工具、结果如何、怎么收场」写进 journal。
//
// 为什么需要它：worker/planner/main 的工具调用此前**完全不可观测**——journal 里只有
// planner 的心跳和 vulnintel 的刷屏，worker 到底在不在干活、卡在哪一步、有没有报错，
// 都只能去翻 transcripts/*.jsonl 的 mtime 才能确认。调优循环（抓日志→看工具使用→
// 调参数）没有这层信号就等于闭眼调。
//
// 设计取舍：
//   - **不打全量命令/输出**。Bash 命令动辄几百字节、工具输出可达几十 KB，全打会把
//     journal 撑爆并拖慢磁盘。只打【首行摘要 + 字节数】+【结果分类】。
//   - **结果分类而非原文**。ok/error/blocked 三态是调优最需要的信号（判断模型是不是
//     在撞 WAF、是不是工具报参数错），原文去 transcript 看。
//   - **每次调用两行**（pre + post）。pre 行给出"要做什么"，post 行给出"做成了吗"。
//     两行都有才能把"卡在调用前"（模型没输出工具）和"卡在调用后"（工具失败）分开。
//
// 它是纯旁路：不拦截、不改输入、不影响决策。判空返回即可。
type toolLogHooks struct {
	// kind 是 agent 角色标签（planner/worker/main/chat），用于日志前缀。
	kind string
	// label 是更具体的运行标签（如 "worker-1 · #42"），可选。
	label string
	// inner 是已有的 hook 链（拦截管控），本层只做旁路观察后转发。
	inner harness.HookRunner
}

// toolLogSink 构造一个只观察不干预的 hook 链（无 inner）。
func toolLogSink(kind string) *toolLogHooks {
	return &toolLogHooks{kind: kind}
}

// wrapToolLog 把日志层套在已有 hook 链外层：先记日志，再转发给 inner。
// inner 为 nil 时本层就是全部。
func wrapToolLog(inner harness.HookRunner, kind string, label string) *toolLogHooks {
	return &toolLogHooks{kind: kind, label: label, inner: inner}
}

// PreToolUse 记录一次工具调用的开始。
//
// 顺序很重要：**先转发给 inner，再记日志**。因为 inner（拦截/steer）会返回
// 「这次调用被拦了」，日志层需要知道这个结果才能准确标注——
//
//	先记后转发 → 日志只说「要调这个工具」，实际有没有被拦是猜的；
//	先转发后记 → 日志直接标 BLOCKED。
//
// 而「被拦」的判据必须是【平台自己的拦截决定】，不是输出里出现 403/denied
// 这类字样——实测生成漏洞报告的命令（输出里含漏洞描述）被误判成 blocked。
func (h *toolLogHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	var (
		block   bool
		message string
		updated []byte
	)
	if h.inner != nil {
		block, message, updated = h.inner.PreToolUse(ctx, name, input)
	}
	tag := ""
	if block {
		tag = " BLOCKED"
	}
	log.Printf("%s → %s%s %s", h.prefix(ctx), name, tag, summarizeToolInput(name, input))
	return block, message, updated
}

// PostToolUse 记录一次工具调用的结果。
func (h *toolLogHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	h.logPost(ctx, name, input, result, isErr)
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

// Stop 记录一次 run 的收场。
func (h *toolLogHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	h.logStop(ctx, messages)
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}

// --- 日志行 ---

func (h *toolLogHooks) prefix(ctx context.Context) string {
	ri := RunInfoFrom(ctx)
	kind := ri.Kind
	if kind == "" {
		kind = h.kind
	}
	p := "[tool] " + kind
	if h.label != "" {
		p += " " + h.label
	}
	switch {
	case ri.TaskID != 0:
		p += " task=" + strconv.FormatInt(ri.TaskID, 10)
	case ri.SessionID != "":
		p += " session=" + shortID(ri.SessionID)
	}
	if ri.ExplorationID != 0 {
		p += " exp=" + strconv.FormatInt(ri.ExplorationID, 10)
	}
	if ri.IntentID != 0 {
		p += " intent=#" + strconv.FormatInt(ri.IntentID, 10)
	}
	return p
}

func (h *toolLogHooks) logPost(ctx context.Context, name string, input, result []byte, isErr bool) {
	log.Printf("%s ← %s %s out=%dB", h.prefix(ctx), name, classifyToolResult(name, result, isErr), len(result))
}
// logStop 打收场行：最后一个助手回合有没有正文/工具调用。这是区分
// 「正常做完」「空转收场」「模型报错」的第一手信号。
func (h *toolLogHooks) logStop(ctx context.Context, messages []llm.Message) {
	var textLen int
	var tools int
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		textLen = len(strings.TrimSpace(m.Text()))
		tools = len(m.ToolUses())
		break
	}
	log.Printf("%s ⏹ stop text=%dB tools=%d msgs=%d", h.prefix(ctx), textLen, tools, len(messages))
}

// --- 工具输入/结果的摘要 ---

// summarizeToolInput 给出工具入参的一行摘要。命令只取第一行（去掉前导空白）并限长，
// 避免把整条多行脚本塞进 journal。
func summarizeToolInput(name string, input []byte) string {
	if len(input) == 0 {
		return ""
	}
	switch name {
	case "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil && in.Command != "" {
			return cmdHead(in.Command)
		}
	case "record_fact", "report_finding", "insert_assets", "record_asset":
		var in struct {
			Type  string `json:"type"`
			Title string `json:"title"`
			Kind  string `json:"kind"`
			Name  string `json:"name"`
		}
		if json.Unmarshal(input, &in) == nil {
			var bits []string
			for _, s := range []string{in.Type, in.Kind, in.Name, in.Title} {
				if s != "" {
					bits = append(bits, trunc(s, 48))
				}
			}
			if len(bits) > 0 {
				return strings.Join(bits, " ")
			}
		}
	}
	// 兜底：整体 JSON 压成一行并限长。空对象/空数组没有信息量，返回空串而不是 "{}"。
	s := strings.Join(strings.Fields(string(input)), " ")
	if s == "{}" || s == "[]" {
		return ""
	}
	return trunc(s, 96)
}

// cmdHead 取命令的第一行，限长 96 字符。
func cmdHead(cmd string) string {
	line := cmd
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return trunc(redactSecrets(strings.TrimSpace(line)), 96)
}

// redactSecrets 把命令行里出现的凭据换成 ***。
//
// 为什么要脱敏：agent 的命令里带着真实口令（sshpass -p 'xxx'、mysql -p xxx、
// Authorization: Bearer xxx），而工具日志会把命令摘要写进 journal——**口令就
// 进了系统日志**，而 journal 默认所有用户可读、还会被 journalctl 导出。
// 实测抓到过 `sshpass -p 'dolphin!@#'` 原样进日志。
//
// 只做「形状明确」的替换，不做通用密钥识别：宁可漏脱敏（仍会打码的粗粒度），
// 也不能把正常参数误伤成 ***，否则日志失去可读性。
func redactSecrets(s string) string {
	for _, p := range secretPatterns {
		s = p.re.ReplaceAllString(s, p.rep)
	}
	return s
}

// secretPatterns 匹配「键=值」形态的凭据。每条规则自带替换串：分组 1 是
// 【要保留的前缀】，值部分被换成 ***（URL 那条额外保留 group 3 的 @host）。
var secretPatterns = []struct {
	re  *regexp.Regexp
	rep string
}{
	// sshpass -p 'xxx' / sshpass -p xxx / sshpass -pxxx
	{regexp.MustCompile(`(?i)(sshpass\s+-p\s*)('[^']*'|"[^"]*"|\S+)`), "${1}***"},
	// key=value / key: value（限定常见凭据键名，避免误伤）
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|pass|secret|token|apikey|api_key|access_key|auth[_-]?key)\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s&;]+)`), "${1}***"},
	// Authorization: Bearer xxx / Basic xxx
	{regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|basic)\s+)('[^']*'|"[^"]*"|\S+)`), "${1}***"},
	// URL 里的 user:pass@host（保留 scheme 与 user，只打码口令）
	{regexp.MustCompile(`(?i)(://[^:/@\s]+:)([^@\s/]+)(@)`), "${1}***${3}"},
	// mysql/psql 的 -p 口令形式。
	//
	// **必须限定命令**：`--password` 这类带字母的写法没有歧义，但裸 `-p` 在不同
	// 命令里含义不同——sshpass/mysql/psql 的 -p 是口令，mkdir/tar 的 -p 是
	// "parents"/"preserve"。通用化会误伤，实测 `mkdir -p /some/dir` 的路径被打成 ***。
	{regexp.MustCompile(`(?i)((?:^|[\s;|&])(?:mysql|mysqldump|psql|pg_dump|mariadb)\s+[^\n;|&]*?\s-p\s*)('[^']*'|"[^"]*"|\S+)`), "${1}***"},
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// reToolBlocked 识别「目标侧拦截」的典型措辞（WAF/403/验证码/限流）。与 guard 的
// 归因正则同源，但这里只用于打标签，不参与决策。
var reToolBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied|too many requests)\b`)

// platformBlockMarker 是平台拦截消息的固定前缀（见 guard.systemBlockMessage）。
// 出现它 = 这次调用被 4ZRECO 自己拦了，与目标侧的 WAF 是两回事。
const platformBlockMarker = "【4ZRECO 平台管控·非目标防御】"

// classifyToolResult 把工具结果压成一个分类标签。
//
// 语义分层，别混：
//   - blocked：平台**自己**拦了这次调用。判据是 4ZRECO 的固定前缀，精确可靠。
//     （PreToolUse 行会标 BLOCKED，这里是兜底——理论上被拦的调用不会有 post 行。）
//   - waf：输出里出现 WAF/403/denied 措辞，**只对 Bash 生效**。Bash 是打目标的，
//     命令输出里的 403 说明被目标挡了——这是给 planner 做归因的有用信号。
//     但数据类工具（list_findings/list_assets）的输出里出现 403/denied 往往只是
//     **漏洞描述本身**，实测 30KB 的漏洞列表和一份漏洞报告都被误判过。
//   - error：工具执行报错。
//   - ok：其余。
//
// 为什么不把 waf 折进 blocked：实测「生成漏洞报告」的命令（输出含漏洞描述）
// 被判成 blocked，而「被平台拦截」是完全不同的语义——前者是正常干活，后者是
// 被平台管控。混在一起会让 blocked 的计数完全失去意义。
func classifyToolResult(name string, result []byte, isErr bool) string {
	s := string(result)
	if isErr {
		return "error"
	}
	if strings.Contains(s, platformBlockMarker) {
		return "blocked"
	}
	if name == "Bash" && reToolBlocked.MatchString(s) {
		return "waf"
	}
	return "ok"
}
