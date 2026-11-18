package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/c1ayooo/4zreco/internal/vulnintel"
)

const (
	// nucleiOutputMaxBytes 是 JSONL 文件读取上限：一次 10 分钟扫描的输出正常 <1MB。
	nucleiOutputMaxBytes = 8 << 20
	// nucleiOutputDefaultHits 是回给模型的结构化命中条数上限——超出的只给计数，
	// 避免一次命中几百条时把上下文灌满。
	nucleiOutputDefaultHits = 50
)

var nucleiOutputExts = map[string]bool{".jsonl": true, ".json": true, ".txt": true, ".log": true}

// parseNucleiOutput 把 nuclei 的 JSONL 输出解析成结构化命中（第三批 J7）。
//
// 为什么要它：`scan_with_nuclei` 只组命令不执行，Bash 跑完拿到的是原始 JSONL 行。
// 直接贴进对话既费 token，又会把 Cookie/Authorization 带进观测面，还看不出"同一个
// 模板在多少个端点命中、严重度怎么分布"。这里一次调用给出：按 template_id+matched_at
// 去重后的命中、severity 分布、坏行计数，并对报文做凭据脱敏。
func (t *ToolSet) parseNucleiOutput() actool.CoreTool {
	return readTool(
		"parse_nuclei_output",
		"解析 nuclei 的 JSONL 输出（scan_with_nuclei 给出的命令跑完后 Bash 的 stdout，建议重定向到文件）。"+
			"返回结构化命中（template_id/name/severity/host/matched_at/extracted，报文已抹掉 Cookie/Authorization 值）、"+
			"按 template_id+matched_at 去重后的条数、severity 分布与坏行计数。空输出=无命中（不是错误）。"+
			"建议链路：scan_with_nuclei 拿命令 → Bash 执行并重定向到文件 → 本工具解析 → assess_nuclei_hit 判证据强度 → report_finding。",
		obj(map[string]any{
			"path":  str("本意图工作目录内的 JSONL 文件路径（相对路径或目录内绝对路径，.jsonl/.json/.txt/.log，≤8MB）"),
			"text":  str("直接给 JSONL 原文（与 path 二选一）"),
			"limit": intp("最多返回多少条结构化命中，默认 50（其余只给计数）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path  string `json:"path"`
				Text  string `json:"text"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)

			// 注意：text 只看「是否给了」而不 TrimSpace——nuclei 空输出（纯换行/空格）
			// 是合法输入，代表「无命中」，必须能走到解析层给出空结果。
			path, text := strings.TrimSpace(a.Path), a.Text
			if path != "" && strings.TrimSpace(text) != "" {
				return actool.Errorf("path 与 text 只能给一个"), nil
			}
			src := "text"
			if path != "" {
				data, rel, err := readWorkspaceFile(t.runDir, path, nucleiOutputExts, nucleiOutputMaxBytes)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				text, src = string(data), rel
			} else if text == "" {
				return actool.Errorf("path 与 text 至少给一个"), nil
			}

			hits, stats, err := vulnintel.ParseNucleiJSONL(text)
			if err != nil {
				return actool.Errorf("解析失败: " + err.Error()), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = nucleiOutputDefaultHits
			}
			shown := hits
			truncated := false
			if len(shown) > limit {
				shown = shown[:limit]
				truncated = true
			}
			res := map[string]any{
				"source":     src,
				"hits":       shown,
				"stats":      stats,
				"truncated":  truncated,
				"total_hits": len(hits),
				"note":       "hits 已按 template_id+matched_at 去重并脱敏；空 hits 表示没有模板命中（空输出不是错误）。上报前用 assess_nuclei_hit 逐条判证据强度：只匹配状态码/无响应正文的命中会被判 needs_review。",
			}
			if len(hits) == 0 {
				res["note"] = "没有解析到任何命中：" +
					"①nuclei 空输出=无模板命中；②输出里有非 JSON 行（看 stats.skipped）；" +
					"③命令没带 -jsonl / -json。确认后再决定换模板、换目标或换扫描参数。"
			}
			return jsonResult(res)
		},
	)
}
