package agent

// http_probe：批量探活领域工具（v0.4.27）。
//
// ## 为什么需要它
//
// 任务 5 实测：Bash 占全部 tool_use 的 57%（6833 次），其中 curl 探活 2750 次、
// python3 胶水 2105 次——worker 逐条手写 curl，每个响应全文进对话（单意图均
// ≈300 万 input）。批量探活是最高频、最模式化的动作，值得一个领域工具：
// 一次调用 → 一条命令 → 每行一个紧凑 JSON（状态码/字节/title/server/类型/跳转/耗时），
// 既把 N 次 Bash 往返压成 1 次，也把响应体从「整页 HTML」压成「一行摘要」。
//
// ## 设计原则（与 auth_request / diff_responses 同款）
//
// **只落脚本 + 组命令，不自己发请求**——流量录制、审批管控、审计全部经由 Bash
// 自动生效，平台自己发请求会绕过整条管控链。
//
// 脚本幂等落盘（runDir/4zreco-probe.sh），后续调用只传 URL 列表，命令保持最短。
// 不带 --noproxy：运行环境若有录制代理（http(s)_proxy 环境变量），curl 自动走
// 代理，流量照常进流量查看器；没有则直连，与手写 curl -k 行为一致。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

const httpProbeScript = `#!/usr/bin/env bash
# 4zreco http_probe: 对每个 URL 输出一行紧凑 JSON（url/status/bytes/time_ms/title/server/content_type/redirect）
for u in "$@"; do
  f=$(mktemp); h=$(mktemp)
  out=$(curl -sS -k -L --max-time 10 -w '%{http_code} %{time_total}' -o "$f" -D "$h" "$u" 2>/dev/null)
  code=${out%% *}; tt=${out##* }
  bytes=$(wc -c < "$f" | tr -d ' ')
  ms=$(awk -v t="$tt" 'BEGIN{printf "%d", t*1000}')
  python3 - "$u" "${code:-000}" "${bytes:-0}" "${ms:-0}" "$f" "$h" <<'PYEOF'
import sys, json, re
u, code, bs, ms, body, hdr = sys.argv[1:7]
title = srv = ct = loc = ""
try:
    s = open(body, 'rb').read(65536).decode('utf-8', 'replace')
    m = re.search(r'<title[^>]*>(.*?)</title>', s, re.S | re.I)
    if m:
        title = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
except Exception:
    pass
try:
    for line in open(hdr, encoding='utf-8', errors='replace'):
        k = line.split(':', 1)
        if len(k) == 2:
            key = k[0].strip().lower()
            if key == 'server':
                srv = k[1].strip()[:80]
            elif key == 'content-type':
                ct = k[1].strip()[:80]
            elif key == 'location':
                loc = k[1].strip()[:200]
except Exception:
    pass
print(json.dumps({"url": u, "status": code, "bytes": int(bs) if bs.isdigit() else 0,
                  "time_ms": int(ms) if ms.isdigit() else 0, "title": title, "server": srv,
                  "content_type": ct, "redirect": loc}, ensure_ascii=False))
PYEOF
  rm -f "$f" "$h"
done
`

// ensureProbeScript 幂等落盘探活脚本；失败返回空串（调用方退化为让模型手写）。
func (t *ToolSet) ensureProbeScript() string {
	if strings.TrimSpace(t.runDir) == "" {
		return ""
	}
	p := filepath.Join(t.runDir, "4zreco-probe.sh")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if err := os.WriteFile(p, []byte(httpProbeScript), 0o755); err != nil {
		return ""
	}
	return p
}

// httpProbe 批量探活：给 URL 列表，返回一条可直接执行的 Bash 命令。
func (t *ToolSet) httpProbe() actool.CoreTool {
	return readTool(
		"http_probe",
		"批量 HTTP 探活（推荐替代逐条手写 curl）：一次探测一批 URL，每个 URL 输出一行紧凑 JSON"+
			"（status/bytes/time_ms/title/server/content_type/redirect）。\n"+
			"本工具返回一条 run_with_bash 命令，交给 Bash 执行即可（流量录制/审批照常生效）。"+
			"适合：批量确认未测 endpoint 存活、快速指纹（server/title/content_type）、"+
			"对照探测（同一路径多 host）。需要完整响应体做深入分析时仍用 curl 手工取，"+
			"本工具只给概要。",
		obj(map[string]any{
			"urls": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "要探测的 URL 列表（1-40 个，绝对地址）",
			},
		}, "urls"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URLs []string `json:"urls"`
			}
			_ = json.Unmarshal(in, &a)
			urls := make([]string, 0, len(a.URLs))
			seen := map[string]bool{}
			for _, u := range a.URLs {
				u = strings.TrimSpace(u)
				if u == "" || seen[u] || (!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://")) {
					continue
				}
				seen[u] = true
				urls = append(urls, u)
				if len(urls) >= 40 {
					break
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("urls 至少要有一个合法的 http(s) 绝对地址"), nil
			}
			script := t.ensureProbeScript()
			if script == "" {
				return actool.Errorf("http_probe 未启用: 本次 run 没有可用的工作目录"), nil
			}
			quoted := make([]string, len(urls))
			for i, u := range urls {
				quoted[i] = "'" + strings.ReplaceAll(u, "'", `'\''`) + "'"
			}
			return jsonResult(map[string]any{
				"run_with_bash": fmt.Sprintf("bash %s %s", script, strings.Join(quoted, " ")),
				"count":         len(urls),
				"note":          "输出每行一个 JSON：url/status/bytes/time_ms/title/server/content_type/redirect。结论照常 record_fact（会自动锚定命中资产）。",
			})
		})
}
