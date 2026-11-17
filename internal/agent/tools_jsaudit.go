package agent

// js_audit：SPA/webpack 前端源码泄露审计领域工具（v0.4.64 批次，移植自上游
// 0.4.59 tools_jsaudit.go）。
//
// ## 为什么需要它
//
// worker 对前端往往只有 api-recon 的 JS 逆向前文，没有系统性的 sourcemap 检测
// ——`//# sourceMappingURL=x.js.map` 指向的 .map 若公开（webpack
// productionSourceMap 未关），sourcesContent 里是**完整原始源码**（Vue SFC/接口/
// 密钥/内网地址），属 CWE-540 源码信息泄露，即可报 high；密钥命中直接 critical。
// 依赖模型"想起来"去 curl .map 不可靠——做成领域工具，一次调用出全链路结论。
//
// ## 检测链（脚本内实现，stdlib only）
//
// 1. 入口 HTML → 提取 <script src> / modulepreload；
// 2. 每个 JS：读尾部 sourceMappingURL（外链或 data:base64 内联）；无提示也探测
//    <js>.map 兜底；从 bundle 里再挖 hash 命名的 chunk（上限内入队）；
// 3. .map 是 JSON 且含 sources → 还原目录落盘（.vue/.env/config 计数），密钥与
//    接口/路由扫描（AKIA/私钥/JWT/AK-SK kv/内网段/URL/API path/router path）；
// 4. 每行一个 JSON 事件，summary 收尾——worker 照常 record_fact / report_finding。
//
// ## 设计原则（与 auth_request 同款）
//
// **只落脚本 + 组命令，不自己发请求**——流量录制、审批管控、审计全部经由 Bash
// 自动生效（http(s)_proxy 环境变量让 python urllib 走记录代理）。
//
// 密钥模式库：与 proton_secrets（tools_zombie_proton.go）同一套观测口径——
// 命中先 record_fact，确认是真实凭据再升级报告；命中原文不进 trace。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

const jsAuditScript = `#!/usr/bin/env python3
"""4zreco js_audit: SPA/webpack 前端源码泄露审计。

用法: python3 4zreco-jsaudit.py --out <outdir> <url1> [url2 ...]
url 可以是入口 HTML（提取 <script src>）或 .js 文件本体。
每行输出一个 JSON 事件；最后一行 type=summary。仅标准库；
http(s)_proxy 环境变量自动生效（流量走记录代理）；证书校验关闭（同 curl -k）。
"""
import sys, os, json, re, base64, ssl, urllib.request, urllib.parse

MAX_BYTES = 3_000_000
MAX_MAP_BYTES = 12_000_000
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
      "Accept-Encoding": "identity"}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx))

def fetch(url, cap=MAX_BYTES):
    req = urllib.request.Request(url, headers=UA)
    with _opener.open(req, timeout=15) as r:
        return r.getcode(), r.read(cap + 1), r.geturl()

def emit(obj):
    print(json.dumps(obj, ensure_ascii=False))
    sys.stdout.flush()

SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
PRELOAD_RE = re.compile(r'<link[^>]+(?:modulepreload|preload)[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', re.I)
SMU_RE = re.compile(r'[#@]\s*sourceMappingURL=([^\s\'"]+)')
URL_RE = re.compile(r'https?://[^\s"\'<>()\\{}\[\]]{4,120}')
API_RE = re.compile(r'["\'](/(?:api|v[0-9]|rest|gateway|service|prod-api|dev-api)[A-Za-z0-9_\-/.]{2,80})["\']')
ROUTER_RE = re.compile(r'path:\s*["\'](/[^"\']{1,60})["\']')
CHUNK_RE = re.compile(r'["\']([A-Za-z0-9_\-./]{2,100}?[0-9a-f]{6,8}\.js)["\']')
SECRET_PATTERNS = [
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("aws_ak", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("aliyun_ak", re.compile(r'LTAI[0-9A-Za-z]{12,}')),
    ("akid", re.compile(r'AKID[A-Za-z0-9]{10,}')),
    ("jwt", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.')),
    ("ak_sk_kv", re.compile(r'(?:access[_-]?key|secret[_-]?key|api[_-]?key|apikey|app[_-]?secret|client[_-]?secret|private[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{10,64})["\']', re.I)),
    ("internal_ip", re.compile(r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)')),
]

def secret_scan(text, src):
    hits = {}
    for label, pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            s = m.group(0)[:120]
            hits[label] = s
    if hits:
        emit({"type": "secrets", "source": src, "hits": hits,
              "note": "确认是真实凭据（能调通接口/解密数据）再升级报告，先 record_fact；命中原文只落 evidence，不进 fact/trace"})
    return len(hits)

def endpoint_scan(js, url):
    urls = []
    for m in URL_RE.findall(js):
        if m not in urls:
            urls.append(m)
        if len(urls) >= 30:
            break
    apis = []
    for m in API_RE.findall(js):
        if m not in apis:
            apis.append(m)
        if len(apis) >= 30:
            break
    routes = []
    for m in ROUTER_RE.findall(js):
        if m not in routes:
            routes.append(m)
        if len(routes) >= 20:
            break
    if urls or apis or routes:
        emit({"type": "endpoints", "url": url, "urls": urls, "api_paths": apis, "router_paths": routes})
    return len(urls) + len(apis) + len(routes)

def chunk_candidates(js, base):
    out = []
    for m in CHUNK_RE.findall(js):
        if m in out or len(out) >= 8:
            continue
        u = urllib.parse.urljoin(base, m)
        if u.startswith("http"):
            out.append(u)
    return out

def safe_name(src, i):
    # webpack:///./src/views/Login.vue -> src/views/Login.vue；防穿越，限制长度。
    p = urllib.parse.urlparse(src).path if "://" in src else src
    p = p.lstrip("/")
    p = re.sub(r"(\.\./)+", "_up/", p)
    parts = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", seg) for seg in p.split("/") if seg and seg not in (".", "..")]
    name = os.path.join(*parts) if parts else ("file_%d" % i)
    if len(name) > 180:
        name = name[-180:]
    return "%04d_%s" % (i, name)

def write_sources(m, outdir, tag):
    sources = m.get("sources") or []
    contents = m.get("sourcesContent") or []
    written = 0
    vue = envf = 0
    for i, src in enumerate(sources):
        c = contents[i] if i < len(contents) and contents[i] else None
        low = src.lower()
        if low.endswith(".vue"):
            vue += 1
        if low.endswith(".env") or "config" in low and low.endswith((".ts", ".js")):
            envf += 1
        if c is None:
            continue
        rel = safe_name(src, i)
        path = os.path.join(outdir, tag, rel)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(c)
            written += 1
            if written >= 300:
                break
        except OSError:
            continue
    return {"sources": len(sources), "with_content": sum(1 for c in contents if c), "written": written,
            "vue_files": vue, "env_or_config": envf}

def analyze_map(raw, js_url, map_url, outdir, tag):
    # 返回 (真实命中, 密钥命中数)：SPA fallback 会给 404 页回 200，"可达"≠"命中"。
    try:
        m = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        emit({"type": "sourcemap", "found": False, "js": js_url, "map_url": map_url,
              "note": "map 可达但不是 JSON"})
        return False, 0
    if not isinstance(m, dict) or "sources" not in m:
        emit({"type": "sourcemap", "found": False, "js": js_url, "map_url": map_url,
              "note": "JSON 但无 sources 字段"})
        return False, 0
    info = write_sources(m, outdir, tag)
    try:
        with open(os.path.join(outdir, tag, "__map__.json"), "wb") as f:
            f.write(raw)
    except OSError:
        pass
    emit({"type": "sourcemap", "found": True, "js": js_url, "map_url": map_url, **info,
          "dir": os.path.join(outdir, tag),
          "note": "CWE-540 源码泄露：sourcesContent 即原始源码；.vue/.env 计数见上。"
                  "含真实密钥可报 critical；仅源码结构泄露报 high"})
    n = secret_scan(raw.decode("utf-8", "replace"), "map:" + map_url)
    return True, n

def audit_js(url, outdir, seen_dirs):
    try:
        code, body, final = fetch(url)
    except Exception as e:
        emit({"type": "js", "url": url, "error": str(e)[:120]})
        return 0, []
    js = body.decode("utf-8", "replace")
    emit({"type": "js", "url": final, "status": code, "bytes": len(body)})
    hits = secret_scan(js, "js:" + final)
    n_ep = endpoint_scan(js, final)
    secrets_n = hits
    eps_n = 1 if n_ep else 0
    found = False
    total = hits
    m_smu = SMU_RE.search(js)
    tag = re.sub(r"[^A-Za-z0-9._-]", "_", urllib.parse.urlparse(final).path.replace("/", "_"))[-60:] or "js"
    if tag in seen_dirs:
        tag = tag + "_%d" % len(seen_dirs)
    seen_dirs.add(tag)
    if m_smu:
        mu = m_smu.group(1)
        if mu.startswith("data:application/json;base64,"):
            try:
                raw = base64.b64decode(mu.split(",", 1)[1])
                ok, total_s = analyze_map(raw, final, "(inline)", outdir, tag)
                total += total_s
                found = found or ok
            except Exception:
                pass
        else:
            map_url = urllib.parse.urljoin(final, mu)
            try:
                code, raw, _ = fetch(map_url, MAX_MAP_BYTES)
                if code == 200:
                    ok, total_s = analyze_map(raw, final, map_url, outdir, tag)
                    total += total_s
                    found = found or ok
                else:
                    emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                          "status": code})
            except Exception as e:
                emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                      "error": str(e)[:120]})
    if not found:
        map_url = final + ".map"
        try:
            code, raw, _ = fetch(map_url, MAX_MAP_BYTES)
            if code == 200:
                ok, total_s = analyze_map(raw, final, map_url, outdir, tag)
                total += total_s
                found = found or ok
            else:
                emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                      "status": code, "note": "无 sourceMappingURL 提示，兜底探测 <js>.map"})
        except Exception as e:
            emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                  "error": str(e)[:120]})
    return (1 if found else 0), chunk_candidates(js, final), secrets_n + total, eps_n

def main():
    args = sys.argv[1:]
    outdir = os.path.join(os.getcwd(), "jsmap")
    urls = []
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            outdir = args[i + 1]
            i += 2
            continue
        urls.append(args[i])
        i += 1
    if not urls:
        emit({"type": "summary", "error": "没有给 URL"})
        return
    os.makedirs(outdir, exist_ok=True)
    queue, fetched, seen_dirs = [], set(), set()
    queue.extend(urls[:6])
    maps = js_n = secrets_total = ep_total = 0
    html_urls = set(u for u in queue if not u.endswith(".js"))
    while queue and js_n < 12:
        url = queue.pop(0)
        if url in fetched:
            continue
        fetched.add(url)
        if url in html_urls or url.endswith((".html", ".htm")) or ".js" not in url:
            try:
                code, body, final = fetch(url)
            except Exception as e:
                emit({"type": "html", "url": url, "error": str(e)[:120]})
                continue
            html = body.decode("utf-8", "replace")
            emit({"type": "html", "url": final, "status": code, "bytes": len(body)})
            found = 0
            for m in SCRIPT_RE.findall(html) + PRELOAD_RE.findall(html):
                u = urllib.parse.urljoin(final, m)
                if u not in fetched and u not in queue and len(queue) < 14:
                    queue.append(u)
                    found += 1
            emit({"type": "html_scripts", "url": final, "queued": found})
            continue
        found_n, chunks, sec_n, ep_n = audit_js(url, outdir, seen_dirs)
        maps += found_n
        secrets_total += sec_n
        ep_total += ep_n
        js_n += 1
        for cu in chunks:
            if cu not in fetched and cu not in queue and len(queue) < 14:
                queue.append(cu)
    emit({"type": "summary", "js_audited": js_n, "sourcemaps_found": maps,
          "secret_signals": secrets_total, "endpoint_signals": ep_total, "dir": outdir,
          "next": "sourcemap found=true 的站点按 CWE-540 报 high（含真实密钥 critical）；"
                  "接口/路由清单 record_fact 并继续接口面测试"})

if __name__ == "__main__":
    main()
`

// ensureJsAuditScript 幂等落盘审计脚本；失败返回空串（调用方退化为让模型手写）。
func (t *ToolSet) ensureJsAuditScript() string {
	if strings.TrimSpace(t.runDir) == "" {
		return ""
	}
	p := filepath.Join(t.runDir, "4zreco-jsaudit.py")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if err := os.WriteFile(p, []byte(jsAuditScript), 0o755); err != nil {
		return ""
	}
	return p
}

// jsAudit SPA/webpack 源码泄露审计：给入口 URL，返回一条可直接执行的命令。
func (t *ToolSet) jsAudit() actool.CoreTool {
	return readTool(
		"js_audit",
		"SPA/webpack 前端源码泄露审计（Vue/React 单页应用必跑）：给入口 URL（HTML 或 JS），"+
			"脚本自动提取 <script> 与 chunk、检测 sourceMappingURL 与 <js>.map 兜底探测、"+
			"还原 sourcesContent 原始源码落盘、扫描密钥（AK/SK/私钥/JWT/内网段）并抽取"+
			"接口与路由清单。本工具返回一条命令，交给 Bash 执行即可（流量录制/审批照常生效）。\n"+
			"结论口径：sourcemap 命中=CWE-540 源码泄露 high；还原出真实凭据=critical；"+
			"接口/路由清单 record_fact 后继续接口面测试。",
		obj(map[string]any{
			"urls": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "入口 URL 列表（1-6 个：入口 HTML 或具体 .js 文件）",
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
				if len(urls) >= 6 {
					break
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("urls 至少要有一个合法的 http(s) 绝对地址"), nil
			}
			script := t.ensureJsAuditScript()
			if script == "" {
				return actool.Errorf("js_audit 未启用: 本次 run 没有可用的工作目录"), nil
			}
			quoted := make([]string, len(urls))
			for i, u := range urls {
				quoted[i] = shellQuote(u)
			}
			out := filepath.Join(t.runDir, "jsmap")
			return jsonResult(map[string]any{
				"run_with_bash": fmt.Sprintf("python3 %s --out %s %s", script, out, strings.Join(quoted, " ")),
				"count":         len(urls),
				"note": "输出每行一个 JSON 事件（html/js/sourcemap/secrets/endpoints/summary）。" +
					"sourcemap found=true → CWE-540：还原源码落盘在 --out 目录，save_evidence 后报 high；" +
					"secrets 有真实凭据 → critical；endpoints 照常 record_fact 并继续接口面测试。",
			})
		})
}
