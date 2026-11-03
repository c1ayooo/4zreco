package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/c1ayooo/4zreco/intercept"
)

// API 契约枚举工具：从目标暴露的 OpenAPI/Swagger/Postman 契约文件里读出
// **接口清单**（路径、方法、参数、是否需要鉴权）。
//
// ## 为什么需要它
//
// 我们现在发现接口靠两条路：
//   - 爬虫（katana）——猜路径，漏掉前端没链到的接口；
//   - 前端 JS 静态/运行时分析（api-recon skill）——准，但依赖前端代码可读，
//     且只看得到「前端调了哪些」，看不到「后端支持哪些」。
//
// **契约文件是第三路，而且往往最准**：它直接回答「有哪些接口、哪些参数、
// 哪些方法、哪些要鉴权」。Strix（开源同类）就走这条路——直读
// OpenAPI/Swagger/Postman。
//
// 常见情形：目标有 `/swagger-ui/`、`/api-docs`、`/openapi.json`、
// `/v2/api-docs`（Swagger 2.0）、`/v3/api-docs`（OpenAPI 3）等。路径是
// **约定俗成**的，扫这几个就能覆盖大部分。
//
// ## 为什么解析在脚本里做
//
// 契约文件动辄几千行。原始内容进模型上下文既费 token 又容易看漏——
// 「漏掉一个带鉴权的接口」正好是越权挖掘最容易丢的地方。
// 解析后的清单是**结构化的、可枚举的**，这才是模型需要的。
//
// 但解析是纯本地计算（下载走 Bash → 走记录代理与审批管控；解析在本地跑）。
// 与 diff_responses 同一模式：脚本写在本次 run 的工作目录，命令交给 Bash。
//
// ## 边界
//
// 只做**读契约**（GET 契约文件）。不 fuzz、不改包、不发业务请求。
// 拿到清单后要不要打、怎么打，是后续的挖掘动作（vuln-hunting 的事）。

// apiContractTool 组装 API 契约枚举工具。
func (t *ToolSet) apiContractTool() actool.CoreTool {
	return readTool(
		"api_contract",
		"从目标暴露的【API 契约文件】里读出接口清单（路径、方法、参数、是否需鉴权）。\n"+
			"用法：给 base_url（目标站点根，如 https://t.example.com），工具会探测常见契约路径"+
			"（/openapi.json、/swagger.json、/v3/api-docs、/api-docs 等）并解析出接口清单。\n"+
			"**为什么值得做**：爬虫靠猜路径会漏接口，前端 JS 分析只能看到「前端调了哪些」；"+
			"契约文件直接给出「后端支持哪些」——是更准的接口清单来源。\n"+
			"输出：每个接口的 path / method / 参数（含必填标记）/ 是否需鉴权（security 字段），"+
			"以及「带鉴权标记的接口」单独列出——那是越权挖掘最该看的那批。\n"+
			"拿到清单后，把它交给 vuln-hunting 的方法论做越权/可枚举/状态机判断。\n"+
			"**本工具只组命令不执行**（下载请求走记录代理与审批管控）。",
		obj(map[string]any{
			"base_url": str("目标站点根地址，如 https://t.example.com（不带路径）"),
			"paths":    str("自定义契约路径(可选)，逗号分隔；不给则探测常见路径"),
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL string `json:"base_url"`
				Paths   string `json:"paths"`
			}
			_ = json.Unmarshal(in, &a)
			base := strings.TrimSpace(a.BaseURL)
			if base == "" {
				return actool.Errorf("base_url 不能为空"), nil
			}
			if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
				return actool.Errorf("base_url 必须是绝对地址（http:// 或 https:// 开头）"), nil
			}
			base = strings.TrimRight(base, "/")

			// 解析脚本要落在本次 run 的工作目录（平台规约：中间产物不落 /tmp）。
			workDir := intercept.ReviewWorkingDirectory(ctx)
			if workDir == "" {
				return actool.Errorf("本次 run 没有绑定工作目录，无法写出契约解析脚本——" +
					"请用 katana 爬路径或 api-recon skill 代替"), nil
			}
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				return actool.Errorf("创建工作目录失败: " + err.Error()), nil
			}
			scriptPath, err := WriteContractScript(workDir)
			if err != nil {
				return actool.Errorf("写出契约解析脚本失败: " + err.Error()), nil
			}
			paths := resolveContractPaths(a.Paths)
			cmd := buildContractCmd(base, paths, scriptPath, workDir)
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"script_path":   scriptPath,
				"probing":       paths,
				"note": "用 Bash 工具执行上面这条命令（会探测契约路径、下载并解析）。输出是 JSON：" +
					"找到的契约文件路径 + 接口清单（path/method/参数/是否需鉴权）。" +
					"没找到契约文件很常见（很多站点不暴露）——那就退回 katana 爬路径或 api-recon skill。" +
					"**清单本身不是漏洞**，但它是越权/可枚举判断的对象清单。",
			})
		},
	)
}

// contractPaths 是常见的 API 契约文件路径。
//
// 覆盖三大家族：
//   - OpenAPI 3：/openapi.json、/openapi.yaml、/v3/api-docs
//   - Swagger 2：/swagger.json、/v2/api-docs、/api-docs、/api/swagger.json
//   - Postman：/postman_collection.json
//
// 顺序有意义：先探 JSON（好解析），后探 YAML。
var contractPaths = []string{
	"/openapi.json",
	"/v3/api-docs",
	"/api-docs",
	"/swagger.json",
	"/v2/api-docs",
	"/api/swagger.json",
	"/api/openapi.json",
	"/docs/openapi.json",
	"/openapi.yaml",
	"/postman_collection.json",
}

// resolveContractPaths 处理自定义路径参数；为空时用默认清单。
func resolveContractPaths(custom string) []string {
	parts := strings.Split(custom, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return contractPaths
	}
	return out
}

// buildContractCmd 生成「探测 + 下载 + 解析」的命令。
//
// 流程：逐个路径 curl 探测（只看 200）→ 第一个命中的下载下来 → 交给解析脚本。
// 契约文件落在工作目录（不是 /tmp——平台规约）。
func buildContractCmd(base string, paths []string, scriptPath, workDir string) string {
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, quoteShell(base+p))
	}
	contractFile := filepath.Join(workDir, "api_contract.json")
	// 第一步：逐个探测，命中就下载到工作目录并停。
	probe := fmt.Sprintf(
		"for u in %s; do code=$(curl -sS -o %s -w '%%{http_code}' --max-time 20 \"$u\"); "+
			"if [ \"$code\" = \"200\" ]; then echo \"CONTRACT $u\"; break; fi; done",
		strings.Join(quoted, " "), quoteShell(contractFile))
	// 第二步：交给解析脚本。
	return probe + " ; " + fmt.Sprintf("python3 %s %s", quoteShell(scriptPath), quoteShell(contractFile))
}

// contractScriptName 是契约解析脚本的文件名。
const contractScriptName = "api_contract.py"

// WriteContractScript 把契约解析脚本写到工作目录，返回脚本路径。
func WriteContractScript(dir string) (string, error) {
	path := filepath.Join(dir, contractScriptName)
	if err := os.WriteFile(path, []byte(contractScriptSource), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// contractScriptSource 是契约解析脚本的源码（纯标准库，无第三方依赖）。
//
// 输出结构：
//   {
//     "contract": "https://t/openapi.json",   // 命中的契约文件（没找到则空）
//     "found": true/false,
//     "api_count": 12,                          // 接口总数
//     "endpoints": [ {path, method, summary, auth_required, params:[{name,in,required}]} ],
//     "auth_endpoints": [ ... ],                // 需要鉴权的那批（越权挖掘先看这批）
//     "auth_schemes": ["bearer","apiKey"],     // 契约里声明的鉴权方式
//   }
//
// 为什么把「需要鉴权的接口」单列：越权/未授权挖掘的入口就是这批接口。
// 混在几百个接口里，模型大概率只看前几个。
const contractScriptSource = `#!/usr/bin/env python3
"""API 契约解析（4ZRECO agent 工具 api_contract 的执行端）。

用法: api_contract.py <契约文件>
支持 OpenAPI 3 / Swagger 2.0（JSON）；YAML 不解析（需要额外依赖），
Postman collection 做尽力解析。
输出 JSON: 命中的契约、接口清单、需鉴权的接口。
"""
import json, sys


def load(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def params_of(op):
    """取一个操作的参数列表（OpenAPI3: parameters + requestBody；Swagger2: parameters）。"""
    out = []
    for p in (op.get("parameters") or []):
        name = p.get("name")
        if not name:
            continue
        sch = p.get("schema") or {}
        out.append({
            "name": name,
            "in": p.get("in", ""),
            "required": bool(p.get("required", False)),
            "type": sch.get("type", "") or p.get("type", ""),
        })
    rb = op.get("requestBody") or {}
    for name, sch in (rb.get("content") or {}).items():
        if isinstance(sch, dict):
            for pn in (sch.get("properties") or {}):
                out.append({
                    "name": pn,
                    "in": "body:" + name,
                    "required": bool(((sch.get("properties") or {}).get(pn) or {}).get("required", False)),
                    "type": (((sch.get("properties") or {}).get(pn) or {}).get("type", "")),
                })
    return out


def auth_required(op, spec):
    """该操作是否需要鉴权。

    判据：操作自己的 security 优先；没有则用全局 security。
    空的 security 数组 [] 表示【显式声明为公开】——那就不算需要鉴权。
    """
    sec = op.get("security", spec.get("security"))
    if sec is None:
        return False
    if isinstance(sec, list) and len(sec) == 0:
        return False
    return bool(sec)


def auth_schemes(spec):
    out = []
    comps = ((spec.get("components") or {}).get("securitySchemes")
             or spec.get("securityDefinitions") or {})
    for name, sch in comps.items():
        t = (sch or {}).get("type", "")
        if t:
            out.append(t if t != "apiKey" else "apiKey:" + str((sch or {}).get("name", "")))
    return out


def parse_openapi(spec):
    endpoints = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch",
                                      "head", "options", "trace"):
                continue
            if not isinstance(op, dict):
                continue
            op = dict(op)
            op["parameters"] = (op.get("parameters") or []) + common
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": (op.get("summary") or op.get("description") or "")[:120],
                "auth_required": auth_required(op, spec),
                "params": params_of(op),
                "tags": op.get("tags") or [],
            })
    return endpoints


def parse_postman(spec):
    endpoints = []
    def walk(items, prefix=""):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:
                walk(it.get("item"), prefix)
            else:
                req = it.get("request") or {}
                url = req.get("url")
                if isinstance(url, dict):
                    raw = url.get("raw") or ""
                else:
                    raw = url or ""
                path = raw.split("?")[0]
                # 绝对 URL 也要剥掉 origin——清单里要的是 path，不是整条 URL。
                if path.startswith("http://") or path.startswith("https://"):
                    rest = path.split("://", 1)[1]
                    slash = rest.find("/")
                    path = rest[slash:] if slash >= 0 else "/"
                if path and not path.startswith("http"):
                    path = prefix + path
                endpoints.append({
                    "path": path,
                    "method": (req.get("method") or "GET").upper(),
                    "summary": (it.get("name") or "")[:120],
                    "auth_required": bool(req.get("auth")),
                    "params": [],
                    "tags": [],
                })
    walk(spec.get("item"))
    return endpoints


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "用法: api_contract.py <契约文件>"}))
        return 1
    raw = load(sys.argv[1])
    out = {
        "contract": sys.argv[1],
        "found": False,
        "api_count": 0,
        "endpoints": [],
        "auth_endpoints": [],
        "auth_schemes": [],
    }
    if not raw.strip():
        out["error"] = "契约文件为空或读不到"
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    try:
        spec = json.loads(raw)
    except ValueError as e:
        out["error"] = "不是 JSON 格式（若是 YAML 契约，需人工读取）: %s" % e
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if "paths" in spec:
        eps = parse_openapi(spec)
        out["auth_schemes"] = auth_schemes(spec)
    elif "item" in spec:
        eps = parse_postman(spec)
    else:
        eps = []
        out["error"] = "未识别的契约格式（既没有 paths 也没有 item）"
    out["found"] = bool(eps)
    out["api_count"] = len(eps)
    out["endpoints"] = eps
    out["auth_endpoints"] = [e for e in eps if e.get("auth_required")]
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
`
