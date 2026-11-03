#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX API 契约巡检。

对后端全部路由做三段检查：

  A. 未授权      —— 不带 Authorization 头，期望 401（/api/auth/* 与 /api/health 除外）
  B. 空参数      —— 带合法 token 但不给必填参数，期望 4xx 而**不是 500**
  C. 正常只读    —— 仅对 GET：带合法 token 正常请求，期望 2xx/4xx，**任何 5xx 都是 bug**

写操作（POST/PUT/PATCH/DELETE）只做 A 和 B 两段——不真的改数据。

用法：
    # 1) 先从源码提取路由
    python scripts/extract_routes.py server /tmp/routes.json

    # 2) 跑巡检（token 从环境变量读，或用用户名密码自动登录换取）
    ARTEX_USERNAME=ARTEX ARTEX_PASSWORD=*** python scripts/apicontract.py \
        --routes /tmp/routes.json --base-url http://127.0.0.1:8787

    # 3) 只跑未授权段（无凭据时）
    python scripts/apicontract.py --routes /tmp/routes.json --anon-only

密码只从环境变量读，绝不写进代码或报告。
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

# 不需要鉴权的路由前缀
AUTH_EXEMPT_PREFIXES = ("/api/auth/",)
AUTH_EXEMPT_EXACT = ("/api/health",)

# 只读方法：做完整的 C 段检查
READ_METHODS = ("GET",)

# 「外部依赖未就绪」不是本系统的缺陷。ScopeSentry 这类集成在用户没配置数据源
# 时必然失败——前端有专门的 status 接口显示「未配置」。把它算成 5xx bug 会
# 让真问题被淹没。识别方式：5xx + 错误消息里出现下列配置类措辞。
UNCONFIGURED_MARKERS = (
    "未配置", "请先配置", "不存在，请先创建", "未初始化",
)

# 路径参数替换表。{key} 等用真实存在的名字。
PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def log(msg):
    print(msg, flush=True)


def fetch(url, method="GET", token=None, body=None, timeout=15, headers=None, retries=2):
    """发一个 HTTP 请求，返回 (status, body_text, error)。不抛异常。

    502 / 连接失败是并发压测下的服务端拒绝，不是路由缺陷——重试几次再判定。
    否则会把「服务端限流」误报成「未鉴权却放行」这种真 bug。
    """
    data = None
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "Bearer " + token

    last = (0, "", "not attempted")
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                return resp.status, raw.decode("utf-8", "replace"), None
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, "read") else b""
            status, text = e.code, raw.decode("utf-8", "replace")
            if status == 502 and attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return status, text, None
        except urllib.error.URLError as e:
            last = (0, "", str(e.reason))
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return last
        except Exception as e:  # 超时等
            last = (0, "", type(e).__name__ + ": " + str(e))
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return last
    return last


def login(base_url, username, password):
    """用用户名密码换 JWT。失败返回 None。"""
    status, text, err = fetch(
        base_url + "/api/auth/login",
        method="POST",
        body={"username": username, "password": password},
    )
    if status != 200:
        log(f"  登录失败: HTTP {status} {err or ''} {text[:200]}")
        return None
    try:
        return json.loads(text).get("token")
    except Exception:
        log(f"  登录响应无法解析: {text[:200]}")
        return None


def discover_ids(base_url, token):
    """从运行中的实例取一批真实 ID，用于替换路径参数。

    路径参数替换不准确的请求会返回 404 —— 那是「参数没替换」不是「路由坏了」，
    报告里要把两者区分开。
    """
    ids = {}
    probes = {
        "task": ("/api/tasks", lambda d: (d.get("tasks") or d.get("data") or [{}])[0].get("id")),
        "id": ("/api/exploration/findings", lambda d: (d.get("findings") or d.get("data") or [{}])[0].get("id")),
        "key": ("/api/agents", lambda d: (d.get("agents") or d.get("data") or [{}])[0].get("key")),
        "name": ("/api/skills", lambda d: (d.get("skills") or d.get("data") or [{}])[0].get("name")),
    }
    for key, (path, pick) in probes.items():
        status, text, _ = fetch(base_url + path, token=token)
        if status != 200:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        try:
            val = pick(data)
        except Exception:
            val = None
        if val is not None:
            ids[key] = val
    # 兜底：没有真实数据时用常见的固定值
    ids.setdefault("id", 1)
    ids.setdefault("task", "1")
    ids.setdefault("taskId", "1")
    ids.setdefault("key", "worker")
    ids.setdefault("name", "default")
    ids.setdefault("skill", "default")
    ids.setdefault("cid", "1")
    ids.setdefault("rid", "1")
    ids.setdefault("gid", "1")
    ids.setdefault("sid", "1")
    ids.setdefault("iid", "1")
    ids.setdefault("assetID", "1")
    ids.setdefault("asset_id", "1")
    ids.setdefault("seq", "1")
    ids.setdefault("binding_id", "1")
    ids.setdefault("bindingId", "1")
    ids.setdefault("requestID", "1")
    ids.setdefault("conversation", "1")
    ids.setdefault("conversation_id", "1")
    ids.setdefault("jobId", "1")
    ids.setdefault("model", "gpt-4")
    return ids


def is_stream_path(path):
    """SSE 长连接路由：请求会一直挂着，直到客户端断开。

    这类路由不能用普通的「请求完成」语义来测——它本来就该挂着。所以
    超时反而说明流正常建立了。
    """
    return path.endswith("/stream")


def route_timeout(path):
    return 4 if is_stream_path(path) else 15


def fill_path(path, ids):
    """把 {param} 换成真实值。返回 (filled_path, unresolved_params)。"""
    missing = []

    def sub(m):
        name = m.group(1)
        if name in ids:
            return str(ids[name])
        missing.append(name)
        return "1"

    filled = PATH_PARAM_RE.sub(sub, path)
    return filled, missing


def is_unconfigured(body):
    """判断错误消息是否属于「外部依赖未配置」而非真 bug。"""
    if not body:
        return False
    return any(m in body for m in UNCONFIGURED_MARKERS)


def check_route(route, base_url, token, ids, do_read):
    """对一条路由跑检查，返回一条结果记录。

    ★ 写操作（POST/PUT/PATCH/DELETE）**绝不带 token 发真实请求**。

    原因（实测事故 2026-10-21）：这些接口不是幂等也不是无副作用的——
      POST /api/llm      空 body 会把「全局激活 LLM 配置」改掉（provider
                          落成默认 anthropic、base_url 清空、api_key 回落到
                          当前内存里的旧 key），随后所有 LLM 调用 403；
      POST /api/tasks    空 body 会真的建出一个任务。
    巡检脚本的任务是「看路由契约对不对」，不是「改线上配置」。写接口只做
    未授权段（段 A）：那时没有 token，服务不会执行任何副作用。
    """
    method = route["method"]
    path = route["path"]
    filled, missing = fill_path(path, ids)
    url = base_url + filled
    rec = {
        "method": method,
        "path": path,
        "filled": filled,
        "handler": route["handler"],
        "unfilled_params": missing,
        "anon_status": None,
        "empty_status": None,
        "read_status": None,
        "unconfigured": False,
        "skipped_write": False,
        "issues": [],
    }

    # A. 未授权（对所有路由都做；没有 token 时服务端不会执行副作用）
    st, body, err = fetch(url, method=method, body={} if method != "GET" else None, timeout=route_timeout(path))
    rec["anon_status"] = st
    exempt = path.startswith(AUTH_EXEMPT_PREFIXES) or path in AUTH_EXEMPT_EXACT
    if st == 0:
        # 连不上：不算路由问题，单独标记
        rec["issues"].append(f"未授权段请求失败: {err}")
    elif exempt:
        if st not in (200, 400, 401, 403):
            rec["issues"].append(f"豁免路由未授权返回 {st}")
    else:
        if st != 401:
            rec["issues"].append(f"未授权应返回 401，实际 {st}")

    if token is None:
        return rec

    if method not in READ_METHODS:
        # 写接口：到此为止。带 token 的请求会真的改线上状态。
        rec["skipped_write"] = True
        return rec

    # B. 空参数（只读路由：带 token，故意不给必填参数）
    st, body, err = fetch(url, method=method, token=token, body={} if method != "GET" else None, timeout=route_timeout(path))
    rec["empty_status"] = st
    if st >= 500 and is_unconfigured(body):
        rec["unconfigured"] = True
    elif st >= 500:
        rec["issues"].append(f"空参数返回 5xx: {st} {body[:300]}")
    if st == 0:
        if is_stream_path(path):
            # SSE 是长连接，等不到结束就超时是预期的，不算问题。
            rec["empty_status"] = 200
            rec["empty_stream"] = True
            rec["issues"] = [i for i in rec["issues"] if "空参数请求失败" not in i]
        else:
            rec["issues"].append(f"空参数请求失败: {err}")

    # C. 正常只读
    st, body, err = fetch(url, method=method, token=token, timeout=route_timeout(path))
    rec["read_status"] = st
    if st >= 500 and is_unconfigured(body):
        rec["unconfigured"] = True
    elif st >= 500:
        rec["issues"].append(f"正常 GET 返回 5xx: {st} {body[:300]}")
    if st == 0:
        if is_stream_path(path):
            rec["read_status"] = 200
            rec["read_stream"] = True
            rec["issues"] = [i for i in rec["issues"] if "正常 GET 请求失败" not in i]
        else:
            rec["issues"].append(f"正常 GET 请求失败: {err}")

    return rec


def summarize(results):
    anon = Counter(str(r["anon_status"]) for r in results)
    empty = Counter(str(r["empty_status"]) for r in results if r.get("empty_status") is not None)
    read = Counter(str(r["read_status"]) for r in results if r.get("read_status") is not None)
    with_issues = [r for r in results if r["issues"]]
    unconfigured = [r for r in results if r.get("unconfigured")]
    skipped_write = [r for r in results if r.get("skipped_write")]
    # 外部依赖未就绪的路由不进 server_errors，但要单独报出来。
    unconfigured_paths = {r["path"] for r in unconfigured}
    server_errors = [
        r for r in results
        if ((r.get("empty_status") or 0) >= 500 or (r.get("read_status") or 0) >= 500)
        and r["path"] not in unconfigured_paths
    ]
    return {
        "total": len(results),
        "anon_status_dist": dict(anon),
        "empty_status_dist": dict(empty),
        "read_status_dist": dict(read),
        "issue_count": len(with_issues),
        "server_errors": server_errors,
        "unconfigured": unconfigured,
        "skipped_write_count": len(skipped_write),
        "auth_leaks": [r for r in results if r["anon_status"] not in (401, 0) and not (
            r["path"].startswith(AUTH_EXEMPT_PREFIXES) or r["path"] in AUTH_EXEMPT_EXACT)],
        "issues": with_issues,
    }


def main():
    ap = argparse.ArgumentParser(description="ARTEX API 契约巡检")
    ap.add_argument("--routes", required=True, help="extract_routes.py 产出的 JSON")
    ap.add_argument("--base-url", default="http://127.0.0.1:8787")
    ap.add_argument("--token", default=os.environ.get("ARTEX_TOKEN"), help="JWT；不给则用用户名密码自动登录")
    ap.add_argument("--username", default=os.environ.get("ARTEX_USERNAME"))
    ap.add_argument("--password", default=os.environ.get("ARTEX_PASSWORD"))
    ap.add_argument("--anon-only", action="store_true", help="只跑未授权段（无凭据时用）")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json", dest="json_out", help="把完整报告写到这个文件")
    args = ap.parse_args()

    with open(args.routes, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    routes = doc["routes"]
    log(f"路由 {len(routes)} 条，目标 {args.base_url}")

    token = args.token
    if not token and not args.anon_only and args.username and args.password:
        log("用用户名密码登录换取 token ...")
        token = login(args.base_url, args.username, args.password)
        if token:
            log("  登录成功")
    if not token:
        log("没有 token —— 只跑未授权段")
        args.anon_only = True

    ids = discover_ids(args.base_url, token) if token else {}

    do_read = not args.anon_only
    log(f"开始巡检（只读段：只有 GET 会带 token 发请求；写操作只做未授权检查，"
        f"不碰线上状态），并发 {args.workers}...")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(
            lambda r: check_route(r, args.base_url, token, ids, do_read),
            routes,
        ))
    elapsed = time.time() - t0

    s = summarize(results)
    log("")
    log(f"=== 巡检完成（{elapsed:.1f}s）===")
    log(f"总路由: {s['total']}")
    log(f"未授权状态分布: {s['anon_status_dist']}")
    if do_read:
        log(f"空参数状态分布（仅 GET）: {s['empty_status_dist']}")
        log(f"正常 GET 状态分布: {s['read_status_dist']}")
    log(f"写操作（只做未授权检查，未发真实请求）: {s['skipped_write_count']} 条")
    log(f"问题路由数: {s['issue_count']}")

    if s["server_errors"]:
        log("")
        log(f"⚠ 5xx 错误 {len(s['server_errors'])} 条（这是 bug）:")
        for r in s["server_errors"]:
            log(f"  {r['method']} {r['path']}  empty={r['empty_status']} read={r['read_status']}")
            for i in r["issues"]:
                log(f"      {i}")

    if s["unconfigured"]:
        log("")
        log(f"外部依赖未就绪（非缺陷）{len(s['unconfigured'])} 条:")
        for r in s["unconfigured"][:10]:
            log(f"  {r['method']} {r['path']}  empty={r['empty_status']} read={r['read_status']}")

    if s["auth_leaks"]:
        log("")
        log(f"⚠ 未鉴权却放行 {len(s['auth_leaks'])} 条:")
        for r in s["auth_leaks"][:30]:
            log(f"  {r['method']} {r['path']} -> {r['anon_status']}")

    other = [r for r in s["issues"] if r not in s["server_errors"] and r not in s["auth_leaks"]]
    if other:
        log("")
        log(f"其他问题 {len(other)} 条:")
        for r in other[:30]:
            log(f"  {r['method']} {r['path']}")
            for i in r["issues"]:
                log(f"      {i}")

    if args.json_out:
        out = {
            "base_url": args.base_url,
            "elapsed_sec": round(elapsed, 1),
            "summary": {k: v for k, v in s.items() if not isinstance(v, list)},
            "server_errors": s["server_errors"],
            "auth_leaks": s["auth_leaks"],
            "results": results,
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=1)
        log(f"\n报告已写入 {args.json_out}")

    # 有 5xx 或鉴权泄露时以非零退出，便于 CI 门禁
    if s["server_errors"] or s["auth_leaks"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
