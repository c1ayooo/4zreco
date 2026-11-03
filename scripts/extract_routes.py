#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Go 源码提取 ARTEX 的全部 API 路由。

ARTEX 用 net/http 的 ServeMux（Go 1.22+ 支持 "METHOD /path/{wildcard}" 模式）。
路由注册散落在 server/ 下的多个文件里，绝大多数是字面量：

    mux.HandleFunc("GET /api/tasks", s.listTasks)

少数用变量拼接（finding_traffic.go 里的 base）：

    base := "/api/exploration/findings/{id}/traffic"
    mux.HandleFunc("PATCH "+base+"/{binding_id}", s.editFindingTraffic)

本脚本处理这两种形式，输出 JSON 路由表供契约测试使用。
"""

import json
import os
import re
import sys

# mux.HandleFunc("METHOD <path expr>", handler)
HANDLE_RE = re.compile(
    r'mux\.HandleFunc\(\s*"(?P<method>[A-Z]+)\s+(?P<path>[^"]*)"\s*(?:\+\s*(?P<plus>[^,]+?))?\s*,\s*(?P<handler>[A-Za-z0-9_.]+)\s*\)'
)

# base := "/api/..."
BASE_RE = re.compile(r'\bbase\s*:?=\s*"(?P<value>/api[^"]*)"')

# var 形式的注册（本次暂不处理，但要能报出来）
VAR_RE = re.compile(r'mux\.HandleFunc\(\s*(?P<expr>[^,]+?)\s*,\s*(?P<handler>[A-Za-z0-9_.]+)\s*\)')


def extract_from_file(path):
    """从一个 Go 文件里提取路由。返回 (routes, unresolved)。"""
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()

    # 先收集本文件里的 base 变量
    bases = {m.group("value") for m in BASE_RE.finditer(src)}

    routes = []
    unresolved = []

    for m in HANDLE_RE.finditer(src):
        method = m.group("method")
        path = m.group("path")
        plus = m.group("plus")
        handler = m.group("handler")
        if plus:
            # 形如 "PATCH " + base + "/{binding_id}"
            expr = f'"{method} {path}" + {plus}'
            resolved = None
            for b in bases:
                # 把 base 变量替换进去；plus 里可能还夹着字面量拼接
                candidate = plus.replace("base", f'"{b}"')
                # candidate 现在形如 ""/api/.../traffic" + "/{binding_id}"
                parts = re.findall(r'"([^"]*)"', candidate)
                if parts:
                    resolved = "".join(parts)
            if resolved is None:
                unresolved.append({"expr": expr, "handler": handler, "file": os.path.basename(path)})
                continue
            path = resolved
        routes.append({"method": method, "path": path, "handler": handler, "file": os.path.basename(path)})

    # 找出我们没解析懂的注册形式，报告出来而不是静默漏掉
    for m in VAR_RE.finditer(src):
        expr = m.group("expr").strip()
        if expr.startswith('"') and " " in expr:
            continue  # 已被 HANDLE_RE 覆盖
        # 尝试再拼一次 base
        parts = re.findall(r'"([^"]*)"', expr)
        if parts:
            joined = "".join(parts)
            if joined.startswith("/api") or " " in joined:
                mm = re.match(r'([A-Z]+)\s+(/api.*)$', joined)
                if mm:
                    routes.append({
                        "method": mm.group(1),
                        "path": mm.group(2),
                        "handler": m.group("handler"),
                        "file": os.path.basename(path),
                    })
                    continue
        unresolved.append({"expr": expr, "handler": m.group("handler"), "file": os.path.basename(path)})

    return routes, unresolved


def main():
    server_dir = sys.argv[1] if len(sys.argv) > 1 else "server"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "routes.json"

    all_routes = []
    all_unresolved = []
    for name in sorted(os.listdir(server_dir)):
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        r, u = extract_from_file(os.path.join(server_dir, name))
        all_routes.extend(r)
        all_unresolved.extend(u)

    # 去重（同一 method+path 注册多次时保留第一个）
    seen = set()
    deduped = []
    for r in all_routes:
        key = (r["method"], r["path"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    deduped.sort(key=lambda r: (r["path"], r["method"]))

    doc = {
        "count": len(deduped),
        "routes": deduped,
        "unresolved": all_unresolved,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)

    print(f"提取 {len(deduped)} 条路由 -> {out_path}")
    if all_unresolved:
        print(f"⚠ {len(all_unresolved)} 条未解析（需人工确认）:")
        for u in all_unresolved:
            print(f"  {u['file']}: {u['expr']} -> {u['handler']}")


if __name__ == "__main__":
    main()
