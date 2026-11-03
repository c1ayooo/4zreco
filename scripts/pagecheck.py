#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX 页面巡检辅助。

配合 chrome-devtools MCP 使用：这份清单给出要访问的页面、每个页面要检查的
DOM 锚点（用来判断页面是否真的渲染出来了，而不是停在 loading / 报错页），
以及截图的存放路径。

用法（由 Claude 调用 chrome-devtools 工具执行）：
    1. browser_navigate 到每个 url
    2. browser_take_snapshot 拿到 a11y 树 → 对照 anchors 检查关键元素在不在
    3. browser_take_screenshot 存到 screenshots/<name>.png
    4. browser_console_messages 收集 console error

页面清单同时也是「哪些页面存在、每个页面应该有什么」的基线。
"""

import json
import os
import sys

# (名称, 路径, 必须出现的关键文本/角色锚点)
# anchors 用「页面上应该看得到的文字」判断，比选择器更抗前端重构。
PAGES = [
    ("login",           "/login",                      ["ARTEX", "密码"]),
    ("dashboard",       "/dashboard",                  []),
    ("tasks",           "/function/tasks",             ["任务"]),
    ("task-detail",     "/function/tasks/detail?id=1",  []),
    ("assets",          "/function/assets",            []),
    ("findings",        "/function/findings",          []),
    ("finding-detail",  "/function/findings/detail?id=1", []),
    ("traffic",         "/function/traffic",           []),
    ("commands",        "/function/commands",          []),
    ("llm-records",     "/function/llm-records",       []),
    ("sync",            "/function/sync",              []),
    ("workspace",       "/function/workspace",         []),
    ("chat",            "/chat",                       []),
    ("agents",          "/system/agents",              []),
    ("agent-detail",    "/system/agents/detail?key=worker", []),
    ("hostenv",         "/system/hostenv",             []),
    ("intercept",       "/system/intercept",           []),
    ("intercept-approvals", "/system/intercept/approvals", []),
    ("intercept-assets",    "/system/intercept/assets",    []),
    ("llm",             "/system/llm",                 []),
    ("logs",            "/system/logs",                []),
    ("mcp",             "/system/mcp",                 []),
    ("notify",          "/system/notify",              []),
    ("proxypool",       "/system/proxypool",           []),
    ("settings",        "/system/settings",            []),
    ("skills",          "/system/skills",              []),
    ("tools",           "/system/tools",               []),
    ("vulnintel",       "/system/vulnintel",           []),
]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "pages.json"
    base = os.environ.get("ARTEX_BASE", "http://10.10.70.17:8787")
    doc = {
        "base": base,
        "count": len(PAGES),
        "pages": [
            {"name": n, "url": base + p, "path": p, "anchors": a}
            for (n, p, a) in PAGES
        ],
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print(f"{len(PAGES)} 个页面 -> {out}")
    for n, p, _ in PAGES:
        print(" ", n, p)


if __name__ == "__main__":
    main()
