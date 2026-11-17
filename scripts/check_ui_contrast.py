#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_ui_contrast.py — 一次性 WCAG 对比度核查（UI_DESIGN.md §14 待确认项 T-4 落地）

只测量与建议，不修改 globals.css。

- 解析 web/src/app/globals.css 的 :root 与 .dark 两个块里的语义令牌；
  支持 oklch(...) 与 oklch(... / alpha) 两种形态，alpha 向下层混合（按浏览器普通
  绘制的合成方式，在 gamma 编码 sRGB 上混合）后再测。
- 颜色数学：oklch → OKLab → LMS' → 线性 sRGB（CSS Color 4 标准逆矩阵，常量取自
  css-color-4 / Björn Ottosson 参考实现）→ 相对亮度 → WCAG 2.x 对比度。
  测量时线性分量按简单截断（clip）处理；本项目令牌均在 sRGB 色域内，仅作兜底。
- 阈值（工单口径）：正文文本对 ≥4.5:1；大字/加粗文本与 UI 组件对（primary 按钮、
  边框/输入框等非文本边界）≥3:1。注：WCAG 1.4.11 非文本 3:1 仅适用于「识别控件
  所必需」的边界（input 最相关），卡片/容器装饰性边框可豁免；报告仍按 3:1 如实给数。
- FAIL 项给出建议值：只动 L（色域不允许时同步降 C），色相 H 一律不动保持语义；
  同一令牌出现在多个 FAIL 对时合并为一个建议值（需同时满足全部对）；
  建议值在脚本内回测确认达标（含 3% 裕量防四舍五入回退）。

用法: python3 -I scripts/check_ui_contrast.py [globals.css 路径]
纯 Python3 标准库（re / math / os / sys），无第三方依赖。
"""
import math
import os
import re
import sys

# ---------------------------------------------------------------------------
# 颜色数学（CSS Color 4：oklch → linear sRGB → 相对亮度 → WCAG 对比度）
# ---------------------------------------------------------------------------

# OKLab → 线性 sRGB（CSS Color 4 §3.7.3 / Ottosson 参考矩阵）
M_OKLAB_TO_LSRGB = (
    (4.0767416621, -3.3077115913, 0.2309699292),
    (-1.2684380046, 2.6097574011, -0.3413193965),
    (-0.0041960863, -0.7034186147, 1.7076147010),
)


def oklch_to_linear_srgb(l_val, c_val, h_deg):
    """oklch → 线性 sRGB（不裁剪）。返回 (r, g, b)，可能越出 [0,1]。"""
    h = math.radians(h_deg)
    a = c_val * math.cos(h)
    b = c_val * math.sin(h)
    l_ = l_val + 0.3963377774 * a + 0.2158037573 * b
    m_ = l_val - 0.1055613458 * a - 0.0638541728 * b
    s_ = l_val - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    r = M_OKLAB_TO_LSRGB[0][0] * l + M_OKLAB_TO_LSRGB[0][1] * m + M_OKLAB_TO_LSRGB[0][2] * s
    g = M_OKLAB_TO_LSRGB[1][0] * l + M_OKLAB_TO_LSRGB[1][1] * m + M_OKLAB_TO_LSRGB[1][2] * s
    b2 = M_OKLAB_TO_LSRGB[2][0] * l + M_OKLAB_TO_LSRGB[2][1] * m + M_OKLAB_TO_LSRGB[2][2] * s
    return r, g, b2


def lin_to_srgb(v):
    """线性 → gamma 编码 sRGB（transfer function，CSS Color 4 §3.3）。"""
    v = min(max(v, 0.0), 1.0)
    return 12.92 * v if v <= 0.0031308 else 1.055 * (v ** (1 / 2.4)) - 0.055


def srgb_to_lin(v):
    """gamma 编码 sRGB → 线性。"""
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def oklch_rgb01(l_val, c_val, h_deg):
    """oklch → 色域裁剪后的 gamma 编码 sRGB (0..1) 三元组。"""
    return tuple(lin_to_srgb(v) for v in oklch_to_linear_srgb(l_val, c_val, h_deg))


def oklch_in_gamut(l_val, c_val, h_deg, eps=1e-4):
    return all(-eps <= v <= 1 + eps for v in oklch_to_linear_srgb(l_val, c_val, h_deg))


def rel_luminance(rgb01):
    """WCAG 相对亮度（输入为 gamma 编码 sRGB 0..1，内部转线性）。"""
    r, g, b = (srgb_to_lin(v) for v in rgb01)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def wcag_ratio(rgb1, rgb2):
    l1, l2 = sorted((rel_luminance(rgb1), rel_luminance(rgb2)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


def composite(fg_rgb, alpha, bg_rgb):
    """alpha < 1 的前景向下层混合（浏览器普通绘制在 gamma 编码 sRGB 上合成）。"""
    if alpha >= 1.0:
        return fg_rgb
    return tuple(f * alpha + b * (1.0 - alpha) for f, b in zip(fg_rgb, bg_rgb))


# ---------------------------------------------------------------------------
# globals.css 解析
# ---------------------------------------------------------------------------

OKLCH_RE = re.compile(
    r"oklch\(\s*([\d.]+)(%?)\s+([\d.]+)(%?)\s+(-?[\d.]+)(?:deg)?\s*(?:/\s*([\d.]+)(%?)\s*)?\)",
    re.IGNORECASE,
)
BLOCK_RE = re.compile(r"(?ms)^(:root|\.dark)\s*\{(.*?)^\}")
TOKEN_RE = re.compile(r"--([a-zA-Z0-9-]+)\s*:\s*([^;]+);")


def parse_css(path):
    """返回 {块名: {'--令牌名': 原始值}}，只保留以 -- 开头的自定义属性。"""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    blocks = {}
    for m in BLOCK_RE.finditer(text):
        name = m.group(1)
        tokens = {}
        for t in TOKEN_RE.finditer(m.group(2)):
            tokens["--" + t.group(1)] = t.group(2).strip()
        blocks[name] = tokens
    return blocks


def parse_oklch(value):
    """解析 oklch 值 → (L, C, H, alpha)；非 oklch 或解析失败返回 None。"""
    m = OKLCH_RE.fullmatch(value.strip())
    if not m:
        return None
    l_val = float(m.group(1)) / (100.0 if m.group(2) else 1.0)
    c_val = float(m.group(3)) / (100.0 if m.group(4) else 1.0)
    h_val = float(m.group(5))
    alpha = float(m.group(6)) / (100.0 if m.group(7) else 1.0) if m.group(6) else 1.0
    return (l_val, c_val, h_val, alpha)


# ---------------------------------------------------------------------------
# 测量对与阈值
# ---------------------------------------------------------------------------

TEXT_THRESHOLD = 4.5   # 正文文本对（本项目状态/辅助文本均为 text-xs/sm 正文尺寸）
UI_THRESHOLD = 3.0     # 大字/加粗文本与 UI 组件对（primary 按钮、边框/输入框等非文本）

TEXT_PAIRS = [
    ("--foreground", "--background"),
    ("--foreground", "--card"),
    ("--card-foreground", "--card"),
    ("--muted-foreground", "--background"),
    ("--muted-foreground", "--card"),
    ("--secondary-foreground", "--secondary"),
    ("--accent-foreground", "--accent"),
    ("--sidebar-foreground", "--sidebar"),
    ("--destructive", "--background"),
    ("--destructive", "--card"),
    ("--success", "--background"),
    ("--success", "--card"),
    ("--warning", "--background"),
    ("--warning", "--card"),
    ("--info", "--background"),
    ("--info", "--card"),
]
UI_PAIRS = [
    ("--primary-foreground", "--primary"),  # 主按钮标签；工单口径按 UI 组件 3:1（WCAG 1.4.3 小字文本仍按 4.5）
    ("--border", "--background"),
    ("--input", "--background"),
    ("--sidebar-border", "--sidebar"),
]

# 建议调整时动哪个令牌：默认动前景令牌的 L；primary 按钮对动 --primary（保住标准前景白/墨）
SUGGEST_TOKEN_OVERRIDES = {("--primary-foreground", "--primary"): "--primary"}

# 工单枚举的令牌全集（存在的都测；不存在如实报告）
STATE_FG_TOKENS = ("--destructive-foreground", "--success-foreground",
                   "--warning-foreground", "--info-foreground")
ALL_TOKENS = sorted(set(t for pair in TEXT_PAIRS + UI_PAIRS for t in pair) | set(STATE_FG_TOKENS))


# ---------------------------------------------------------------------------
# FAIL 建议值搜索（只动 L，必要时降 C；H 不动；同一令牌合并满足全部 FAIL 对）
# ---------------------------------------------------------------------------

MARGIN = 1.03          # 建议值裕量，防四舍五入回退到阈值以下
GAMUT_EPS = 1e-4       # 建议搜索的色域判定余量（收紧，避免放行依赖 clip 的退化值）


def search_adjusted(l0, c0, h0, others):
    """为单个令牌搜建议值。others: [(对照侧 rgb, 阈值), ...]（该令牌的 FAIL 对全集）。
    返回 (L_new, C_new, [每对回测比值])；不可行返回 None。优先保持 C，仅动 L。"""
    l_grid = [round(i * 0.005, 3) for i in range(1, 199)]  # 0.005..0.99
    for c_factor in (1.0, 0.75, 0.5, 0.25, 0.0):
        c_try = round(c0 * c_factor, 4)
        best = None
        for l_try in l_grid:
            if not oklch_in_gamut(l_try, c_try, h0, GAMUT_EPS):
                continue
            rgb = oklch_rgb01(l_try, c_try, h0)
            ratios = [wcag_ratio(rgb, o_rgb) for o_rgb, _ in others]
            if all(r >= t * MARGIN for r, (_, t) in zip(ratios, others)):
                if best is None or abs(l_try - l0) < best[0]:
                    best = (abs(l_try - l0), l_try, ratios)
        if best is not None:
            return best[1], c_try, best[2]
    return None


def fmt_g(x):
    return "%g" % round(x, 4)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def measure_theme(block_name, tokens):
    lines = []
    # 令牌回显（便于复现）
    lines.append("**令牌取值**（%s 块）：" % block_name)
    for t in ALL_TOKENS:
        if t in tokens:
            lines.append("- `%s: %s`" % (t, tokens[t]))
    for t in STATE_FG_TOKENS:
        if t not in tokens:
            lines.append("- `%s` **未定义**（:root 与 .dark 均无）——不测量" % t)
    lines.append("")

    def color_lch(name):
        raw = tokens.get(name)
        return parse_oklch(raw) if raw is not None else None

    # 第一遍：算出全部对的比值
    results = []   # (fg, bg, ratio, threshold, ok)
    for pairs, threshold in ((TEXT_PAIRS, TEXT_THRESHOLD), (UI_PAIRS, UI_THRESHOLD)):
        for fg_name, bg_name in pairs:
            fg, bg = color_lch(fg_name), color_lch(bg_name)
            if fg is None or bg is None:
                results.append((fg_name, bg_name, None, threshold, None))
                continue
            fg_rgb = oklch_rgb01(*fg[:3])
            bg_rgb = oklch_rgb01(*bg[:3])
            if fg[3] < 1.0:  # alpha 混合到下层（本主题当前无 alpha 令牌，路径保留）
                fg_rgb = composite(fg_rgb, fg[3], bg_rgb)
            ratio = wcag_ratio(fg_rgb, bg_rgb)
            results.append((fg_name, bg_name, ratio, threshold, ratio >= threshold))

    # 第二遍：按「被调整令牌」合并 FAIL 对，各给一个建议值
    fail_groups = {}   # target_token -> [(fg, bg, other_rgb, threshold)]
    for fg_name, bg_name, ratio, threshold, ok in results:
        if ok not in (False,):
            continue
        target = SUGGEST_TOKEN_OVERRIDES.get((fg_name, bg_name), fg_name)
        other_name = bg_name if target == fg_name else fg_name
        other_lch = color_lch(other_name)
        fail_groups.setdefault(target, []).append(
            (fg_name, bg_name, oklch_rgb01(*other_lch[:3]), threshold))

    suggestions = {}   # target_token -> 建议文案
    for target, items in fail_groups.items():
        lch = color_lch(target)
        hit = search_adjusted(lch[0], lch[1], lch[2],
                              [(o_rgb, t) for _, _, o_rgb, t in items])
        if hit is None:
            suggestions[target] = "无可行建议（全 L 域色域/阈值不可满足，需人工改色相）"
            continue
        l_new, c_new, ratios = hit
        note = "仅调 L" if abs(c_new - lch[1]) < 1e-9 else "调 L 并降 C"
        backtest = "、".join(
            "%s %.2f:1" % (bg_name.lstrip("-") if target == fg_name else fg_name.lstrip("-"), r)
            for (fg_name, bg_name, _, _), r in zip(items, ratios))
        suggestions[target] = "建议 `oklch(%s %s %s)`（%s；回测 %s）" % (
            fmt_g(l_new), fmt_g(c_new), fmt_g(lch[2]), note, backtest)

    # 渲染
    for title, pairs, threshold in (
        ("正文文本对（阈值 ≥%.1f:1）" % TEXT_THRESHOLD, TEXT_PAIRS, TEXT_THRESHOLD),
        ("大字/加粗与 UI 组件对（阈值 ≥%.1f:1）" % UI_THRESHOLD, UI_PAIRS, UI_THRESHOLD),
    ):
        lines.append("| 令牌对 | 实测比 | 阈值 | 结果 | 建议调整（FAIL 项） |")
        lines.append("|---|---|---|---|---|")
        for fg_name, bg_name in pairs:
            entry = next(r for r in results if r[0] == fg_name and r[1] == bg_name)
            _, _, ratio, thr, ok = entry
            label = "`%s` / `%s`" % (fg_name, bg_name)
            if ok is None:
                missing = fg_name if ratio is None and ok is None and color_lch(fg_name) is None else bg_name
                lines.append("| %s | — | %.1f | SKIP（%s 未定义） | — |" % (label, threshold, missing))
                continue
            target = SUGGEST_TOKEN_OVERRIDES.get((fg_name, bg_name), fg_name)
            suggestion = "—" if ok else suggestions.get(target, "—")
            lines.append("| %s | %.2f | %.1f | %s | %s |" % (
                label, ratio, thr, "PASS" if ok else "**FAIL**", suggestion))
        lines.append("")
    fail_pairs = [(f, b, r, t) for f, b, r, t, ok in results if ok is False]
    return lines, fail_pairs


def self_test():
    """公式自检：黑白灰锚点、白黑对比度、alpha 解析/混合。任一失败即中止。"""
    eps = 0.01
    white = oklch_rgb01(1, 0, 0)
    black = oklch_rgb01(0, 0, 0)
    assert all(abs(v - 1) < eps for v in white), white
    assert all(abs(v - 0) < eps for v in black), black
    grey = oklch_rgb01(0.59986, 0, 0)  # oklab(0.59986,0,0) ≈ #808080
    assert all(abs(v - 0.5) < eps for v in grey), grey
    assert abs(wcag_ratio((1, 1, 1), (0, 0, 0)) - 21.0) < 0.01
    parsed = parse_oklch("oklch(0.5 0.1 200 / 50%)")
    assert parsed is not None and abs(parsed[3] - 0.5) < 1e-9, parsed
    blended = composite((1, 1, 1), 0.5, (0, 0, 0))
    assert all(abs(v - 0.5) < 1e-9 for v in blended)
    print("自检通过：oklch→sRGB 锚点（白/黑/中灰）、白黑对比度=21、alpha 解析与混合均正确。")


def main():
    default_css = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "web", "src", "app", "globals.css",
    )
    css_path = sys.argv[1] if len(sys.argv) > 1 else default_css
    blocks = parse_css(css_path)
    print("对比度核查（UI_DESIGN T-4）— 数据源：%s" % css_path)
    print("公式：oklch→OKLab→线性 sRGB（CSS Color 4 逆矩阵）→相对亮度→WCAG 2.x 对比度")
    print("注：--border/--input/--sidebar-border 的 3:1 按 WCAG 1.4.11 仅约束「识别控件所必需」")
    print("    的边界（input 最相关）；卡片/容器装饰性边框可豁免，数值如实报告供裁量。")
    print()
    self_test()
    print()
    all_fails = {}
    for block_name, heading in ((":root", "## 亮色 :root"), (".dark", "## 暗色 .dark")):
        if block_name not in blocks:
            print("⚠️ 未找到 %s 块" % block_name)
            continue
        print(heading)
        lines, fails = measure_theme(block_name, blocks[block_name])
        all_fails[block_name] = fails
        print("\n".join(lines))
    print("## 汇总")
    for block_name, fails in all_fails.items():
        n_pairs = len(TEXT_PAIRS) + len(UI_PAIRS)
        print("- %s：%d/%d FAIL%s" % (
            block_name, len(fails), n_pairs,
            ("：" + "、".join("%s/%s" % (f[0], f[1]) for f in fails)) if fails else "",
        ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
