#!/usr/bin/env bash
# check-eino-boundary.sh — Eino 接入架构红线门禁（docs/Eino深度接入方案-2026-11-05.md §8.2）
#
# 红线来源见同文档 §0.1：
#   R1  双图架构留在 engine：internal/db 与 internal/server/engine*.go 不得依赖 eino
#   R2  planner/worker 调度留在 engine 状态机：全仓禁 compose.Graph / compose.Workflow
#       （白名单为空，出现即违规）
#   R4  判定逻辑不感知 eino：guard/intercept/vulnintel/honeydetect 不得 import eino，
#       导出函数签名不得出现 schema./adk./compose. 等 eino 类型
#   版本锁：go.mod 的 cloudwego/eino 必须等于锁定版本（v0.9.21），且 go.sum 含对应
#       哈希行（同步性）+ go mod verify 全量核对（方案 §8.2 第 4 条）
#
# 注意：刻意不对 ./internal/server 整包做依赖树检查——P1 落地后 internal/server 会经
# internal/agent 合法依赖 eino，整包检查会把红线误判成违规；engine*.go 按源文件 grep。
#
# 用法：./scripts/check-eino-boundary.sh   # CI 门禁与本地均可跑，任一失败 exit 1
set -uo pipefail
cd "$(dirname "$0")/.."

LOCKED_EINO_VERSION="v0.9.21"
EINO_IMPORT_RE='github\.com/(cloudwego/eino|eino-contrib)'
R4_PKGS=(internal/guard internal/intercept internal/vulnintel internal/honeydetect)

fail=0

# --- 检查 1：红线 R1 —— 双图架构留在 engine --------------------------------
# internal/db 用 go list -deps 查依赖树（传递依赖全覆盖）；
# engine*.go 按源文件 grep（不做 ./internal/server 整包依赖树，原因见文件头）。
if db_deps=$(go list -deps ./internal/db 2>&1); then
  db_hits=$(printf '%s\n' "$db_deps" | grep -E "$EINO_IMPORT_RE" || true)
  if [ -n "$db_hits" ]; then
    printf '[FAIL] R1 internal/db 依赖树出现 eino（go list -deps ./internal/db）：\n'
    printf '%s\n' "$db_hits" | sed 's/^/       /'
    fail=$((fail+1))
  else
    printf '[ok]   R1 internal/db 依赖树无 eino（go list -deps ./internal/db，共 %s 个包）\n' \
      "$(printf '%s\n' "$db_deps" | wc -l)"
  fi
else
  printf '[FAIL] R1 internal/db：go list -deps ./internal/db 失败\n%s\n' "$db_deps"
  fail=$((fail+1))
fi

engine_hits=$(grep -nE "$EINO_IMPORT_RE" internal/server/engine*.go 2>/dev/null || true)
if [ -n "$engine_hits" ]; then
  printf '[FAIL] R1 internal/server/engine*.go 源码出现 eino 引用：\n'
  printf '%s\n' "$engine_hits" | sed 's/^/       /'
  fail=$((fail+1))
else
  printf '[ok]   R1 internal/server/engine*.go 源码无 eino 引用（grep %s 个文件）\n' \
    "$(ls internal/server/engine*.go 2>/dev/null | wc -l)"
fi

# --- 检查 2：红线 R4 —— 判定逻辑不感知 eino --------------------------------
# import 检查 + 导出函数签名 eino 类型检查（源码 grep 近似）。
# 签名近似法：grep func 声明行及其后 3 行（覆盖多行签名），含 eino 类型限定符
# （schema./adk./compose.，即方案 §8.2 点名的三类）即报；宁可误报不放过——
# 这些包连 import 都被上一条禁了，报出来说明两层都破。
r4_hits=$(grep -rnE --include='*.go' "$EINO_IMPORT_RE" "${R4_PKGS[@]}" 2>/dev/null || true)
if [ -n "$r4_hits" ]; then
  printf '[FAIL] R4 guard/intercept/vulnintel/honeydetect 源码出现 eino import/引用：\n'
  printf '%s\n' "$r4_hits" | sed 's/^/       /'
  fail=$((fail+1))
else
  printf '[ok]   R4 guard/intercept/vulnintel/honeydetect 无 eino import\n'
fi

r4_sig_hits=$(
  grep -rnE -A3 --include='*.go' '^func (\([^)]*\) )?[A-Z]' "${R4_PKGS[@]}" 2>/dev/null \
    | grep -E '(^|[^A-Za-z0-9_])(schema|adk|compose)\.' || true
)
if [ -n "$r4_sig_hits" ]; then
  printf '[FAIL] R4 guard/intercept/vulnintel/honeydetect 导出函数签名出现 eino 类型（grep 近似）：\n'
  printf '%s\n' "$r4_sig_hits" | sed 's/^/       /'
  fail=$((fail+1))
else
  printf '[ok]   R4 guard/intercept/vulnintel/honeydetect 导出函数签名无 eino 类型（grep 近似）\n'
fi

# --- 检查 3：红线 R2 —— 调度不写成 eino 图 ---------------------------------
# 全仓禁 compose.Graph / compose.Workflow，白名单为空（只查 .go 源码）。
r2_hits=$(grep -rnE --include='*.go' --exclude-dir=.git '\bcompose\.(Graph|Workflow)\b' . 2>/dev/null || true)
if [ -n "$r2_hits" ]; then
  printf '[FAIL] R2 全仓出现 compose.Graph/compose.Workflow（白名单为空，planner-worker 调度禁止写成 eino 图）：\n'
  printf '%s\n' "$r2_hits" | sed 's/^/       /'
  fail=$((fail+1))
else
  printf '[ok]   R2 全仓无 compose.Graph/compose.Workflow（白名单为空）\n'
fi

# --- 检查 4：版本锁 ---------------------------------------------------------
# eino 尚未引入（P1 未开工）时跳过不失败；一旦引入，版本必须精确等于锁定版本。
# 注意：go.mod 的 require 有两种形态——块内缩进（行首制表符）与单行 `require path version`；
# 锚 ^ 都匹配不到（沙箱实测踩过），故允许行首空白与可选 require 前缀。
# 行尾的空格要求同时保证不会误配 eino-ext/eino-contrib 等子模块。
# 版本取行尾字段：块内形态是 `path version`（$2），单行形态是 `require path version`（$3），
# 先剥 // 注释再取 $NF 两种通吃。
eino_ver=$(grep -E "^[[:space:]]*(require[[:space:]]+)?github\.com/cloudwego/eino " go.mod \
  | sed 's|//.*||' | awk '{print $NF}' || true)
if [ -z "$eino_ver" ]; then
  printf '[ok]   版本锁：eino 未引入，版本检查跳过（锁定版本 %s，P1 引入时必须等于它）\n' \
    "$LOCKED_EINO_VERSION"
elif [ "$eino_ver" = "$LOCKED_EINO_VERSION" ]; then
  printf '[ok]   版本锁：go.mod eino 版本 %s = 锁定版本 %s\n' "$eino_ver" "$LOCKED_EINO_VERSION"
else
  printf '[FAIL] 版本锁：go.mod eino 版本 %s ≠ 锁定版本 %s（版本漂移则按方案 §P1 重跑依赖尖刺）\n' \
    "$eino_ver" "$LOCKED_EINO_VERSION"
  fail=$((fail+1))
fi

# go.sum 校验（方案 §8.2 第 4 条后半，此前缺实现）。
# a) eino 引入后：go.sum 必须含该版本的哈希行（go.mod/go.sum 同步性，防 require 了却没
#    tidy 落账）；未引入时随版本锁一起跳过。
#    go.sum 行格式是「<module> <version> h1:<hash>」（空格分隔），不是 module@version——
#    早期实现的 @ 形态 grep 永远匹配不到（go.sum 从不写 @）。版本串自带 v 前缀
#    （go.mod 里就是 v0.9.21），不要再加上一个 v。
if [ -n "$eino_ver" ]; then
  if grep -qF "github.com/cloudwego/eino ${eino_ver} h1:" go.sum; then
    printf '[ok]   go.sum：含 github.com/cloudwego/eino@%s 哈希行\n' "$eino_ver"
  else
    printf '[FAIL] go.sum：无 github.com/cloudwego/eino@%s 哈希行（go.mod/go.sum 不同步，跑 go mod tidy）\n' \
      "$eino_ver"
    fail=$((fail+1))
  fi
else
  printf '[ok]   go.sum：eino 未引入，eino 哈希行检查跳过\n'
fi

# b) go mod verify：模块缓存内容哈希与 go.sum 全量核对（官方手段），与 eino 是否引入无关。
#    网络不可达导致模块下载失败也落在这里——门禁宁可误报，按失败阻断。
if verify_out=$(go mod verify 2>&1); then
  printf '[ok]   go mod verify：%s\n' "$verify_out"
else
  printf '[FAIL] go mod verify 失败（依赖树与 go.sum 不一致或模块下载失败）：\n' >&2
  printf '%s\n' "$verify_out" | sed 's/^/       /' >&2
  fail=$((fail+1))
fi

# --- 汇总 -------------------------------------------------------------------
if [ "$fail" -ne 0 ]; then
  printf '[check-eino-boundary] %s 项失败，阻断（docs/Eino深度接入方案-2026-11-05.md §8.2）\n' "$fail" >&2
  exit 1
fi
printf '[check-eino-boundary] 4 条检查全部通过\n'
exit 0
