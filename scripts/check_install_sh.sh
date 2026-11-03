#!/usr/bin/env bash
# install.sh 的静态属性检查。
#
# 2026-10-22 在一台真实服务器（Kali 2026.3）上做全新安装时，这四条全部
# 暴露了问题——它们是「本地跑一遍看不出来、只有真装才会炸」的那类：
#
#  1. curl 的 --retry 默认**不重试 SSL 中断**（--retry 只覆盖瞬时错误：
#     超时/429/5xx）。经代理下载 17MB 的发行包时连接被切断
#     （SSL_read: unexpected eof），curl 直接放弃——重试参数形同虚设。
#  2. 下载失败**没有 die**，脚本继续往下走，最后报「解压失败（需要 unzip）」，
#     把网络问题误导成包损坏。
#  3. SHA256SUMS 取不到时只 warn 然后**跳过校验**——取不到校验文件等于
#     没校验，这对供应链是硬伤。
#  4. 没有断点续传：17MB 传到 90% 断线，只能从头再来。
#
# 这些用 grep 就能静态断言，不需要真的装一遍。
set -uo pipefail

# MSYS（Git Bash）下 pwd 给的是 /d/... 形式，bash -n 与 grep 读不了；
# 转成 Windows 绝对路径再交给子进程。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W 2>/dev/null || cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$SCRIPT_DIR/install.sh}"

fail=0
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '[ok]   %s\n' "$desc"
  else
    printf '[FAIL] %s\n' "$desc"
    fail=$((fail+1))
  fi
}

printf '=== 检查 %s ===\n' "$TARGET"

# 1) curl 必须带 --retry-all-errors（否则 SSL 中断不重试）。
#    判据要排除注释行——本文件顶部的说明里就写着「--retry-all-errors」，
#    不排除的话 grep 会匹配到注释，判据永远是 ok（假阳性）。
check "curl 带 --retry-all-errors（SSL 中断也要重试）" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q -- "--retry-all-errors"
  '

# 2) 下载发行包失败必须 die，不能拖到解压才报错。
#    判据要严：取发行包的那一行 curl 调用**所在的完整语句**（含 \ 续行）
#    必须带 || die。
#    （之前写成「往下看 3 行里有 die」——那 3 行里正好有另一个 if 分支的
#    die，判据会假阳性通过。测试自己写错比没测试更糟。）
check "下载发行包失败即 die（不拖到解压才报错）" \
  bash -c '
    awk "
      /releases\/download\/\\\$VERSION\/\\\$zip/ && !/SHA256SUMS/ { hit=1 }
      hit { printf \"%s\\n\", \$0 }
      hit && !/\\\\$/ { exit }
    " "'"$TARGET"'" | grep -q "|| die"
  '

# 3) SHA256SUMS 取不到必须 die，不能只 warn 降级放行。
#    判据：取 SHA256SUMS 的 curl 调用**所在的完整语句**（含 \ 续行）必须
#    带 || die。找的是 curl 调用本身，不是某句提示文案——文案会随修复
#    改写，判据绑在文案上会误报。
check "SHA256SUMS 取不到即 die（不降级放行）" \
  bash -c '
    awk "
      /^[[:space:]]*#/ { next }
      /SHA256SUMS/ && !/grep / { hit=1 }
      hit { printf \"%s\\n\", \$0 }
      hit && !/\\\\$/ { exit }
    " "'"$TARGET"'" | grep -q "|| die"
  '

# 4) 大文件下载要支持断点续传（-C -）。同样排除注释行。
check "发行包下载支持断点续传（-C -）" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q -- "-C -"
  '

# 5) 脚本本身语法正确（bash -n）。
check "install.sh 语法正确（bash -n）" bash -n "$TARGET"

# 6) 脚本以 set -euo pipefail 开头（出错即停）。
check "install.sh 启用 set -euo pipefail" \
  grep -q 'set -euo pipefail' "$TARGET"

# 7) 数据库角色已存在时必须同步密码。
#
# 踩过的坑（2026-10-22 真实安装）：机器上残留旧的 4zreco 角色时，脚本走
# 「已存在 → 跳过创建」分支，config.json 里写的却是**新生成**的密码 →
# 服务起来就反复 SASL 认证失败退出，报错指不到真因。
check "角色已存在时同步密码（ALTER ROLE）" \
  bash -c '
    grep -v "^[[:space:]]*#" "'"$TARGET"'" | grep -q "ALTER ROLE 4zreco LOGIN PASSWORD"
  '

if [ "$fail" -gt 0 ]; then
  printf '\n=== %d 项检查未通过 ===\n' "$fail"
  exit 1
fi
printf '\n=== 全部检查通过 ===\n'
