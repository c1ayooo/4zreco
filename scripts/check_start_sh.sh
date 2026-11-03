#!/usr/bin/env bash
# start.sh 的崩溃处理与 install.sh 的 systemd 单元属性检查。
#
# 背景（2026-10-22 在真机上撞到）：配置坏了（如数据库密码不一致）时，
# 4zreco 会反复崩溃重启，而 start.sh 无限自拉起 + systemd 的 Restart=always
# 叠加，结果是：
#
#   - systemctl status 显示 **active (running)**——活着的是 start.sh 这个包装
#     脚本，4zreco 本体在崩；
#   - 网页打不开，但状态一切正常，排查方向完全跑偏；
#   - 日志被同一行错误刷爆，首因被埋掉。
#
# 这两条防线：start.sh 的崩溃上限 + systemd 的 StartLimit。
set -uo pipefail

# MSYS（Git Bash）下路径转换会把 Windows 路径里的 ".." 处理得很别扭，
# 所以这里直接用仓库根的相对路径：脚本在 scripts/，目标在上一级。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
START="${1:-$REPO_ROOT/start.sh}"
INSTALL="${2:-$REPO_ROOT/install.sh}"
if [ ! -f "$START" ]; then START="./start.sh"; fi
if [ ! -f "$INSTALL" ]; then INSTALL="./install.sh"; fi

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

printf '=== 检查 start.sh ===\n'

# 1) 必须有崩溃次数上限。
check "start.sh 有连续崩溃次数上限" \
  grep -q 'MAX_CRASHES=' "$START"

# 2) 崩溃计数要在「异常退出」分支里累加（不是只在别处定义）。
#    判据用行号关系而不是模式匹配：awk 正则里 $code 的 $ 是行尾锚点，
#    按字面文本匹配会踩坑。改成「crashes=0 之后、crashes=...+1 之前
#    必须有 case 的异常分支」。
check "start.sh 在异常退出分支累加崩溃计数" \
  bash -c '
    reset_line=$(grep -n "crashes=0" "'"$START"'" | tail -1 | cut -d: -f1)
    inc_line=$(grep -n "crashes=\$((crashes + 1))" "'"$START"'" | head -1 | cut -d: -f1)
    [ -n "$reset_line" ] && [ -n "$inc_line" ] && [ "$inc_line" -gt "$reset_line" ]
  '

# 3) 达到上限必须退出（不能让脚本继续无限重启）。
check "达到崩溃上限后退出脚本" \
  grep -q 'exit "\$code"' "$START"

# 4) 崩溃上限必须不太小（否则正常的短暂故障也会被判死）也不太大
#    （否则「卡在半死状态」太久）。
check "崩溃上限在 3~10 之间" \
  bash -c '
    n=$(grep -oE "^MAX_CRASHES=[0-9]+" "'"$START"'" | cut -d= -f2)
    [ -n "$n" ] && [ "$n" -ge 3 ] && [ "$n" -le 10 ]
  '

# 5) 「请求重启」(75) 不该计入崩溃次数——那是用户点一键更新的正常流程。
#    判据：RESTART_CODE 分支之后要有 crashes=0（把计数清零）。
check "程序请求重启(75) 不计入崩溃次数" \
  bash -c '
    reset_line=$(grep -n "crashes=0" "'"$START"'" | tail -1 | cut -d: -f1)
    case_line=$(grep -n "RESTART_CODE" "'"$START"'" | tail -1 | cut -d: -f1)
    [ -n "$reset_line" ] && [ -n "$case_line" ] && [ "$reset_line" -gt "$case_line" ]
  '

# 6) 脚本语法正确。
check "start.sh 语法正确（sh -n）" sh -n "$START"

printf '\n=== 检查 install.sh 的 systemd 单元 ===\n'

# 7) unit 里要有 StartLimit（否则 systemd 无限重启，状态永远 running）。
check "systemd 单元设置了 StartLimitBurst" \
  grep -q 'StartLimitBurst=' "$INSTALL"

check "systemd 单元设置了 StartLimitIntervalSec" \
  grep -q 'StartLimitIntervalSec=' "$INSTALL"

# 8) StartLimit 必须在 [Unit] 段（新 systemd 的位置）——
#    放在 [Service] 段会被 systemd 忽略。
#    判据用行号：StartLimitBurst 必须落在 [Unit] 与下一个 [ 段之间。
check "StartLimit 在 [Unit] 段内" \
  bash -c '
    unit_line=$(grep -n "^\[Unit\]" "'"$INSTALL"'" | head -1 | cut -d: -f1)
    burst_line=$(grep -n "StartLimitBurst=" "'"$INSTALL"'" | head -1 | cut -d: -f1)
    next_sec=$(awk -v s="$unit_line" "NR>s && /^\\[/ { print NR; exit }" "'"$INSTALL"'")
    [ -n "$unit_line" ] && [ -n "$burst_line" ] && [ -n "$next_sec" ] \
      && [ "$burst_line" -gt "$unit_line" ] && [ "$burst_line" -lt "$next_sec" ]
  '

if [ "$fail" -gt 0 ]; then
  printf '\n=== %d 项检查未通过 ===\n' "$fail"
  exit 1
fi
printf '\n=== 全部检查通过 ===\n'
