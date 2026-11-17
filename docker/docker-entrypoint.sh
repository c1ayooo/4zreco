#!/bin/sh
# 容器入口：后台拉起特权安装助手 hostd + 首次启动后台预装工具，再把控制权交给
# start.sh（4zreco 守护）。
#
# 为什么这样分层（参考上游 v0.4.69「主程序与工具环境解耦」的部署思路）：
#   - 主镜像只带运行时依赖与核心工具，保持精简（发布/拉取快）；
#   - catalog 全量工具在**首次启动后台预装**，不阻塞主服务，也不需要把镜像
#     再撑大 1–2GB；装完写标记文件，重启不重复；
#   - 「系统 → 宿主环境」页可随时查看/补装（走常驻 hostd）。
# 环境变量：
#   ZRECO_PREINSTALL_TOOLS=0   关闭首次启动预装
#   ZRECO_PREINSTALL_TOOLS=1   默认：首次启动后台预装
#   ZRECO_PREINSTALL_TOOLS=force  强制重跑（升级 binary 后想重新核对工具时用）
set -u

HOSTD_SOCK="/run/4zreco/hostd.sock"
# 标记放**容器层**而不是 data 卷：预装出来的工具落在容器可写层，镜像升级重建
# 容器后「工具没了、标记还在」会导致永久跳过预装、工具静默消失。标记随容器
# 生命周期走，重建即重跑（预装本身幂等：已装好的逐项跳过，开销只有探测）。
PREINSTALL_MARK="/app/.tools-preinstall-done"
PREINSTALL_LOG="/app/data/tools-preinstall.log"
mkdir -p "$(dirname "$HOSTD_SOCK")" /app/data

# ── hostd：常驻 unix socket，供「宿主环境」页一键装/重装 ──
if [ -x /app/4zreco-hostd ]; then
  if [ ! -S "$HOSTD_SOCK" ]; then
    /app/4zreco-hostd -socket "$HOSTD_SOCK" >>/app/data/hostd.log 2>&1 &
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -S "$HOSTD_SOCK" ] && break
      sleep 0.3
    done
    if [ -S "$HOSTD_SOCK" ]; then
      echo "[entrypoint] hostd 已就绪 → $HOSTD_SOCK（宿主环境页可一键装工具）"
    else
      echo "[entrypoint] warn: hostd 未就绪（页面一键安装不可用，其余功能正常）"
    fi
  fi

  # ── 首次启动后台预装 catalog 全量工具（幂等；失败项可在宿主环境页重试）──
  mode="${ZRECO_PREINSTALL_TOOLS:-1}"
  if [ "$mode" != "0" ]; then
    if [ "$mode" = "force" ] || [ ! -f "$PREINSTALL_MARK" ]; then
      (
        echo "[preinstall] $(date '+%F %T') 开始 catalog 预装（后台，不影响主服务）" >>"$PREINSTALL_LOG"
        if /app/4zreco-hostd -install-all >>"$PREINSTALL_LOG" 2>&1; then
          echo "[preinstall] $(date '+%F %T') 完成（失败项见上方 [fail] 行）" >>"$PREINSTALL_LOG"
          touch "$PREINSTALL_MARK"
        else
          echo "[preinstall] $(date '+%F %T') 存在失败项，未写完成标记（下次启动重试；也可在宿主环境页重装）" >>"$PREINSTALL_LOG"
        fi
      ) &
      echo "[entrypoint] 已启动后台工具预装 → data/tools-preinstall.log（宿主环境页可看进度）"
    fi
  fi
else
  echo "[entrypoint] warn: 未找到 /app/4zreco-hostd（页面一键安装不可用）"
fi

# exec 让 start.sh 成为 PID 1 的替代进程，docker stop 的 SIGTERM 直接到 4zreco。
exec /app/start.sh "$@"
