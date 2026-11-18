#!/usr/bin/env bash
# 一次性 PostgreSQL 集群：initdb 到 /tmp + trust 认证 + 建 4zreco_ci + 跑全量测试。
#
# 为什么用它：本机系统 PG（5432）上的 4zrec 角色没有 CREATEDB 权限，共享库跑多轮
# 会撞固定名 fixture 的唯一键产生假失败（AGENTS.md §1）。这里在 15432 起一个用完
# 即删的独立集群：不碰系统 PG、不写任何密码（trust）、失败也会被 trap 清理。
#
# 用法：
#   ./scripts/setup-postgres.sh                      # 起库 + 全量 go test -p 1
#   ./scripts/setup-postgres.sh ./internal/agent/... # 透传给 go test 的其它参数
#   ZRECO_TEST_PG_PORT=15433 ./scripts/setup-postgres.sh
#   ZRECO_PG_BIN=/usr/lib/postgresql/17/bin ./scripts/setup-postgres.sh
#
# 退出码 = go test 的退出码（集群启动失败时为 1）。测试结束后集群立即销毁。
set -euo pipefail

DB_NAME="4zreco_ci"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 端口占用探测：/dev/tcp 不需要 ss/lsof。默认 15432；被占（别的实例/容器）就顺延，
# 免得为了跑测试要求先手工腾端口。
port_busy() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null || return 1
  exec 3>&- 2>/dev/null || true
  return 0
}
BASE_PORT="${ZRECO_TEST_PG_PORT:-15432}"
PORT="$BASE_PORT"
for _ in $(seq 0 20); do
  if ! port_busy "$PORT"; then break; fi
  PORT=$((PORT + 1))
done
if port_busy "$PORT"; then
  echo "setup-postgres: $BASE_PORT..$PORT 全部被占用；请设置 ZRECO_TEST_PG_PORT 指定空闲端口" >&2
  exit 1
fi

# 取本机最高版本的 PostgreSQL bin（ls -d | sort -V 避免 9.6 > 16 的字典序坑）。
if [[ -z "${ZRECO_PG_BIN:-}" ]]; then
  ZRECO_PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"
fi
if [[ ! -x "${ZRECO_PG_BIN:-}/initdb" ]]; then
  echo "setup-postgres: 找不到 initdb（已探测 '${ZRECO_PG_BIN:-}'）；请设置 ZRECO_PG_BIN 指向 PostgreSQL bin 目录" >&2
  exit 1
fi
BIN="$ZRECO_PG_BIN"

# initdb 拒绝以 root 运行；给个明确提示而不是让 initdb 自己报错。
if [[ "$(id -u)" == "0" ]]; then
  echo "setup-postgres: 不能用 root 运行（initdb 拒绝 root）；请用普通用户执行" >&2
  exit 1
fi

DATA="$(mktemp -d "${TMPDIR:-/tmp}/4zreco-pg-XXXXXX")"
LOG="$DATA/postgres.log"

cleanup() {
  "$BIN/pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$DATA"
}
trap cleanup EXIT

echo "setup-postgres: initdb -> $DATA (port $PORT)"
"$BIN/initdb" -D "$DATA" -A trust -U 4zreco >/dev/null

# 只监听回环、独立端口；-k /tmp 让 unix socket 不落进系统 PG 的 socket 目录。
"$BIN/pg_ctl" -D "$DATA" \
  -o "-p $PORT -k /tmp -c listen_addresses=127.0.0.1" \
  -l "$LOG" -w start >/dev/null

"$BIN/createdb" -h 127.0.0.1 -p "$PORT" -U 4zreco "$DB_NAME"

export ZRECO_PG_DSN="postgres://4zreco@127.0.0.1:$PORT/$DB_NAME?sslmode=disable"
echo "setup-postgres: ZRECO_PG_DSN=$ZRECO_PG_DSN"

cd "$ROOT"
# 参数若给了包/测试选择子就用给的，否则默认全量（./...）。
if [[ $# -eq 0 ]]; then
  set -- ./...
fi
# -p 1 不能去：连 PG 的包之间有跨包 advisory lock，并行会死锁（AGENTS.md §1）。
go test -p 1 -count=1 "$@"
