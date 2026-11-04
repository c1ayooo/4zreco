#!/usr/bin/env bash
# devtest.sh — 全量测试（真 PostgreSQL）一键跑：Docker 起 PG → 新鲜 4zreco_ci 库 →
# ZRECO_PG_DSN=... go test -p 1 ./... -count=1。
#
# 为什么必须新鲜库：测试里有固定名 fixture（唯一键），共享库连跑多轮会撞键产生假失败。
# 为什么 -p 1：跨包并行会死锁（AGENTS.md §1）。
#
# 用法：
#   ./scripts/devtest.sh                                # 全量（默认新建 4zreco_ci）
#   ./scripts/devtest.sh ./internal/agent/ -run TestGraphOverview
#   SKIP_FRESH=1 ./scripts/devtest.sh ./server/         # 复用现有库（快速迭代,可能假失败）
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER=4zreco-devtest-pg
PORT=15432
DSN="postgres://4zreco:4zrecotest@127.0.0.1:${PORT}/4zreco_ci?sslmode=disable"

fail() { echo "[devtest] $*" >&2; exit 1; }

# 1) Docker 可用性
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 \
  || fail "Docker 不可用（需要本机 Docker Desktop/daemon 在跑）。也可手工起库后直接设 ZRECO_PG_DSN 跑 go test。"

# 2) 容器：不存在→创建；存在未跑→启动；跑着→复用
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "[devtest] 创建容器 $CONTAINER (postgres:16-alpine :$PORT)"
  docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=4zrecotest -e POSTGRES_USER=4zreco \
    -e POSTGRES_DB=4zreco -p "${PORT}:5432" postgres:16-alpine >/dev/null \
    || fail "docker run 失败"
elif [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
  echo "[devtest] 启动已存在的容器 $CONTAINER"
  docker start "$CONTAINER" >/dev/null || fail "docker start 失败"
fi

# 3) 等待 PG ready（有界轮询，不用 sleep 猜）
ready=0
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" pg_isready -U 4zreco -d 4zreco >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || fail "PG 30 次轮询后仍未 ready（docker logs $CONTAINER 看原因）"

# 4) 新鲜库（默认）——先掐断残留连接再 DROP，否则 drop 会被占用挡住
if [ "${SKIP_FRESH:-0}" != "1" ]; then
  echo "[devtest] 重建 4zreco_ci（新鲜库）"
  docker exec "$CONTAINER" psql -U 4zreco -d postgres -q \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='4zreco_ci'" >/dev/null
  docker exec "$CONTAINER" psql -U 4zreco -d postgres -q -c "DROP DATABASE IF EXISTS 4zreco_ci" >/dev/null
  docker exec "$CONTAINER" psql -U 4zreco -d postgres -q -c "CREATE DATABASE 4zreco_ci OWNER 4zreco" >/dev/null \
    || fail "重建 4zreco_ci 失败"
fi

# 5) 跑测试（透传包/参数；缺省全量）
PKGS=("$@")
if [ ${#PKGS[@]} -eq 0 ]; then PKGS=(./...); fi
echo "[devtest] go test -p 1 ${PKGS[*]} -count=1  (DSN=4zreco_ci@127.0.0.1:$PORT)"
ZRECO_PG_DSN="$DSN" go test -p 1 "${PKGS[@]}" -count=1
