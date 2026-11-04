#!/usr/bin/env bash
# 项目管理与对话绑定 · HTTP 层端到端烟测
# 对应 docs/项目管理与对话绑定改造-2026-11-04.md §4.3 验收链路。
#
# 用法：先对一个全新数据库起好 4zreco（无 LLM 也能跑，任务只创建不运行），
# 然后执行本脚本。环境变量：
#   SMOKE_BASE   API 基址（默认 http://127.0.0.1:18923/api）
#   SMOKE_PASS   管理密码（默认 SmokeTest#2026；未初始化会自动 init）
#   SMOKE_PSQL   psql 检查命令前缀（默认 docker exec 4zreco-audit-pg psql -U 4zreco -d 4zreco_ci -tAc）
set -u
B=${SMOKE_BASE:-http://127.0.0.1:18923/api}
PW=${SMOKE_PASS:-SmokeTest#2026}
PSQL=${SMOKE_PSQL:-"docker exec 4zreco-audit-pg psql -U 4zreco -d 4zreco_ci -tAc"}

T=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' -d "{\"username\":\"4ZRECO\",\"password\":\"$PW\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')
if [ -z "$T" ]; then
  T=$(curl -s -X POST $B/auth/init -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))')
fi
[ -n "$T" ] || { echo "认证失败：无法 login/init"; exit 1; }
AUTH="Authorization: Bearer $T"
CT='Content-Type: application/json'
pass=0; fail=0
ck() { if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "PASS $3"; else fail=$((fail+1)); echo "FAIL $3 (got=$1 want=$2)"; echo "  detail: $4"; fi }

# 1. 建项目
P=$(curl -s -X POST $B/projects -H "$AUTH" -H "$CT" -d '{"name":"烟测项目","description":"端到端验收"}')
PID=$(echo "$P" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))')
ck "$([ -n "$PID" ] && echo y)" y "POST /projects 建项目" "$P"

# 2. 录范围（2 有效 + 1 非法(过宽网段) + 1 重复）
S=$(curl -s -X POST $B/projects/$PID/scope -H "$AUTH" -H "$CT" -d '{"scope":"smoke.example.com\n198.51.100.0/24\n10.0.0.0/8\nsmoke.example.com","reason":"委托书"}')
A=$(echo "$S" | S="$S" python3 -c 'import json,sys,os;d=json.loads(os.environ["S"]);print(str(d["added"])+"/"+str(d["invalid"])+"/"+str(len(d["errors"])))')
ck "$A" "2/1/1" "POST scope 解析护栏(added/invalid/errors)" "$S"

# 3. 项目列表富化
L=$(curl -s $B/projects -H "$AUTH")
N=$(echo "$L" | L="$L" PID="$PID" python3 -c 'import json,sys,os;d=json.loads(os.environ["L"])["projects"];p=[x for x in d if x["id"]==int(os.environ["PID"])][0];print(str(len(p["scope"]))+"/"+str(p["task_count"]))')
ck "$N" "2/0" "GET /projects scope+计数富化" "$L"

# 4. 建任务挂项目（先验两条错误路径）
E1=$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/tasks -H "$AUTH" -H "$CT" -d '{"description":"x","goal":"y","project_id":99999}')
ck "$E1" 400 "POST /tasks project_id 不存在→400" ""
ARCH=$(curl -s -X PATCH $B/projects/$PID -H "$AUTH" -H "$CT" -d '{"name":"烟测项目","description":"","status":"archived"}' >/dev/null; curl -s -o /dev/null -w '%{http_code}' -X POST $B/tasks -H "$AUTH" -H "$CT" -d "{\"description\":\"x\",\"goal\":\"y\",\"project_id\":$PID}")
ck "$ARCH" 400 "POST /tasks 归档项目→400" ""
curl -s -X PATCH $B/projects/$PID -H "$AUTH" -H "$CT" -d '{"name":"烟测项目","description":"端到端验收","status":"active"}' >/dev/null

T=$(curl -s -X POST $B/tasks -H "$AUTH" -H "$CT" -d "{\"name\":\"烟测任务\",\"description\":\"验证项目种子\",\"goal\":\"全链路\",\"project_id\":$PID}")
TID=$(echo "$T" | TJ="$T" python3 -c 'import json,sys,os;d=json.loads(os.environ["TJ"]);print(d.get("id",""))')
TP=$(echo "$T" | TJ="$T" python3 -c 'import json,sys,os;d=json.loads(os.environ["TJ"]);print(d.get("project_id"))')
ck "$TP" "$PID" "POST /tasks 带 project_id 创建并回显" "$T"

# 5. task_scope 种子（psql 直查）
SEED=$($PSQL "SELECT count(*) FROM task_scope WHERE task_id=$TID AND source='project'")
ck "$SEED" 2 "task_scope 出现 2 条 source='project'" ""

# 6. 建会话 + PATCH 绑定任务（server 应把 project 对齐到任务所属项目）
C=$(curl -s -X POST $B/conversations -H "$AUTH" -H "$CT" -d '{"agent_key":"auto","title":"烟测会话"}')
CID=$(echo "$C" | C="$C" python3 -c 'import json,sys,os;d=json.loads(os.environ["C"]);print(d.get("id",""))')
UB=$(curl -s -X PATCH $B/conversations/$CID -H "$AUTH" -H "$CT" -d "{\"task_id\":$TID}")
B1=$(echo "$UB" | UB="$UB" python3 -c 'import json,sys,os;d=json.loads(os.environ["UB"]);print(str(d.get("task_id"))+"/"+str(d.get("project_id")))')
ck "$B1" "$TID/$PID" "PATCH task_id → project 自动对齐" "$UB"

# 7. PATCH 部分语义：省略=不改，0=清除；冲突拒绝
CONV=$(curl -s $B/conversations -H "$AUTH")
curl -s -X PATCH $B/conversations/$CID -H "$AUTH" -H "$CT" -d '{"title":"改了标题"}' >/dev/null
CONV=$(curl -s $B/conversations -H "$AUTH")
K=$(echo "$CONV" | CONV="$CONV" CID="$CID" python3 -c 'import json,sys,os;d=json.loads(os.environ["CONV"])["conversations"];c=[x for x in d if x["id"]==int(os.environ["CID"])][0];print(str(c["title"])+"/"+str(c.get("project_id"))+"/"+str(c.get("task_id")))')
ck "$K" "改了标题/$PID/$TID" "PATCH 仅 title 保留绑定" ""
curl -s -X PATCH $B/conversations/$CID -H "$AUTH" -H "$CT" -d '{"project_id":0}' >/dev/null
CONV=$(curl -s $B/conversations -H "$AUTH")
K2=$(echo "$CONV" | CONV="$CONV" CID="$CID" python3 -c 'import json,sys,os;d=json.loads(os.environ["CONV"])["conversations"];c=[x for x in d if x["id"]==int(os.environ["CID"])][0];print(str(c.get("project_id"))+"/"+str(c.get("task_id")))')
ck "$K2" "None/$TID" "PATCH project_id=0 清除挂载、task 保留" ""
P2=$(curl -s -X POST $B/projects -H "$AUTH" -H "$CT" -d '{"name":"另一个项目"}')
PID2=$(echo "$P2" | P2="$P2" python3 -c 'import json,sys,os;print(json.loads(os.environ["P2"]).get("id",""))')
CF=$(curl -s -o /dev/null -w '%{http_code}' -X PATCH $B/conversations/$CID -H "$AUTH" -H "$CT" -d "{\"task_id\":$TID,\"project_id\":$PID2}")
ck "$CF" 400 "PATCH 绑定冲突项目→400" ""

# 8. 删项目 → task/conversation 的 project_id 置空，行不删
DP=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE $B/projects/$PID -H "$AUTH")
ck "$DP" 200 "DELETE /projects/$PID" ""
D=$($PSQL "SELECT (SELECT project_id FROM tasks WHERE id=$TID) ISNULL AND (SELECT count(*) FROM project_scope WHERE project_id=$PID)=0 AND (SELECT count(*) FROM projects WHERE id=$PID)=0")
ck "$D" t "删项目级联：scope 清空、task.project_id 置空" ""
TASKS=$(curl -s $B/tasks -H "$AUTH")
TJ2=$(echo "$TASKS" | TASKS="$TASKS" TID="$TID" python3 -c 'import json,sys,os;d=json.loads(os.environ["TASKS"])["tasks"];t=[x for x in d if x["id"]==os.environ["TID"]][0];print(t.get("project_id"))')
ck "$TJ2" "None" "GET /tasks 回显 project_id=null(内存快照同步)" ""

# 9. 删任务 → conversation.task_id 置空
curl -s -X PATCH $B/conversations/$CID -H "$AUTH" -H "$CT" -d "{\"task_id\":$TID}" >/dev/null
CONV=$(curl -s $B/conversations -H "$AUTH")
CKB=$(echo "$CONV" | CONV="$CONV" CID="$CID" python3 -c 'import json,sys,os;d=json.loads(os.environ["CONV"])["conversations"];c=[x for x in d if x["id"]==int(os.environ["CID"])][0];print(c.get("task_id"))')
ck "$CKB" "$TID" "重新绑定 task_id" ""
$PSQL "DELETE FROM tasks WHERE id=$TID" >/dev/null
CONV=$(curl -s $B/conversations -H "$AUTH")
K3=$(echo "$CONV" | CONV="$CONV" CID="$CID" python3 -c 'import json,sys,os;d=json.loads(os.environ["CONV"])["conversations"];c=[x for x in d if x["id"]==int(os.environ["CID"])][0];print(c.get("task_id"))')
ck "$K3" "None" "删任务 → conversation.task_id 置空(FK SET NULL)" ""

# 清理烟测数据
curl -s -X DELETE $B/projects/$PID2 -H "$AUTH" >/dev/null
curl -s -X DELETE $B/conversations/$CID -H "$AUTH" >/dev/null
echo "----"; echo "PASS=$pass FAIL=$fail"
[ "$fail" = 0 ]
