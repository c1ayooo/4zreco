package db

import "fmt"

// 内置规则动作的一次性迁移：把「一律 deny」改成「明令禁止 / 交给 Agent 研判 /
// 人工确认」三分。
//
// 背景（2026-10-22 的整改）：内置规则此前**全部**是 deny，规则层就把每一类
// 调用都拍板了——「明令禁止」和「交给 Agent 研判」在规则层根本没有分开，模型
// 从来没机会看这些命令。后果有两面：
//   - 该拦的拦了，但每次都要白烧一次本可以不调用的模型往返；
//   - 不该拦的直接拦死（删自己建的测试表这种合法操作被当成破坏）。
//
// 新的划界（判据见 db/intercept_builtin_rules.go）：任何语境都不可逆且无合法
// 用途 → 仍是 deny；作用对象取决于上下文 → 改成 judge；只改平台自身状态 → ask。
//
// ## 怎么保证不覆盖用户自己改过的规则
//
// 内置规则是 first-insert only 的 seed，改代码对已部署实例无效，所以这里用
// 一次性迁移。判定「这行还是内置默认值」用的是**旧默认指纹**：只有当行的
// action / pattern / timeout 组合仍与旧默认一致时才更新。用户把自己的规则
// 改成 judge、停用、改了 pattern 或改了超时策略，行为一律保持。

// 旧默认指纹：v1/v2/v3 的旧默认统一是 deny + timeout(false, 60, deny)；
// v4 的 listener 旧默认是 ask + timeout(true, 180, allow)。
const (
	oldDenyAction   = "deny"
	oldDenyTimeoutE = false
	oldDenyTimeoutS = 60
	oldDenyTimeoutA = "deny"

	oldListenerAction = "ask"
	oldListenerTE     = true
	oldListenerTS     = 180
	oldListenerTA     = "allow"
)

// oldRuleNames 记录每条新规则在旧库里的名字。
//
// v1 的 DROP 规则是**一条**覆盖 DATABASE/TABLE/SCHEMA/INDEX/VIEW/... 的合并
// 规则；整改后拆成两条：
//   - DROP DATABASE / SCHEMA → 明令禁止
//   - DROP TABLE / INDEX / VIEW 等 → 交给 Agent 研判
//
// 拆分时旧的那一条要**改名**成研判那条（保持「用户没动过」的可判定性），
// 而硬禁那条是新名字——它需要被**插入**（不是改名，否则就少了硬禁那条）。
// 所以这里用「旧名 → 新名」表示改名，用 renameTargets 标记哪些需要改名。
var oldRuleNames = map[string]string{
	"[内置] SQL DROP DATABASE / SCHEMA":      "[内置] SQL DROP DATABASE / TABLE / SCHEMA",
	"[内置] SQL DROP TABLE / INDEX / VIEW":   "[内置] SQL DROP DATABASE / TABLE / SCHEMA",
}

// oldRulePatterns 记录部分规则在旧库里的 pattern。
//
// 只登记**与新定义不同**的那些——其余规则的 pattern 本来就没变，迁移不必
// 动它（也不必拿它做「用户没动过」的判据）。
//
// 用途有两个：
//  1. 作为「用户没动过 pattern」的判据——用户改过 pattern 的规则不能被覆盖；
//  2. 迁移时把旧 pattern 换成新的（数据外泄规则换 pattern 是本次整改的一部分）。
var oldRulePatterns = map[string]string{
	"[内置] SQL DROP DATABASE / TABLE / SCHEMA": `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
	"[内置] 数据外泄管道":                       `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
}

// migrationSQL 是 migrateBuiltinRuleActions 实际执行的两条 UPDATE 的形状。
//
// 之所以把它抽成可测的纯函数：迁移函数本身要 DB 才能跑，而 SQL 的正确性
// （占位符编号连续、参数个数匹配、指纹齐全）是纯字符串问题——把它从 DB
// 依赖里剥出来才能在 CI 上真正被测。
type migrationSQL struct {
	sql   string
	args  []any
	stage string
}

// buildMigrationSQL 构造迁移要执行的全部 UPDATE（与 migrateBuiltinRuleActions
// 保持同构）。真实实现调用它，测试也断言它——两处不会漂移。
func buildMigrationSQL() []migrationSQL {
	var out []migrationSQL

	// 1) 改名：旧的合并 DROP 规则 → 研判那条的新名。
	oldDropName := "[内置] SQL DROP DATABASE / TABLE / SCHEMA"
	newDropJudgeName := "[内置] SQL DROP TABLE / INDEX / VIEW"
	out = append(out, migrationSQL{
		stage: "rename-drop",
		sql: `
UPDATE intercept_rules SET name=$2
 WHERE name=$1
   AND action=$3 AND timeout_enabled=$4 AND timeout_seconds=$5 AND timeout_action=$6
   AND pattern=$7`,
		args: []any{oldDropName, newDropJudgeName,
			oldDenyAction, oldDenyTimeoutE, oldDenyTimeoutS, oldDenyTimeoutA,
			oldRulePatterns[oldDropName]},
	})

	// 2) 逐条更新。
	for _, r := range builtinInterceptRules {
		oldName := r.name
		if old, ok := oldRuleNames[r.name]; ok {
			oldName = old
		}
		oldPat, hasOldPat := oldRulePatterns[oldName]
		patChanged := hasOldPat && oldPat != r.pattern

		cond := `action=$2 AND timeout_enabled=$3 AND timeout_seconds=$4 AND timeout_action=$5`
		args := []any{r.name, oldDenyAction, oldDenyTimeoutE, oldDenyTimeoutS, oldDenyTimeoutA}
		if r.class == classAsk {
			args = []any{r.name, oldListenerAction, oldListenerTE, oldListenerTS, oldListenerTA}
		}
		if hasOldPat {
			cond += fmt.Sprintf(" AND pattern=$%d", len(args)+1)
			args = append(args, oldPat)
		}
		// 新值接在判据参数之后，编号必须连续。
		//
		// 参数的 append 顺序必须与 SQL 里占位符的顺序**完全一致**：
		//   $1        name（判据）
		//   $2..$5    旧默认指纹（action / timeout 三元组）
		//   $6        旧 pattern（仅当该规则有已知旧 pattern）
		//   $7..$11   新值（action / message / timeout_enabled / timeout_seconds /
		//              timeout_action）
		//   $12       新 pattern（仅当 pattern 确实要换）
		//
		// 之前把 pattern 先 append、新值后 append，与 SQL 的编号顺序相反——整段
		// 参数错位，CI 上直接报 "encode false into int4"（timeout_seconds 那个
		// 位置收到的是 bool）。这类错位只有真跑一次 PG 才暴露得出来，所以它
		// 同时是「参数顺序必须与占位符顺序一致」那条断言的由来。
		setSQL := fmt.Sprintf(`
UPDATE intercept_rules
   SET action=$%d, message=$%d, timeout_enabled=$%d, timeout_seconds=$%d, timeout_action=$%d`,
			len(args)+1, len(args)+2, len(args)+3, len(args)+4, len(args)+5)
		args = append(args, r.action, r.message, r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction)
		if patChanged {
			setSQL += fmt.Sprintf(", pattern=$%d", len(args)+1)
			args = append(args, r.pattern)
		}
		out = append(out, migrationSQL{
			stage: "update:" + r.name,
			sql:   setSQL + "\n WHERE name=$1 AND " + cond,
			args:  args,
		})
	}
	return out
}

// migrateBuiltinRuleActions 把内置规则的动作改成新的三分，并补上拆分出来的
// 新规则、更换需要更换的 pattern。
//
// 迁移分三步，顺序不能换：
//  1. 改名：把旧的合并 DROP 规则改成研判那条的新名字（改名前按旧默认指纹
//     判定「用户没动过」）。
//  2. 更新：按新定义更新 action / message / timeout / pattern。
//  3. 插入：拆分出来的新规则（硬禁的 DROP DATABASE/SCHEMA）插入。
func (d *DB) migrateBuiltinRuleActions() error {
	const flag = "intercept_builtin_rule_actions_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, m := range buildMigrationSQL() {
		if _, err := d.Exec(m.sql, m.args...); err != nil {
			return fmt.Errorf("migrate builtin rule actions (%s): %w", m.stage, err)
		}
	}
	// 3) 插入：拆分出来的新规则（硬禁的 DROP DATABASE / SCHEMA）。
	//
	// 用 INSERT ... WHERE NOT EXISTS：用户已经自己建了同名规则时不覆盖。
	for _, r := range builtinInterceptRules {
		if _, ok := oldRuleNames[r.name]; !ok {
			continue // 旧库里就有这条，改名或更新已处理
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("insert split rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}

