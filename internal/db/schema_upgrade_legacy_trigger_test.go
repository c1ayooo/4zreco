package db

import (
	"context"
	"testing"
	"time"
)

// 生产升级首例的回归测试（2026-11-06，库 4zrec）：老部署带着 cb13bd0 原始形态的
// 不可变触发器（无 audit_writer 放行口）跑 apply schema 时，ask_source 回填
// UPDATE 被旧触发器拒绝，启动直接崩溃循环。修复口径：schema 在回填 DML 前先摘
// 旧触发器、文件尾统一重建（单隐式事务，原子性不变）。
//
// 本测试把共享测试库临时还原成「旧触发器 + decision_source 旧列」的升级前形态，
// 重放当前 schema，断言：迁移成功、回填正确、旧列退役、新触发器（带放行口）在位。
func TestApplySchemaUpgradesLegacyImmutableTrigger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "legacy-trigger-upgrade-" + t.Name()

	// 开跑前先清同名 scope（防上次失败残留行让计数断言翻车）；此时还是当前
	// schema，purgeInterceptRows 的 audit_writer 放行口可用。
	purgeInterceptRows(t, d, scope)

	reapplyCurrent := func(t *testing.T) {
		t.Helper()
		if err := applySchemaWithRetry(context.Background(), d.DB, time.Sleep); err != nil {
			t.Fatalf("re-apply current schema: %v", err)
		}
	}

	// ① 模拟老部署形态：旧列 decision_source + 旧版触发器（生产报错的原话文案，
	// 无放行口；函数用独立名，模拟老版本时代的函数与当前版并存）。
	legacy := []string{
		`ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decision_source TEXT NOT NULL DEFAULT ''`,
		`CREATE OR REPLACE FUNCTION deny_intercept_mutation_legacy() RETURNS trigger AS $fn$
		 BEGIN
		     RAISE EXCEPTION 'intercept_pending 为 append-only 审计表,UPDATE 被拒绝;决定请插入 intercept_decisions';
		 END;
		 $fn$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS trg_intercept_pending_immutable ON intercept_pending`,
		`CREATE TRIGGER trg_intercept_pending_immutable BEFORE UPDATE OR DELETE ON intercept_pending
		 FOR EACH ROW EXECUTE FUNCTION deny_intercept_mutation_legacy()`,
	}
	for _, stmt := range legacy {
		if _, err := d.Exec(stmt); err != nil {
			t.Fatalf("install legacy shape: %v\nstmt: %s", err, stmt)
		}
	}
	// Cleanup 注册顺序 = 退出时的执行顺序（t.Cleanup LIFO 反转后）：
	// 先重放当前 schema（恢复新触发器），再 purge（GUC 口径要新触发器才放行），
	// 最后清掉遗留函数。
	t.Cleanup(func() { purgeInterceptRows(t, d, scope) })
	t.Cleanup(func() { reapplyCurrent(t) })
	t.Cleanup(func() {
		_, _ = d.Exec(`DROP FUNCTION IF EXISTS deny_intercept_mutation_legacy()`)
	})

	// ② 铺三行旧数据（INSERT 不受限）：分别覆盖 rule / model / unknown 三条回填分支。
	seed := []struct {
		name   string
		stmt   string
		source string
	}{
		{"rule", `INSERT INTO intercept_pending(task_id, tool_name, decision_source) VALUES ($1,'Bash','rule')`, "rule"},
		{"model", `INSERT INTO intercept_pending(task_id, tool_name, reason, decision_source) VALUES ($1,'Bash','[模型] 可疑命令','')`, "model"},
		{"unknown", `INSERT INTO intercept_pending(task_id, tool_name, decision_source) VALUES ($1,'Bash','')`, "unknown"},
	}
	for _, s := range seed {
		if _, err := d.Exec(s.stmt, scope); err != nil {
			t.Fatalf("seed %s: %v", s.name, err)
		}
	}

	// 旧形态生效性预检：UPDATE 必须被旧触发器拒绝（行级触发器只在命中行上触发，
	// 所以上面先铺数据）——否则模拟失真，测试无意义。
	if _, err := d.Exec(`UPDATE intercept_pending SET reason='x' WHERE task_id=$1`, scope); err == nil {
		t.Fatal("legacy trigger did not reject UPDATE — simulation broken")
	}

	// ③ 重放当前 schema：修复点——回填前先摘旧触发器。失败即回归。
	reapplyCurrent(t)

	// ④ 断言：ask_source 回填正确、旧列已退役。
	var n int
	for _, s := range seed {
		if err := d.QueryRow(
			`SELECT count(*) FROM intercept_pending WHERE task_id=$1 AND ask_source=$2`,
			scope, s.source,
		).Scan(&n); err != nil {
			t.Fatalf("verify %s: %v", s.name, err)
		}
		if n != 1 {
			t.Fatalf("ask_source backfill for %s: want 1 row with %q, got %d", s.name, s.source, n)
		}
	}
	if err := d.QueryRow(
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_schema=current_schema() AND table_name='intercept_pending' AND column_name='decision_source'`,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("decision_source should be dropped after upgrade")
	}

	// ⑤ 新触发器在位且保持不可变语义：UPDATE 拒绝、audit_writer 放行。
	if _, err := d.Exec(`UPDATE intercept_pending SET reason='tampered' WHERE task_id=$1`, scope); err == nil {
		t.Fatal("current trigger must reject UPDATE without audit_writer")
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL app.role='audit_writer'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE intercept_pending SET reason='migrated' WHERE task_id=$1`, scope); err != nil {
		t.Fatalf("audit_writer must be allowed: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
