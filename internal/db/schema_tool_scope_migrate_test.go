package db

import "testing"

// tool_scope 是加在 create 之后的新列，已发版库只能靠 schema.sql 的幂等
// ALTER 补上。这里把表回退到无列形态，再跑真实 schema，验证补列与重复执行。
// 全过程在事务内进行（PG 支持事务性 DDL），测试结束即回滚，不会留下痕迹。
func TestSchemaMigrateAddsInterceptToolScope(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tx, err := d.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // 测试永不提交

	// 回退到加列前的形态。
	if _, err := tx.Exec(`ALTER TABLE intercept_rules DROP COLUMN IF EXISTS tool_scope`); err != nil {
		t.Fatalf("simulate pre-upgrade table: %v", err)
	}

	// 跑真实 schema（生产每次启动都会整份执行）。
	if _, err := tx.Exec(schemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}

	var (
		n          int
		isNullable string
		def        string
	)
	if err := tx.QueryRow(`
SELECT count(*), COALESCE(MAX(is_nullable),''), COALESCE(MAX(column_default),'')
  FROM information_schema.columns
 WHERE table_name='intercept_rules' AND column_name='tool_scope'`).Scan(&n, &isNullable, &def); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if n != 1 {
		t.Fatal("tool_scope 列未补上")
	}
	if isNullable != "NO" {
		t.Fatalf("tool_scope 应为 NOT NULL，实际 is_nullable=%s", isNullable)
	}
	if def != "'[]'::jsonb" {
		t.Fatalf("tool_scope 默认值应为 '[]'::jsonb，实际 %q", def)
	}

	// 再跑一次：幂等（生产每次启动都会重复执行整份 schema）。
	if _, err := tx.Exec(schemaSQL); err != nil {
		t.Fatalf("schema 第二次执行应幂等: %v", err)
	}
}
