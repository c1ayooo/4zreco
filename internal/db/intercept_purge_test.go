package db

import (
	"testing"
)

// purgeInterceptRows removes all approval rows of the given task scopes — the
// only sanctioned mutation path for tests: 三表 append-only 触发器拒绝普通
// UPDATE/DELETE，测试清理必须走 audit_writer GUC 事务（与迁移/归档同一放行口）。
func purgeInterceptRows(t *testing.T, d *DB, scopes ...string) {
	t.Helper()
	if len(scopes) == 0 {
		return
	}
	fail := func(format string, args ...any) {
		if t.Failed() {
			t.Logf(format, args...) // 原始失败已在，清理错误只记录不覆盖
			return
		}
		t.Errorf(format, args...)
	}
	tx, err := d.Begin()
	if err != nil {
		fail("purge begin: %v", err)
		return
	}
	if _, err := tx.Exec(`SET LOCAL app.role='audit_writer'`); err != nil {
		fail("purge set role: %v", err)
		_ = tx.Rollback()
		return
	}
	for _, stmt := range []string{
		`DELETE FROM intercept_executions WHERE pending_id IN (SELECT id FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[]))`,
		`DELETE FROM intercept_decisions WHERE pending_id IN (SELECT id FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[]))`,
		`DELETE FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[])`,
	} {
		if _, err := tx.Exec(stmt, scopes); err != nil {
			fail("purge: %v (%s)", err, stmt)
			_ = tx.Rollback()
			return
		}
	}
	if err := tx.Commit(); err != nil {
		fail("purge commit: %v", err)
	}
}

// rewindChainHeadToSurvivors 把链头回拨到**仍然存活的最高接链行**（含锚行）。
// 测试用 GUC 删除接链行后必须调用它——直接回放旧快照会让链头指向已删除的行，
// 或让链头与锚行脱钩（下一条决定 prev_hash 接不上）。锚行也被删光时回拨到
// 初始空态 {0,""}，下一次 ensureAuditAnchor 会重建锚行并重新接上链头。
// Cleanup 阶段不允许 FailNow（会 panic 并吞掉原始失败），只记错误。
func rewindChainHeadToSurvivors(t *testing.T, d *DB) {
	t.Helper()
	var seq int64
	var hash string
	err := d.QueryRow(`SELECT COALESCE(max(seq),0),
COALESCE((SELECT row_hash FROM intercept_decisions WHERE seq=(SELECT max(seq) FROM intercept_decisions) AND seq IS NOT NULL),'')
FROM intercept_decisions WHERE seq IS NOT NULL`).Scan(&seq, &hash)
	if err != nil {
		t.Errorf("rewind chain head (read): %v", err)
		return
	}
	if _, err := d.Exec(`UPDATE audit_chain_head SET last_seq=$2, last_hash=$3, updated_at=now() WHERE chain_id=$1`,
		"intercept", seq, hash); err != nil {
		t.Errorf("rewind chain head (update): %v", err)
	}
}

// readChainHead reads the current chain head for assertions.
func readChainHead(d *DB) (int64, string) {
	var seq int64
	var hash string
	if err := d.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE chain_id='intercept'`).Scan(&seq, &hash); err != nil {
		return 0, ""
	}
	return seq, hash
}
