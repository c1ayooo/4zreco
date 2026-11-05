package agent

import (
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// purgeAgentInterceptRows 是本包测试清理审批行的唯一放行路径：三表 append-only
// 触发器拒绝普通 DELETE，测试清理走 audit_writer GUC 事务（与迁移/归档同口）。
// 删除接链决定行会让链头悬空，收尾时回拨到存活行。
func purgeAgentInterceptRows(t *testing.T, d *db.DB, scopes ...string) {
	t.Helper()
	if len(scopes) == 0 {
		return
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL app.role='audit_writer'`); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DELETE FROM intercept_executions WHERE pending_id IN (SELECT id FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[]))`,
		`DELETE FROM intercept_decisions WHERE pending_id IN (SELECT id FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[]))`,
		`DELETE FROM intercept_pending WHERE COALESCE(task_id,'')=ANY($1::text[])`,
	} {
		if _, err := tx.Exec(stmt, scopes); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var seq int64
	var hash string
	if err := d.QueryRow(`SELECT COALESCE(max(seq),0),
COALESCE((SELECT row_hash FROM intercept_decisions WHERE seq=(SELECT max(seq) FROM intercept_decisions) AND seq IS NOT NULL),'')
FROM intercept_decisions WHERE seq IS NOT NULL`).Scan(&seq, &hash); err == nil {
		_, _ = d.Exec(`UPDATE audit_chain_head SET last_seq=$2, last_hash=$3 WHERE chain_id=$1`, "intercept", seq, hash)
	}
}
