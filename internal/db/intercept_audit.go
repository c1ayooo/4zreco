package db

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// 审批决定 HMAC-SHA256 哈希链（P0-3）。
//
// 串行化：写决定行前在事务内取 pg_advisory_xact_lock(hashtext('intercept_chain'))，
// 两条并发 decide 因此串行——后提交者读到前者回写后的链头，链不断、seq 无空洞
//（回滚的事务不占用 seq）。row_hash = HMAC(audit_key, canonical(行字段))，
// seq 单调、写进行内。归档恢复补插的旧行 seq=NULL 落「历史区」（锚行之前），
// 不接链尾；/api/audit/verify 只对 seq 非空的行逐行校验，历史区单独计数。
//
// audit_key 与 jwt.key 严格分离（服务端各自独立文件，见 config.Paths.AuditKeyPath）：
// jwt.key 改密码即轮换，若从它派生，改一次密码全部历史哈希链验签失效。

const auditChainID = "intercept"

// SetAuditKey installs the HMAC key for the approval hash chain. The key is
// loaded from its own persisted file by the server layer (audit.key, 与
// jwt.key 分离) — a nil/empty key degrades to an unkeyed MAC so the chain
// never blocks startup, and is only expected in tests.
func (d *DB) SetAuditKey(key []byte) {
	d.auditKey.Store(append([]byte{}, key...))
}

func (d *DB) auditChainKey() []byte {
	if v, ok := d.auditKey.Load().([]byte); ok && len(v) > 0 {
		return v
	}
	return []byte{}
}

// formatChainTime normalizes timestamps to microsecond precision (PG
// timestamptz resolution) so the canonical string round-trips through the
// database byte-for-byte — otherwise verify would reject its own writes.
func formatChainTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}

// chainRowHash computes HMAC-SHA256(audit_key, canonical(row)) for one decision.
func (d *DB) chainRowHash(seq int64, prevHash string, pendingID int64, decision, action, reason, decidedBy, decisionSource string, decidedAt time.Time) string {
	canonical := fmt.Sprintf("v1\nchain=%s\nseq=%d\nprev=%s\npending=%d\ndecision=%s\naction=%s\nreason=%s\ndecided_by=%s\nsource=%s\nat=%s",
		auditChainID, seq, prevHash, pendingID, decision, action, reason, decidedBy, decisionSource, formatChainTime(decidedAt))
	mac := hmac.New(sha256.New, d.auditChainKey())
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// ensureAuditAnchorTx inserts the seq=0 anchor row when absent and seeds the
// chain head with its hash, so the first real decision's prev_hash links to the
// anchor (链从锚行起算). It must run inside a transaction that already holds the
// chain advisory lock, so concurrent writers cannot both see "absent".
func (d *DB) ensureAuditAnchorTx(tx *sql.Tx) error {
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM intercept_decisions WHERE seq=0 AND decision='anchor')`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	now := time.Now().UTC()
	hash := d.chainRowHash(0, "", 0, "anchor", "", "", "", "anchor", now)
	if _, err := tx.Exec(`INSERT INTO intercept_decisions(pending_id, decision, action, decision_reason, decided_by, decision_source, decided_at, seq, prev_hash, row_hash)
VALUES (NULL, 'anchor', '', '', '', 'anchor', $1, 0, '', $2)`, now, hash); err != nil {
		return err
	}
	// 链头从初始空态推进到锚行；已在活跃链上的情况不动（锚行被 GUC 删除后重建的防御）。
	_, err := tx.Exec(`UPDATE audit_chain_head SET last_hash=$2, updated_at=now() WHERE chain_id=$1 AND last_seq=0 AND last_hash=''`, auditChainID, hash)
	return err
}

// appendChainDecisionTx appends one decision row to the hash chain inside tx
// (which must already hold the chain advisory lock), advancing the chain head.
func (d *DB) appendChainDecisionTx(tx *sql.Tx, pendingID int64, decision, action, reason, decidedBy, decisionSource string) (int64, error) {
	var lastSeq int64
	var lastHash string
	if err := tx.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE chain_id=$1 FOR UPDATE`, auditChainID).Scan(&lastSeq, &lastHash); err != nil {
		return 0, fmt.Errorf("read chain head: %w", err)
	}
	seq := lastSeq + 1
	decidedAt := time.Now().UTC()
	rowHash := d.chainRowHash(seq, lastHash, pendingID, decision, action, reason, decidedBy, decisionSource, decidedAt)
	if _, err := tx.Exec(`INSERT INTO intercept_decisions(pending_id, decision, action, decision_reason, decided_by, decision_source, decided_at, seq, prev_hash, row_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		pendingID, decision, action, reason, decidedBy, decisionSource, decidedAt, seq, lastHash, rowHash); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE audit_chain_head SET last_seq=$2, last_hash=$3, updated_at=now() WHERE chain_id=$1`,
		auditChainID, seq, rowHash); err != nil {
		return 0, err
	}
	return seq, nil
}

// appendExecutionTx pre-inserts the execution row a decision implies:
// allow + exact correlation → awaiting_result (the result callback appends the
// terminal row later); allow + non-exact → unknown (无法唯一关联，等价旧行为);
// deny/timeout → not_executed. This must run inside the decide transaction.
func (d *DB) appendExecutionTx(tx *sql.Tx, pendingID int64, action string) error {
	status := "not_executed"
	if action == "allow" {
		status = "awaiting_result"
		var corr string
		if err := tx.QueryRow(`SELECT COALESCE(audit->>'correlation','') FROM intercept_pending WHERE id=$1`, pendingID).Scan(&corr); err != nil {
			return err
		}
		if corr != "exact" {
			status = "unknown"
		}
	}
	_, err := tx.Exec(`INSERT INTO intercept_executions(pending_id, run_id, tool_use_id, execution_status, ended_at)
SELECT $1, COALESCE(audit->>'run_id',''), COALESCE(audit->>'tool_use_id',''), $2,
       CASE WHEN $2='awaiting_result' THEN NULL ELSE now() END
FROM intercept_pending WHERE id=$1`, pendingID, status)
	return err
}

// AuditChainStatus is the /api/audit/verify response. HistoryRows counts
// decision rows outside the chain (legacy backfill / archive restore, 锚行之前)
// which are reported but never per-row verified; BrokenAtSeq pins the first
// inconsistency (0 = the anchor itself, >0 = a chained decision).
type AuditChainStatus struct {
	OK          bool   `json:"ok"`
	ChainID     string `json:"chain_id"`
	LastSeq     int64  `json:"last_seq"`
	Checked     int64  `json:"checked"`
	HistoryRows int64  `json:"history_rows"`
	BrokenAtSeq int64  `json:"broken_at_seq"`
	Reason      string `json:"reason,omitempty"`
}

// VerifyAuditChain re-walks the approval decision hash chain: anchor at seq 0,
// then every decision 1..last_seq with seq continuity, prev_hash linkage and
// recomputed HMAC row_hash. Rows with seq IS NULL are the history zone — they
// are counted, not verified (旧行本就不接链；归档恢复不得污染链校验).
func (d *DB) VerifyAuditChain() (*AuditChainStatus, error) {
	st := &AuditChainStatus{OK: true, ChainID: auditChainID}
	var lastSeq int64
	var lastHash string
	err := d.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE chain_id=$1`, auditChainID).Scan(&lastSeq, &lastHash)
	if err == sql.ErrNoRows {
		st.OK = false
		st.Reason = "链头缺失"
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	st.LastSeq = lastSeq
	if err := d.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE seq IS NULL`).Scan(&st.HistoryRows); err != nil {
		return nil, err
	}
	if lastSeq == 0 {
		// 空链（新装/刚迁移、尚无任何决定写入）是合法状态：锚行在首次决定时
		// 惰性创建，verify 对它报异常会让每个新实例初始就亮红灯。只有「已有
		// 接链行但锚行丢了」才是不一致。
		var chained int
		if err := d.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE seq IS NOT NULL`).Scan(&chained); err != nil {
			return nil, err
		}
		if chained > 0 {
			st.OK = false
			st.BrokenAtSeq = 0
			st.Reason = "锚行缺失"
		}
		return st, nil
	}
	rows, err := d.Query(`SELECT seq, prev_hash, row_hash, COALESCE(pending_id,0), decision, action, decision_reason, decided_by, decision_source, decided_at
FROM intercept_decisions WHERE seq IS NOT NULL AND seq <= $1 ORDER BY seq`, lastSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var expectedSeq int64 = -1
	var prevRowHash string
	for rows.Next() {
		var seq int64
		var prevHash, rowHash, decision, action, reason, decidedBy, decisionSource string
		var pendingID int64
		var decidedAt time.Time
		if err := rows.Scan(&seq, &prevHash, &rowHash, &pendingID, &decision, &action, &reason, &decidedBy, &decisionSource, &decidedAt); err != nil {
			return nil, err
		}
		if seq != expectedSeq+1 {
			st.OK = false
			st.BrokenAtSeq = expectedSeq + 1
			st.Reason = "seq 断档"
			return st, nil
		}
		expectedSeq = seq
		if seq == 0 {
			if decision != "anchor" || rowHash != d.chainRowHash(0, "", 0, "anchor", "", "", "", "anchor", decidedAt) {
				st.OK = false
				st.BrokenAtSeq = 0
				st.Reason = "锚行被篡改或缺失"
				return st, nil
			}
			prevRowHash = rowHash
			st.Checked++
			continue
		}
		if prevHash != prevRowHash || rowHash != d.chainRowHash(seq, prevHash, pendingID, decision, action, reason, decidedBy, decisionSource, decidedAt) {
			st.OK = false
			st.BrokenAtSeq = seq
			st.Reason = "行哈希校验失败"
			return st, nil
		}
		prevRowHash = rowHash
		st.Checked++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if expectedSeq < lastSeq {
		st.OK = false
		st.BrokenAtSeq = expectedSeq + 1
		st.Reason = "链尾缺失"
		return st, nil
	}
	if lastHash != prevRowHash {
		st.OK = false
		st.BrokenAtSeq = expectedSeq
		st.Reason = "链头与尾行不一致"
		return st, nil
	}
	return st, nil
}
