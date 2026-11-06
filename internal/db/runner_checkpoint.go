package db

// runner_checkpoint.go — 刀④（docs/Eino深度接入方案-2026-11-05.md §4-P1 第 7/8 条）
// 的两张落库面：
//
//   - runner_checkpoints：装配指纹留痕（P2 HITL 恢复校验用，P1 只写不读）；
//   - exploration_nodes.empty_turn_nudges：空转回合续跑预算的「每条意图总量」
//     计数（等价 norma defaultEmptyTurnNudges=2；路线 A 上移 engine 后由 driver
//     经这两个方法读写，跨 run/跨 model_error 重试持久）。

import (
	"context"
)

// RecordRunnerCheckpoint persists one assembly fingerprint row (per primary
// kernel run). P2 起 checkpointID 非空时与 SetCheckpoint 落在同一行（部分唯一
// 索引上的 upsert：装配方拥有 fingerprint/session/agent 字段，SetCheckpoint 拥有
// payload 字段——两个写者互不覆盖，先到者建行后到者补字段）。
func (d *DB) RecordRunnerCheckpoint(ctx context.Context, sessionID, agentKey, checkpointID, fingerprint string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO runner_checkpoints
(session_id, agent_key, checkpoint_id, fingerprint)
VALUES ($1, $2, $3, $4)
ON CONFLICT (checkpoint_id) WHERE checkpoint_id <> '' DO UPDATE
SET session_id=EXCLUDED.session_id, agent_key=EXCLUDED.agent_key, fingerprint=EXCLUDED.fingerprint,
    created_at=now()`, // 重录即重盖时刻，保住 LatestRunnerCheckpoint 的「最新行」语义
		sessionID, agentKey, checkpointID, fingerprint)
	return err
}

// LatestRunnerCheckpoint returns the newest fingerprint recorded for a session
// (P2 resume verification reads this; empty string when none).
func (d *DB) LatestRunnerCheckpoint(ctx context.Context, sessionID string) (string, error) {
	var fp string
	err := d.QueryRowContext(ctx, `SELECT fingerprint FROM runner_checkpoints
WHERE session_id=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, sessionID).Scan(&fp)
	if err != nil {
		return "", err
	}
	return fp, nil
}

// EmptyTurnNudges returns the persisted empty-turn nudge count for one intent.
func (s *ExplorationStore) EmptyTurnNudges(intentID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT empty_turn_nudges FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='intent'`, intentID, s.expID).Scan(&n)
	return n, err
}

// IncrEmptyTurnNudges atomically bumps the intent's nudge counter and returns
// the new value — the driver's check-then-inject races are resolved in SQL.
func (s *ExplorationStore) IncrEmptyTurnNudges(intentID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`UPDATE exploration_nodes
SET empty_turn_nudges = empty_turn_nudges + 1
WHERE id=$1 AND exploration_id=$2 AND kind='intent'
RETURNING empty_turn_nudges`, intentID, s.expID).Scan(&n)
	return n, err
}
