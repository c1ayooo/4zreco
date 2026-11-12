package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// A8 无成果止损（移植自 ARTEX 0.3.29 db/task_no_result.go）。
//
// 任务创建时可设 no_result_seconds>0：活跃运行满该秒数时做一次（且仅一次）达标
// 漏洞检查——独立漏洞数（status != false_positive、达到 min_severity 阈值）少于
// min_findings → 建议收场（timeout 终态 + stop_reason='no_result'）。检查通过则
// 任务继续运行且不再检查（no_result_checked_at 落库即一次性断言）。

// StopReasonNoResult 是 timeout 终态家族下的无成果止损原因，落 tasks.stop_reason。
const StopReasonNoResult = "no_result"

// NormalizeNoResultOptions 由任务创建与 API 校验共用。秒数 <60 的非零值一律抬到
// 60（防止误填 1 秒把任务秒停）；min_findings 下限 1；min_severity 白名单校验
// （空串=不限等级）。纯函数，便于表驱动测试。
func NormalizeNoResultOptions(opts *TaskCreateOptions) error {
	if opts.NoResultSeconds < 0 {
		opts.NoResultSeconds = 0
	} else if opts.NoResultSeconds > 0 && opts.NoResultSeconds < 60 {
		opts.NoResultSeconds = 60
	}
	if opts.NoResultMinFindings < 1 {
		opts.NoResultMinFindings = 1
	}
	switch opts.NoResultMinSeverity {
	case "", "low", "medium", "high", "critical":
		return nil
	default:
		return fmt.Errorf("invalid no_result_min_severity: %q", opts.NoResultMinSeverity)
	}
}

// C1 落地后升级为独立漏洞口径（与 ARTEX 0.3.29 同款）：同一 case 文件夹的成员
// 折叠成一个实体 'c:<case_id>'，severity 取 case 统一评级（未评级时按空串，
// 只在未设阈值时计入）；未归并的 findings 仍是 'f:<id>'。
const countQualifyingFindingsSQL = `WITH observations AS (
 SELECT CASE WHEN m.case_id IS NULL THEN 'f:'||f.id ELSE 'c:'||m.case_id END entity,
        CASE WHEN m.case_id IS NULL THEN f.severity ELSE c.severity END severity
 FROM findings f
 LEFT JOIN finding_case_members m ON m.finding_id=f.id
 LEFT JOIN finding_cases c ON c.id=m.case_id
 WHERE f.task_id=$1 AND f.status<>'false_positive'
)
SELECT count(DISTINCT entity) FROM observations
WHERE $2='' OR array_position(ARRAY['low','medium','high','critical'],severity)
 >= array_position(ARRAY['low','medium','high','critical'],$2)`

// CountQualifyingFindings 统计任务内达标漏洞数（case 折叠口径）。误报永不计入；
// 未设 severity 阈值时各等级都计入。
func (d *DB) CountQualifyingFindings(taskID int64, minSeverity string) (int, error) {
	if err := NormalizeNoResultOptions(&TaskCreateOptions{NoResultMinSeverity: minSeverity}); err != nil {
		return 0, err
	}
	var count int
	err := d.QueryRow(countQualifyingFindingsSQL, taskID, minSeverity).Scan(&count)
	return count, err
}

// CheckNoResultCheckpoint 用单事务完成「认领检查点 + 达标计数 + 落判定」。
// 返回 checked=nil 表示检查点未被认领（任务不存在/已删除/已终态/已检查过）。
//
// 串行化协议（与 ARTEX 同款，恰好与本仓库漏洞写路径天然对齐）：tasks 行
// SELECT ... FOR UPDATE。本地 RecordFindingTx（finding_traffic.go）在同一事务里
// 先对 tasks 行 FOR UPDATE（LockTaskEvidenceTx）再写 findings，所以与漏洞写入
// 的互斥由这把行锁直接保证——不需要也不应再取 WithEvidenceTx 的 advisory lock
// （那会连带被证据 GC/导出拖慢）。已提交的漏洞一定计入；判定一旦落库，之后
// 写入的漏洞不能推翻止损（检查点一次性）。
func (d *DB) CheckNoResultCheckpoint(ctx context.Context, taskID int64, minFindings int, minSeverity string) (count int, stop bool, checked *time.Time, err error) {
	if err = NormalizeNoResultOptions(&TaskCreateOptions{NoResultMinSeverity: minSeverity}); err != nil {
		return
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, nil, err
	}
	defer tx.Rollback()
	var status string
	var previous sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT status, no_result_checked_at FROM tasks
 WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&status, &previous)
	if err == sql.ErrNoRows {
		return 0, false, nil, nil
	}
	if err != nil {
		return 0, false, nil, err
	}
	if previous.Valid || status == "done" || status == "failed" || status == "timeout" {
		return 0, false, nil, nil
	}
	// READ COMMITTED 下这条独立语句在等锁事务提交后取新快照：刚提交的达标漏洞
	// 一定可见。若与上面的锁定 SELECT 合并则沿用等待前的旧快照，会漏计。
	if err = tx.QueryRowContext(ctx, countQualifyingFindingsSQL, taskID, minSeverity).Scan(&count); err != nil {
		return 0, false, nil, err
	}
	stop = count < max(1, minFindings)
	var at time.Time
	if err = tx.QueryRowContext(ctx, `UPDATE tasks SET no_result_checked_at=clock_timestamp(),
 stop_reason=CASE WHEN $2 THEN 'no_result' ELSE '' END WHERE id=$1
 RETURNING no_result_checked_at`, taskID, stop).Scan(&at); err != nil {
		return 0, false, nil, err
	}
	if err = tx.Commit(); err != nil {
		return 0, false, nil, err
	}
	return count, stop, &at, nil
}

// ---------- 活跃运行段计时（A8，移植自 ARTEX db/tasks.go 段 helpers） ----------

// StartTaskRunSegment 打开当前活跃运行段。幂等（已有开放段不动），且任务处于
// paused/queued/终态时拒绝打开。返回折叠后的累计值与段起点（nil=段未开）。
func (d *DB) StartTaskRunSegment(id int64) (int64, *time.Time, error) {
	var active int64
	var started *time.Time
	err := d.QueryRow(`UPDATE tasks
SET run_segment_started_at=COALESCE(run_segment_started_at, now())
WHERE id=$1 AND deleted_at IS NULL AND status IN ('created','running') AND NOT paused AND NOT queued
RETURNING active_run_seconds, run_segment_started_at`, id).Scan(&active, &started)
	if err == sql.ErrNoRows {
		err = d.QueryRow(`SELECT active_run_seconds, run_segment_started_at FROM tasks WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&active, &started)
		if err == sql.ErrNoRows {
			return 0, nil, nil
		}
	}
	return active, started, err
}

// FinalizeTaskRunSegment 把开放段折叠进 active_run_seconds。开放段为 NULL 时是
// 安全空操作（暂停/终态路径与引擎晚到的取消可重复调用）。
func (d *DB) FinalizeTaskRunSegment(id int64) (int64, *time.Time, error) {
	var active int64
	var started *time.Time
	err := d.QueryRow(`UPDATE tasks
SET active_run_seconds=active_run_seconds + GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (now() - run_segment_started_at)))::bigint),
    run_segment_started_at=NULL
WHERE id=$1 AND run_segment_started_at IS NOT NULL
RETURNING active_run_seconds, run_segment_started_at`, id).Scan(&active, &started)
	if err == sql.ErrNoRows {
		err = d.QueryRow(`SELECT active_run_seconds, run_segment_started_at FROM tasks WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&active, &started)
		if err == sql.ErrNoRows {
			return 0, nil, nil
		}
	}
	return active, started, err
}

// ClearOpenTaskRunSegments 丢弃进程停止时仍开放的段。崩溃/发版后的墙钟时长不可知，
// 启动时故意清空；引擎恢复实际工作时会重新开段。
func (d *DB) ClearOpenTaskRunSegments() (int64, error) {
	res, err := d.Exec(`UPDATE tasks SET run_segment_started_at=NULL WHERE run_segment_started_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
