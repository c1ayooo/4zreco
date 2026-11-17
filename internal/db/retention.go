package db

import (
	"strconv"
	"strings"
	"time"
)

// retention.go — 追留清理（体检 O2，docs/体检修复方案-2026-11-13.md）：
// server_logs 与 llm_records 两张只增不减的增长表按 settings 里的天数裁剪历史。
// 语义（方案 D2 决策）：
//   - retention_server_logs_days 缺省 30（后端日志默认清 30 天以前）；
//   - retention_llm_records_days 缺省 0=关闭——录制数据可能要长期留证，保守不删，
//     需要时设一个天数即开启；
//   - 天数 <=0 一律视为关闭；
//   - 审批三表（intercept_pending/intercept_decisions/intercept_executions）是
//     append-only（触发器禁 UPDATE/DELETE），永不纳入清理，也不提供绕过触发器的
//     删除路径。
//
// 调度在 internal/server/manager.go（启动延迟数分钟一轮 + 每 24h 一轮），这里只
// 提供「读天数」与「按截止时间删除」两块纯能力。

const (
	// SettingRetentionServerLogsDays：server_logs 追留天数（按 created_at）。
	SettingRetentionServerLogsDays = "retention_server_logs_days"
	// SettingRetentionLLMRecordsDays：llm_records 追留天数（按 ts）。
	SettingRetentionLLMRecordsDays = "retention_llm_records_days"
	// DefaultRetentionServerLogsDays：后端日志默认保留 30 天。
	DefaultRetentionServerLogsDays = 30
	// DefaultRetentionLLMRecordsDays：录制数据默认永久保留（0=关闭清理）。
	DefaultRetentionLLMRecordsDays = 0
)

// RetentionDays 读一个按天计的追留设置：键未设置回落 def，值非法（非整数）也回落
// def（防手滑把清理配置写坏后语义不明）；返回值 <=0 表示关闭清理。
func (d *DB) RetentionDays(key string, def int) int {
	v, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, perr := strconv.Atoi(strings.TrimSpace(v))
	if perr != nil {
		return def
	}
	return n
}

// DeleteServerLogsOlderThan 删除 created_at 早于 cutoff 的 server_logs 行，返回删除数。
func (d *DB) DeleteServerLogsOlderThan(cutoff time.Time) (int64, error) {
	res, err := d.Exec(`DELETE FROM server_logs WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteLLMRecordsOlderThan 删除 ts 早于 cutoff 的 llm_records 行，返回删除数。
func (d *DB) DeleteLLMRecordsOlderThan(cutoff time.Time) (int64, error) {
	res, err := d.Exec(`DELETE FROM llm_records WHERE ts < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
