package db

// retention_test.go — 追留清理的 DSN 门控测试（ZRECO_PG_DSN 缺省 skip，与
// hitl_test.go 同款门控）：
//   - DeleteServerLogsOlderThan / DeleteLLMRecordsOlderThan：建表 → 插旧/新两批
//     → 按截止删 → 断言只删旧批、新批幸存、返回数准确；
//   - RetentionDays：未设置/非法值回落默认，0=关闭语义。
//
// 两个 Delete 测试对「全表早于截止」的存量行先计数再断言增量（deleted == before+1），
// 共享库残留老行也不影响判定（AGENTS.md §1 固定名 fixture 教训）。llm_records 不在
// schema.sql，测试里显式 EnsureLLMRecordsTable 建表。

import (
	"testing"
	"time"
)

func retentionTestDB(t *testing.T) *DB {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestDeleteServerLogsOlderThan(t *testing.T) {
	d := retentionTestDB(t)

	// 清掉上一轮残留（tag 专用标记，不碰别人的行）。
	testTag := "retention-test"
	if _, err := d.Exec(`DELETE FROM server_logs WHERE tag=$1`, testTag); err != nil {
		t.Fatalf("清理残留: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM server_logs WHERE tag=$1`, testTag) })

	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	var before int
	if err := d.QueryRow(`SELECT COUNT(*) FROM server_logs WHERE created_at < $1`, cutoff).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// 插旧/新两批：旧批 40 天前（应被删），新批当前时间（应幸存）。
	if _, err := d.Exec(`INSERT INTO server_logs(created_at, level, tag, text) VALUES ($1,'info',$2,'old')`,
		time.Now().Add(-40*24*time.Hour), testTag); err != nil {
		t.Fatalf("插旧行: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO server_logs(created_at, level, tag, text) VALUES (now(),'info',$1,'fresh')`, testTag); err != nil {
		t.Fatalf("插新行: %v", err)
	}

	deleted, err := d.DeleteServerLogsOlderThan(cutoff)
	if err != nil {
		t.Fatalf("DeleteServerLogsOlderThan: %v", err)
	}
	if deleted != int64(before+1) {
		t.Fatalf("删除数 = %d，want %d（存量旧行 %d + 本测 1）", deleted, before+1, before)
	}

	var stale, alive int
	if err := d.QueryRow(`SELECT COUNT(*) FROM server_logs WHERE created_at < $1`, cutoff).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("截止后仍剩 %d 条旧行，want 0", stale)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM server_logs WHERE tag=$1 AND text='fresh'`, testTag).Scan(&alive); err != nil {
		t.Fatal(err)
	}
	if alive != 1 {
		t.Fatalf("新批应幸存 1 条，got %d", alive)
	}
}

func TestDeleteLLMRecordsOlderThan(t *testing.T) {
	d := retentionTestDB(t)

	// 建表（llm_records 不在 schema.sql，由本函数幂等创建，顺带验证 O1 新索引语句）。
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatalf("EnsureLLMRecordsTable: %v", err)
	}

	// 清掉上一轮残留（model 专用标记）。
	testModel := "retention-test"
	if _, err := d.Exec(`DELETE FROM llm_records WHERE model=$1`, testModel); err != nil {
		t.Fatalf("清理残留: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_records WHERE model=$1`, testModel) })

	cutoff := time.Now().Add(-24 * time.Hour)
	var before int
	if err := d.QueryRow(`SELECT COUNT(*) FROM llm_records WHERE ts < $1`, cutoff).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// 插旧/新两批：旧批 40 天前（应被删），新批走正常写入路径 ts=now()（应幸存）。
	if _, err := d.Exec(`INSERT INTO llm_records(ts, model, task_id, status) VALUES ($1,$2,'retention-old','ok')`,
		time.Now().Add(-40*24*time.Hour), testModel); err != nil {
		t.Fatalf("插旧行: %v", err)
	}
	if err := d.InsertLLMRecord(&LLMRecord{Model: testModel, Status: "ok"}); err != nil {
		t.Fatalf("插新行: %v", err)
	}

	deleted, err := d.DeleteLLMRecordsOlderThan(cutoff)
	if err != nil {
		t.Fatalf("DeleteLLMRecordsOlderThan: %v", err)
	}
	if deleted != int64(before+1) {
		t.Fatalf("删除数 = %d，want %d（存量旧行 %d + 本测 1）", deleted, before+1, before)
	}

	var stale, alive int
	if err := d.QueryRow(`SELECT COUNT(*) FROM llm_records WHERE ts < $1`, cutoff).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("截止后仍剩 %d 条旧行，want 0", stale)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM llm_records WHERE model=$1`, testModel).Scan(&alive); err != nil {
		t.Fatal(err)
	}
	if alive != 1 {
		t.Fatalf("新批应幸存 1 条，got %d", alive)
	}
}

func TestRetentionDaysDefaults(t *testing.T) {
	d := retentionTestDB(t)

	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`,
			SettingRetentionServerLogsDays, SettingRetentionLLMRecordsDays)
	}
	cleanup()
	t.Cleanup(cleanup)

	// 未设置 → 各自默认（server_logs 30 启用；llm_records 0=关闭，保守不删录制）。
	if got := d.RetentionDays(SettingRetentionServerLogsDays, DefaultRetentionServerLogsDays); got != 30 {
		t.Fatalf("未设置 server_logs 天数 = %d，want 30", got)
	}
	if got := d.RetentionDays(SettingRetentionLLMRecordsDays, DefaultRetentionLLMRecordsDays); got != 0 {
		t.Fatalf("未设置 llm_records 天数 = %d，want 0（默认关闭）", got)
	}

	// 显式 0 = 关闭；正整数原样；非法值回落默认。
	if err := d.SetSetting(SettingRetentionServerLogsDays, "0"); err != nil {
		t.Fatal(err)
	}
	if got := d.RetentionDays(SettingRetentionServerLogsDays, DefaultRetentionServerLogsDays); got != 0 {
		t.Fatalf("显式 0 = %d，want 0（关闭）", got)
	}
	if err := d.SetSetting(SettingRetentionServerLogsDays, "7"); err != nil {
		t.Fatal(err)
	}
	if got := d.RetentionDays(SettingRetentionServerLogsDays, DefaultRetentionServerLogsDays); got != 7 {
		t.Fatalf("显式 7 = %d，want 7", got)
	}
	if err := d.SetSetting(SettingRetentionServerLogsDays, "abc"); err != nil {
		t.Fatal(err)
	}
	if got := d.RetentionDays(SettingRetentionServerLogsDays, DefaultRetentionServerLogsDays); got != 30 {
		t.Fatalf("非法值 = %d，want 回落默认 30", got)
	}
}
