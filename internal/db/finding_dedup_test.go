package db

import (
	"context"
	"strings"
	"testing"
)

// 同任务同指纹的重复上报:不插新行,证据合并,返回原 finding_id + Duplicate。
func TestRecordFindingDedup(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("dedup test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// 真实资产行(anchors 有 asset 外键)
	var assetA, assetB int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain) VALUES ('service','a.dedup.test','dedup.test') RETURNING id`).Scan(&assetA); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain) VALUES ('service','b.dedup.test','dedup.test') RETURNING id`).Scan(&assetB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, assetA, assetB) })

	in := RecordFindingInput{
		TaskID:        task.ID,
		ExplorationID: task.ExplorationID,
		VulnClass:     "sqli",
		Name:          "Union-based SQLi on /login",
		Severity:      "high",
		Summary:       "classic union sqli",
		Evidence:      "' OR 1=1 -- returned admin row",
		Worker:        "work#1",
		AssetIDs:      []int64{assetB, assetA},
	}

	r1, err := d.Exploration(in.ExplorationID).RecordFinding(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Duplicate {
		t.Fatal("first report must not be duplicate")
	}

	// 同指纹再来一次(不同 worker/证据/资产顺序)
	in2 := in
	in2.Worker = "work#2"
	in2.Evidence = "second confirmation with time-based blind sqli"
	in2.AssetIDs = []int64{assetA, assetB} // 顺序不同,指纹必须相同
	r2, err := d.Exploration(in2.ExplorationID).RecordFinding(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Duplicate || r2.FindingID != r1.FindingID {
		t.Fatalf("second report: duplicate=%v id=%d want dup of %d", r2.Duplicate, r2.FindingID, r1.FindingID)
	}

	// 库里只有一行,且证据含两次内容
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d want 1", rows)
	}
	var ev string
	if err := d.QueryRow(`SELECT evidence FROM findings WHERE task_id=$1`, task.ID).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev, "second confirmation") || !strings.Contains(ev, "OR 1=1") {
		t.Fatal("evidence merge lost one of the reports")
	}

	// 不同指纹(换 name)→ 新行
	in3 := in
	in3.Name = "Boolean-based SQLi on /search"
	r3, err := d.Exploration(in3.ExplorationID).RecordFinding(ctx, in3)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Duplicate || r3.FindingID == r1.FindingID {
		t.Fatalf("different fingerprint must create new finding: dup=%v id=%d", r3.Duplicate, r3.FindingID)
	}
}
