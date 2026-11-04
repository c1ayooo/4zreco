package db

import (
	"fmt"
	"testing"
	"time"
)

func TestMergeHoneypotEvidence(t *testing.T) {
	// 空旧值 + 新证据
	got := MergeHoneypotEvidence("", []string{"a(X, 0.90)"})
	if got != `["a(X, 0.90)"]` {
		t.Fatalf("from empty: %q", got)
	}
	// 合并去重,保序
	got = MergeHoneypotEvidence(`["a(X, 0.90)"]`, []string{"a(X, 0.90)", "b(Y, 0.85)"})
	if got != `["a(X, 0.90)","b(Y, 0.85)"]` {
		t.Fatalf("dedup merge: %q", got)
	}
	// 旧值损坏按无旧值处理,不丢新证据
	got = MergeHoneypotEvidence("garbage", []string{"a(X, 0.90)"})
	if got != `["a(X, 0.90)"]` {
		t.Fatalf("corrupt old: %q", got)
	}
	// 双方都空
	if got := MergeHoneypotEvidence("", nil); got != "" {
		t.Fatalf("both empty: %q", got)
	}
}

// PG 集成：评分回写取更高分 + 证据合并去重 + 按任务列出 score>0 的资产。
func TestHoneypotScoreRoundtrip(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()

	url := fmt.Sprintf("http://honeypot-roundtrip-%d.test", time.Now().UnixNano())
	id, err := as.UpsertHTTPService(UpsertHTTPServiceReq{URL: url, TaskID: 42})
	if err != nil {
		t.Fatal(err)
	}
	defer deleteAsset(d, id)

	// 首次写入
	if err := as.SetHoneypotScore(id, 0.9, []string{"a(X, 0.90)"}); err != nil {
		t.Fatal(err)
	}
	// 分数更低、证据重复 → 行不动（幂等）；分数更高 → 取更高并合并证据。
	if err := as.SetHoneypotScore(id, 0.5, []string{"a(X, 0.90)"}); err != nil {
		t.Fatal(err)
	}
	if err := as.SetHoneypotScore(id, 0.99, []string{"b(Y, 0.99)"}); err != nil {
		t.Fatal(err)
	}
	pots, err := as.HoneypotAssetsByTask(42, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pots) != 1 {
		t.Fatalf("expected 1 honeypot asset for task 42, got %d", len(pots))
	}
	// honeypot_score 是 REAL(float32) 列，回读有精度漂移，用容差比较。
	if pots[0].ID != id || pots[0].Label != url || pots[0].Score < 0.985 || pots[0].Score > 0.995 {
		t.Fatalf("unexpected row: %+v", pots[0])
	}
	want := `["a(X, 0.90)","b(Y, 0.99)"]`
	if pots[0].Evidence != want {
		t.Fatalf("evidence should merge+dedup to %s, got %s", want, pots[0].Evidence)
	}
	// 其他任务读不到。
	if pots, _ = as.HoneypotAssetsByTask(43, 0); len(pots) != 0 {
		t.Fatalf("task 43 should see no honeypot assets, got %d", len(pots))
	}
}
