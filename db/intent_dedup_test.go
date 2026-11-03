package db

import (
	"testing"
)

// 归一化要吃掉大小写、空白与中英文标点——否则同一句话换个标点就被判成两条。
func TestNormalizeIntentText(t *testing.T) {
	same := []string{
		"扫描 8080 端口",
		"扫描8080端口",
		"扫描 8080 端口。",
		"  扫描 8080 端口 !! ",
	}
	want := normalizeIntentText(same[0])
	for _, s := range same {
		if got := normalizeIntentText(s); got != want {
			t.Errorf("normalize(%q)=%q，期望 %q", s, got, want)
		}
	}
	if normalizeIntentText("扫描8080端口") == normalizeIntentText("扫描443端口") {
		t.Error("不同端口不该归一化成同一个串")
	}
}

// FindSimilarOpenIntent 是派发去重：同任务里高度相似的 open/running 意图不再重复下发。
func TestFindSimilarOpenIntent(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("dedup intent test", "goal")
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(expID)

	id, err := ts.AddIntent(map[string]any{"summary": "对 example.com 做目录爆破"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	// 仅标点/空白不同 → 判为重复
	if got, _, ok, err := ts.FindSimilarOpenIntent("对 example.com 做目录爆破。"); err != nil || !ok {
		t.Fatalf("标点差异应判定为重复：ok=%v err=%v", ok, err)
	} else if got != id {
		t.Fatalf("应返回已有意图 id=%d，得到 %d", id, got)
	}

	// 明显不同的方向 → 不判重
	if _, _, ok, err := ts.FindSimilarOpenIntent("对 example.com 做子域名枚举"); err != nil || ok {
		t.Fatalf("不同方向不该判重：ok=%v err=%v", ok, err)
	}

	// 意图完成后不再参与判重（允许重新下发）
	if err := ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := ts.FindSimilarOpenIntent("对 example.com 做目录爆破"); ok {
		t.Fatal("已完成的意图不该再挡住新意图")
	}
}
