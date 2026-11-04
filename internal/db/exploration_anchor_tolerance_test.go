package db

import (
	"testing"
)

// 锚点引用了不存在的资产时，节点本身必须照样写进去。
//
// 回归背景（2026-10-21 线上事故）：worker 调 record_fact 写回一条探索事实，
// asset_ids 里混进了一个不存在的资产 id（模型凭记忆编的、或资产已被删除）。
// exploration_anchors.asset_id 上是 FK REFERENCES assets(id)，于是 INSERT 报
//
//	ERROR: insert or update on table "exploration_anchors" violates foreign key
//	       constraint "exploration_anchors_asset_id_fkey" (SQLSTATE 23503)
//
// 而 AddNode 把节点 INSERT 和锚点 INSERT 放在**同一个事务**里——锚点一失败，
// 整条事务回滚，**事实节点连同模型辛苦探测出来的结论一起消失**。planner 看不到
// 这条事实，于是同一个方向被重新探测一遍，纯属白干。
//
// 正确语义：锚点是「可选的溯源边」，不是事实的载体。锚点指向的资产没了，
// 丢的是边，不是事实。
func TestAddNodeSkipsMissingAssetAnchors(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "锚点容错")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	// 一个真实存在的资产 + 一个绝对不存在的资产 id。
	realID, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: "anchor-ok.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, realID) })
	const missingID = int64(999999999)

	// 写一个 fact，同时锚到存在的和不存在的资产。
	nodeID, err := es.AddNode(KindFact, map[string]any{"summary": "锚点里有坏 id 也要写成"}, 5, "confirmed", "worker-1", []int64{realID, missingID})
	if err != nil {
		t.Fatalf("AddNode must not fail on a missing asset anchor: %v", err)
	}
	if nodeID <= 0 {
		t.Fatalf("node id = %d, want > 0", nodeID)
	}

	// 节点必须真的落库了（这是被回归的那条路径）。
	var cnt int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE id=$1 AND kind='fact'`, nodeID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("fact node persisted = %d, want 1", cnt)
	}

	// 真实锚点必须保留下来。
	var anchored int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, nodeID, realID).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	if anchored != 1 {
		t.Errorf("valid asset anchor kept = %d, want 1", anchored)
	}

	// 不存在的资产不能留下悬空锚点行。
	var dangling int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, nodeID, missingID).Scan(&dangling); err != nil {
		t.Fatal(err)
	}
	if dangling != 0 {
		t.Errorf("dangling anchor = %d, want 0", dangling)
	}
}

// AddIntent 走同一条 AddNode 路径，坏锚点同样不能击穿意图写入——
// 意图写不进去意味着探索方向直接丢了，比事实丢失更严重。
func TestAddIntentSkipsMissingAssetAnchors(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "意图锚点容错")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	intentID, err := es.AddIntent(map[string]any{"summary": "锚点含坏 id 的意图"}, 5, []int64{999999998}, "planner")
	if err != nil {
		t.Fatalf("AddIntent must not fail on a missing asset anchor: %v", err)
	}
	if intentID <= 0 {
		t.Fatalf("intent id = %d, want > 0", intentID)
	}

	// 意图必须真的进了 frontier（能被 worker 领到）。
	fr, err := es.Frontier(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr) != 1 || fr[0].ID != intentID {
		t.Fatalf("frontier = %+v, want the intent to survive", fr)
	}
}
