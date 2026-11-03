package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/c1ayooo/4zreco/db"
)

// record_fact 传了不存在的 asset id 时：事实必须写进去，且模型必须被告知
// 那个 id 不存在。
//
// 回归背景（2026-10-21 线上事故）：模型凭记忆编了个 asset id，record_fact
// 直接撞 FK 约束报错，整条事实连同锚点一起回滚消失——planner 看不到这条事实，
// 同一个方向被重新探测一遍。而模型也不知道自己的 id 是假的，下次继续用。
//
// 修复分两层：db 层跳过悬空锚点（保住事实），工具层把无效 id 报给模型
// （让它改用 list_assets 查到的真 id）。
func TestRecordFactReportsMissingAssetIDs(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("fact-asset-hint", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	exp, err := d.CreateExploration("fact-asset-hint", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	store := d.Exploration(exp)

	intentID, err := store.AddIntent(map[string]any{"summary": "探测某接口"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	assets := d.Assets()
	realID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: "fact-hint-host.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{realID}) })

	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(assets, assets.Companies())

	const missingID = int64(987654321)
	input := fmt.Sprintf(`{"summary":"引用了假资产 id 的事实","intent_id":%d,"asset_ids":[%d,%d]}`, intentID, realID, missingID)

	tool := tools.recordFact()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("record_fact must not fail on a missing asset id: %v", err)
	}
	text := res.Flatten()

	// 事实必须真的落库。
	facts, err := store.ListByKind(db.KindFact, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts persisted = %d, want 1", len(facts))
	}

	// 真实资产的锚点必须保留。
	var anchored int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, facts[0].ID, realID).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	if anchored != 1 {
		t.Errorf("valid asset anchor = %d, want 1", anchored)
	}

	// 假 id 必须出现在返回里——模型要知道自己错在哪。
	if !strings.Contains(text, fmt.Sprint(missingID)) {
		t.Errorf("tool result must mention the missing asset id %d; got: %s", missingID, text)
	}
	if !strings.Contains(text, "list_assets") {
		t.Errorf("tool result must point the model at list_assets; got: %s", text)
	}
}

// 全部 asset id 都有效时，返回里不该有多余的告警——避免污染模型上下文。
func TestRecordFactNoWarningWhenAssetsValid(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("fact-asset-ok", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	exp, err := d.CreateExploration("fact-asset-ok", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	store := d.Exploration(exp)

	assets := d.Assets()
	realID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: "fact-ok-host.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{realID}) })

	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(assets, assets.Companies())

	input := fmt.Sprintf(`{"summary":"锚点全有效的事实","asset_ids":[%d]}`, realID)
	tool := tools.recordFact()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("record_fact: %v", err)
	}
	text := res.Flatten()
	if strings.Contains(text, "不存在") {
		t.Errorf("no warning expected when every asset id is valid; got: %s", text)
	}
	if !strings.Contains(text, "fact recorded") {
		t.Errorf("unexpected result shape: %s", text)
	}
}

var _ = actool.CoreTool(nil)
