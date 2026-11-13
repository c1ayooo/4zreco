package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testIntelligenceInput() IntelligenceInput {
	return IntelligenceInput{Kind: "credential", Title: "测试数据库账号", Content: `{"username":"qa","password":"local-fixture-secret"}`, Evidence: "本机测试配置文件 /tmp/fixture", Confidence: "observed"}
}

// TestIntelligenceValidation 纯函数校验：非法输入全拒；合法输入补默认状态、
// asset_ids 排序去重。
func TestIntelligenceValidation(t *testing.T) {
	for _, change := range []func(*IntelligenceInput){
		func(i *IntelligenceInput) { i.Kind = "other" }, func(i *IntelligenceInput) { i.Evidence = "" }, func(i *IntelligenceInput) { i.Status = "confirmed" },
		func(i *IntelligenceInput) { i.Confidence = "inferred"; i.Status = "verified" }, func(i *IntelligenceInput) { i.AssetIDs = []int64{-1} },
		func(i *IntelligenceInput) { i.Content = strings.Repeat("x", 32769) },
	} {
		in := testIntelligenceInput()
		change(&in)
		if _, err := NormalizeIntelligence(in); !errors.Is(err, ErrIntelligenceInvalid) {
			t.Fatalf("accepted invalid input: %v", err)
		}
	}
	in := testIntelligenceInput()
	in.AssetIDs = []int64{2, 1, 2}
	got, err := NormalizeIntelligence(in)
	if err != nil || got.Status != "unverified" || len(got.AssetIDs) != 2 {
		t.Fatalf("normalization failed: %+v %v", got, err)
	}
}

// TestIntelligenceProvenanceDedupAndDirectContent：内容指纹去重（JSON 键序无关）、
// 跨任务节点拒绝、列表直出 content/evidence、跨任务改状态拒绝、重复上报不重置人工
// 定级、无关任务不可见、task_relations 继承可见、已删除任务拒绝写入。
func TestIntelligenceProvenanceDedupAndDirectContent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	first, err := d.CreateTask("intelligence source", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(first.ID)
	second, err := d.CreateTask("intelligence unrelated", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(second.ID)
	node, err := d.Exploration(first.ExplorationID).AddIntent(map[string]any{"summary": "read fixture"}, 5, nil, "qa")
	if err != nil {
		t.Fatal(err)
	}
	in := testIntelligenceInput()
	item, err := d.RecordIntelligence(t.Context(), first.ID, node, "worker-qa", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Content = `{ "password":"local-fixture-secret", "username":"qa" }`
	in.Title = "不同标题"
	again, err := d.RecordIntelligence(t.Context(), first.ID, node, "worker-qa", in)
	if err != nil || again.ID != item.ID {
		t.Fatalf("dedup failed: %+v %v", again, err)
	}
	if _, err = d.RecordIntelligence(t.Context(), second.ID, node, "qa", in); !errors.Is(err, ErrIntelligenceInvalid) {
		t.Fatalf("cross-task node accepted: %v", err)
	}
	page, err := d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(page)
	if page.Total != 1 || !strings.Contains(string(raw), "local-fixture-secret") || !strings.Contains(string(raw), "/tmp/fixture") {
		t.Fatal("list omitted recorded content or evidence")
	}
	if err = d.UpdateIntelligenceStatus(t.Context(), second.ID, item.ID, "verified"); !errors.Is(err, ErrIntelligenceNotFound) {
		t.Fatalf("cross-task mutation accepted: %v", err)
	}
	if err = d.UpdateIntelligenceStatus(t.Context(), first.ID, item.ID, "verified"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordIntelligence(t.Context(), first.ID, node, "qa", in); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.Status != "verified" {
		t.Fatal("duplicate reset triage")
	}
	page, err = d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: second.ID})
	if err != nil || page.Total != 0 {
		t.Fatal("unrelated task sees intelligence")
	}
	if _, err = d.Exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, second.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	page, err = d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: second.ID})
	if err != nil || page.Total != 1 || !page.Items[0].Inherited {
		t.Fatalf("inheritance failed: %+v %v", page, err)
	}
	if err = d.DeleteTask(second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordIntelligence(t.Context(), second.ID, 0, "qa", in); !errors.Is(err, ErrIntelligenceNotFound) {
		t.Fatalf("deleted task accepted: %v", err)
	}
}

// TestIntelligenceConfidenceUpgrade：ON CONFLICT 升级语义——observed 不被 inferred
// 降级；人工定级（verified/confirmed）不被机器重复上报覆盖，但初始态可被推进。
func TestIntelligenceConfidenceUpgrade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("intelligence upgrade semantics", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	in := testIntelligenceInput()
	item, err := d.RecordIntelligence(t.Context(), task.ID, 0, "qa", in)
	if err != nil {
		t.Fatal(err)
	}
	// inferred 上报不降 observed。
	lower := in
	lower.Confidence = "inferred"
	lower.Title = "推断标题"
	if _, err = d.RecordIntelligence(t.Context(), task.ID, 0, "qa", lower); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.Confidence != "observed" {
		t.Fatalf("confidence downgraded: %+v %v", got, err)
	}
	// 初始态 unverified 可被推进为 invalid（人工定级），再重复上报不回退。
	if err = d.UpdateIntelligenceStatus(t.Context(), task.ID, item.ID, "invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordIntelligence(t.Context(), task.ID, 0, "qa", in); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.Status != "invalid" {
		t.Fatalf("manual triage overwritten: %+v %v", got, err)
	}
}

// TestIntelligenceArchiveAssetRemapPreservesManualTriage：归档恢复重映射 asset id 后
// 指纹按新 id 重算、人工定级保留。
func TestIntelligenceArchiveAssetRemapPreservesManualTriage(t *testing.T) {
	row := map[string]any{"kind": "credential", "title": "manual validation", "content": "fixture", "evidence": "fixture", "confidence": "inferred", "status": "verified", "asset_ids": []int64{10, 20}}
	raw, _ := json.Marshal([]any{row})
	tables, err := remapArchiveAssetReferences(map[string]json.RawMessage{"task_intelligence": raw}, map[int64]int64{10: 30})
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(tables["task_intelligence"], &rows); err != nil {
		t.Fatal(err)
	}
	expected := intelligenceFingerprint(IntelligenceInput{Content: "fixture", AssetIDs: []int64{20, 30}})
	if len(rows) != 1 || rows[0]["fingerprint"] != expected || rows[0]["status"] != "verified" {
		t.Fatal("remap lost dedup or manual triage")
	}
}

// TestIntelligenceSensitiveDataListIncludesContent：敏感数据类列表直出原文与证据。
func TestIntelligenceSensitiveDataListIncludesContent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("direct sensitive data display", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	in := IntelligenceInput{Kind: "sensitive_data", Title: "fixture dataset", Content: "qa@example.invalid", Evidence: "/tmp/qa-users.json", Confidence: "observed"}
	_, err = d.RecordIntelligence(t.Context(), task.ID, 0, "qa", in)
	if err != nil {
		t.Fatal(err)
	}
	page, err := d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: task.ID, Kind: "sensitive_data"})
	if err != nil || page.Total != 1 || page.Items[0].Content != in.Content || page.Items[0].Evidence != in.Evidence {
		t.Fatalf("missing sensitive data content: %+v %v", page, err)
	}
}

// TestIntelligenceSourceSessionUsesGraphProvenance：溯源走探索图——节点本身是意图或
// 被唯一意图 yield → intent:id；多父歧义/无图谱事实 → 空串，绝不拿显示编号猜。
func TestIntelligenceSourceSessionUsesGraphProvenance(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("source navigation", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intent, err := store.AddIntent(map[string]any{"summary": "origin worker"}, 5, nil, "qa")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.AddNode(KindFact, map[string]any{"summary": "reported observation"}, 0, "confirmed", "qa", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Link(intent, RelYields, fact); err != nil {
		t.Fatal(err)
	}
	for _, node := range []int64{intent, fact} {
		in := testIntelligenceInput()
		in.Content = fmt.Sprintf("fixture node %d", node)
		item, err := d.RecordIntelligence(t.Context(), task.ID, node, "work#3", in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.GetIntelligence(t.Context(), item.ID)
		if err != nil || got.SourceSession != fmt.Sprintf("intent:%d", intent) {
			t.Fatalf("wrong source: %+v %v", got, err)
		}
	}
	page, err := d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: task.ID})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("list: %+v %v", page, err)
	}
	for _, item := range page.Items {
		if item.SourceSession != fmt.Sprintf("intent:%d", intent) {
			t.Fatalf("list source: %+v", item)
		}
	}
	// 多个 yield 父节点时不得把用户引向任意一个 worker。
	other, err := store.AddIntent(map[string]any{"summary": "other worker"}, 5, nil, "qa")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Link(other, RelYields, fact); err != nil {
		t.Fatal(err)
	}
	page, err = d.ListIntelligence(t.Context(), IntelligenceFilter{TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.NodeID != nil && *item.NodeID == fact && item.SourceSession != "" {
			t.Fatalf("ambiguous fact has exact session: %+v", item)
		}
	}
	// 图谱事实缺失时不从显示标签猜会话。
	in := testIntelligenceInput()
	in.Content = "orphan fixture"
	item, err := d.RecordIntelligence(t.Context(), task.ID, 0, "work#3", in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetIntelligence(t.Context(), item.ID)
	if err != nil || got.SourceSession != "" {
		t.Fatalf("guessed session: %+v %v", got, err)
	}
}
