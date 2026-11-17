package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// 上游 0.4.63：record_fact 的 asset_ids 锚定校验——本任务自有范围资产放行，
// 来源/继承范围与完全越界拒绝；recordOneFact 把守卫结论带回给模型（真实 PostgreSQL）。
func TestScopeGuardFactAnchoring(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	as := d.Assets()

	taskA, err := d.CreateTask("scope guard fact task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskA.ID) })
	taskB, err := d.CreateTask("scope guard other task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskB.ID) })

	if _, err := as.AddAgentScope(taskA.ID, "root_domain", "x.test", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	var ownID, foreignID int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain, task_ids) VALUES ('service','web.x.test','x.test',$1) RETURNING id`, []int64{taskA.ID}).Scan(&ownID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, ownID) })
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain, task_ids) VALUES ('service','host.z.test','z.test',$1) RETURNING id`, []int64{taskB.ID}).Scan(&foreignID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, foreignID) })

	tset := &ToolSet{ts: d.Exploration(taskA.ExplorationID), as: as, worker: "worker#1", taskID: taskA.ID}

	// 自有范围资产：放行。
	if msg := tset.scopeGuardError(taskA.ID, []int64{ownID}); msg != "" {
		t.Fatalf("自有范围资产应放行，得到 %q", msg)
	}
	// 完全越界：拒绝，纠正提示带分类标签。
	if msg := tset.scopeGuardError(taskA.ID, []int64{foreignID}); msg == "" || !strings.Contains(msg, "完全越界") {
		t.Fatalf("完全越界资产应被拒绝，得到 %q", msg)
	}
	// 无任务上下文/无资产库：fail-open 不拦。
	if msg := tset.scopeGuardError(0, []int64{foreignID}); msg != "" {
		t.Fatalf("taskID=0 应 fail-open 放行，得到 %q", msg)
	}

	// recordOneFact 锚定越界资产 → 整条拒绝，事实不落库。
	rawForeign, _ := json.Marshal(foreignID)
	if _, err := tset.recordOneFact(factItem{Summary: "拿到敏感数据", AssetIDs: []json.RawMessage{rawForeign}}, 0); err == nil || !strings.Contains(err.Error(), "范围守卫") {
		t.Fatalf("越界锚定的 fact 应被拒绝，err=%v", err)
	}
	// 锚定自有资产 → 正常落库且锚点保留。
	rawOwn, _ := json.Marshal(ownID)
	id, err := tset.recordOneFact(factItem{Summary: "识别技术栈", AssetIDs: []json.RawMessage{rawOwn}}, 0)
	if err != nil {
		t.Fatalf("自有锚定的 fact 应落库，err=%v", err)
	}
	node, err := tset.ts.GetNode(id)
	if err != nil || node == nil {
		t.Fatalf("fact 节点应存在，err=%v", err)
	}
	// GetNode 不带 anchors——直接查锚点表。
	var anchor int64
	err = d.QueryRow(`SELECT asset_id FROM exploration_anchors WHERE node_id=$1`, id).Scan(&anchor)
	if err != nil || anchor != ownID {
		t.Fatalf("fact 应锚定自有资产 %d，err=%v anchor=%d", ownID, err, anchor)
	}
}
