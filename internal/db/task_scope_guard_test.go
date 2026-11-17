package db

import (
	"testing"
)

// 上游 0.4.63：ClassifyAssetsForTask 把资产按 own/source/foreign 分类；
// FindForeignAssetForTask 反查「不属于本任务且不在本任务自有 scope」的既有资产。
func TestScopeGuardClassifyAssetsForTask(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	as := d.Assets()

	taskA, err := d.CreateTask("scope guard task A", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskA.ID) })
	taskB, err := d.CreateTask("scope guard source task B", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskB.ID) })
	taskC, err := d.CreateTask("scope guard foreign task C", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskC.ID) })

	// A 的基线：x.test；B 的基线：y.test（对 A 是来源/继承范围）。
	if _, err := as.AddAgentScope(taskA.ID, "root_domain", "x.test", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAgentScope(taskB.ID, "root_domain", "y.test", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	// A ← B：B 是 A 的来源任务（A 继承 B 的上下文）。
	if _, err := d.Exec(`INSERT INTO task_relations(task_id, source_task_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, taskA.ID, taskB.ID); err != nil {
		t.Fatal(err)
	}

	mkAsset := func(domain, root string, taskIDs []int64) int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain, task_ids) VALUES ('service',$1,$2,$3) RETURNING id`,
			domain, root, taskIDs).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, id) })
		return id
	}
	aOwn := mkAsset("host.x.test", "x.test", []int64{taskA.ID})     // task_ids 含本任务
	aScoped := mkAsset("web.x.test", "x.test", []int64{})           // 只匹配本任务 scope
	aSource := mkAsset("host.y.test", "y.test", []int64{taskB.ID})  // 只属于来源任务
	aForeign := mkAsset("host.z.test", "z.test", []int64{taskC.ID}) // 完全越界

	own, source, foreign, err := as.ClassifyAssetsForTask(taskA.ID, []int64{aOwn, aScoped, aSource, aForeign})
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 2 || !hasID(own, aOwn) || !hasID(own, aScoped) {
		t.Fatalf("own 应含 aOwn/aScoped，得到 %v", own)
	}
	if len(source) != 1 || !hasID(source, aSource) {
		t.Fatalf("source 应含 aSource，得到 %v", source)
	}
	if len(foreign) != 1 || !hasID(foreign, aForeign) {
		t.Fatalf("foreign 应含 aForeign，得到 %v", foreign)
	}

	// 空入参：直接返回空分类，不查库。
	if own, source, foreign, err := as.ClassifyAssetsForTask(taskA.ID, nil); err != nil || own != nil || source != nil || foreign != nil {
		t.Fatalf("空 ids 应返回空分类，得到 %v/%v/%v/%v", own, source, foreign, err)
	}

	// FindForeignAssetForTask：z.test 不属于 A 且不在 A 自有 scope → 命中 aForeign。
	id, owners, err := as.FindForeignAssetForTask(taskA.ID, []string{"host.z.test"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id != aForeign || owners == "" {
		t.Fatalf("应反查到 aForeign（归属 %q），得到 id=%d owners=%q", "taskC", id, owners)
	}
	// x.test 在 A 自有 scope → 未命中。
	if id, _, _ := as.FindForeignAssetForTask(taskA.ID, []string{"web.x.test"}, nil, nil); id != 0 {
		t.Fatalf("自有范围资产不应命中 foreign 反查，得到 id=%d", id)
	}
}

// 上游 0.4.71：自动范围归属校验——公共设施/CDN 黑名单 + 任务基线归属。
func TestAutoScopeOwnership(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	as := d.Assets()

	task, err := d.CreateTask("auto scope ownership", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	scopeRows := func() []TaskScope {
		rows, err := as.ListTaskScope(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	autoCount := func(kind, value string) int {
		n := 0
		for _, r := range scopeRows() {
			if r.Source != "auto" {
				continue
			}
			v := r.Domain
			if r.Net != "" {
				v = r.Net
			}
			if r.Kind == kind && v == value {
				n++
			}
		}
		return n
	}

	// 无基线老任务：非黑名单域保持旧行为（自动入范围）。
	if err := as.AddAutoScope(task.ID, "root_domain", "legacy.test", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := autoCount("root_domain", "legacy.test"); n != 1 {
		t.Fatalf("无基线时非黑名单域应照旧自动入范围，得到 %d 行", n)
	}
	// 公共设施黑名单不收（即使无基线）：github.com / play.min.io / cdn.jsdelivr.net。
	for _, bad := range []string{"github.com", "play.min.io", "cdn.jsdelivr.net", "unpkg.com"} {
		if err := as.AddAutoScope(task.ID, "root_domain", bad, "", ""); err != nil {
			t.Fatal(err)
		}
		if n := autoCount("root_domain", bad); n != 0 {
			t.Fatalf("公共设施 %s 不应自动入范围，得到 %d 行", bad, n)
		}
	}

	// 建立基线：根域 baseline.test + 网段 10.0.0.0/24。
	if _, err := as.AddAgentScope(task.ID, "root_domain", "baseline.test", "test", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAgentScope(task.ID, "cidr", "10.0.0.0/24", "test", "manual"); err != nil {
		t.Fatal(err)
	}

	// 基线内：同根域 / 网段内 IP → 收。
	if err := as.AddAutoScope(task.ID, "subdomain", "app.baseline.test", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := autoCount("subdomain", "app.baseline.test"); n != 1 {
		t.Fatalf("基线内子域应自动入范围，得到 %d 行", n)
	}
	if err := as.AddAutoScope(task.ID, "ip", "", "", "10.0.0.55"); err != nil {
		t.Fatal(err)
	}
	if n := autoCount("ip", "10.0.0.55/32"); n != 1 {
		t.Fatalf("基线网段内 IP 应自动入范围，得到 %d 行", n)
	}
	// 基线外：异根域 / 网段外 IP → 不收。
	for _, c := range []struct {
		typ, domain, ip string
	}{
		{"root_domain", "outside.test", ""},
		{"ip", "", "9.9.9.9"},
	} {
		if err := as.AddAutoScope(task.ID, c.typ, c.domain, "", c.ip); err != nil {
			t.Fatal(err)
		}
		v := c.domain
		if v == "" {
			v = c.ip + "/32"
		}
		if n := autoCount(c.typ, v); n != 0 {
			t.Fatalf("基线外 %s/%s 不应自动入范围，得到 %d 行", c.typ, v, n)
		}
	}

	// AuditAutoScope 回放：source=auto 行按新规则分类。infra 黑名单行与基线外行
	// 模拟存量库（修复前的 AddAutoScope 会收进来，现在不会）——直接插行再回放。
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain, source) VALUES ($1,'root_domain','github.com','auto'), ($1,'root_domain','outside.test','auto')`, task.ID); err != nil {
		t.Fatal(err)
	}
	items, err := as.AuditAutoScope()
	if err != nil {
		t.Fatal(err)
	}
	reasonOf := func(taskID int64, kind, value string) (AutoScopeAudit, bool) {
		for _, it := range items {
			if it.TaskID != taskID {
				continue
			}
			v := it.Domain
			if it.Net != "" {
				v = it.Net
			}
			if it.Kind == kind && v == value {
				return it, true
			}
		}
		return AutoScopeAudit{}, false
	}
	if it, ok := reasonOf(task.ID, "root_domain", "github.com"); !ok || it.Reason != "infra-blacklist" {
		t.Fatalf("github.com 应判 infra-blacklist，得到 %+v", it)
	}
	if it, ok := reasonOf(task.ID, "subdomain", "app.baseline.test"); !ok || !it.Allowed || it.Reason != "ok" {
		t.Fatalf("基线内子域应判 ok，得到 %+v", it)
	}
	if it, ok := reasonOf(task.ID, "ip", "10.0.0.55/32"); !ok || !it.Allowed {
		t.Fatalf("基线网段内 IP 应判 ok，得到 %+v", it)
	}
	if it, ok := reasonOf(task.ID, "root_domain", "outside.test"); !ok || it.Allowed || it.Reason != "outside-baseline" {
		t.Fatalf("基线外域应判 outside-baseline，得到 %+v", it)
	}
}

func hasID(ids []int64, want int64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
