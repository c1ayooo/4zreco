package db

import (
	"fmt"
	"testing"
	"time"
)

// 覆盖归账（v0.4.27）：record_fact 自动锚定依赖 ResolveHostAssets 把事实文本里的
// 主机/URL 反查回任务资产。这里验证三种命中（url 精确、url 前缀、host/root_domain）
// 与上限截断。
func TestResolveHostAssets(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	taskID := time.Now().UnixNano()
	cleanup := func() {
		d.Exec(`DELETE FROM assets WHERE domain IN ('probe.example.com','example.com') OR root_domain='example.com'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{TaskID: taskID, Domain: "probe.example.com"}); err != nil {
		t.Fatalf("upsert subdomain: %v", err)
	}
	ep, err := as.UpsertEndpoint(UpsertEndpointReq{TaskID: taskID, URL: "https://probe.example.com/prod-api/list", Method: "GET"})
	if err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	root, err := as.UpsertRootDomain(UpsertRootDomainReq{TaskID: taskID, Domain: "example.com"})
	if err != nil {
		t.Fatalf("upsert root: %v", err)
	}

	// URL 精确命中 endpoint（rank 0 排最前）。
	ids, err := as.ResolveHostAssets(taskID, nil, []string{"https://probe.example.com/prod-api/list"}, 5)
	if err != nil || len(ids) == 0 || ids[0] != ep {
		t.Fatalf("url exact: ids=%v err=%v want first=%d", ids, err, ep)
	}
	// host 命中 subdomain + root_domain（≥2 条）。
	ids, err = as.ResolveHostAssets(taskID, []string{"probe.example.com"}, nil, 5)
	if err != nil || len(ids) < 2 {
		t.Fatalf("host match: ids=%v err=%v want >=2", ids, err)
	}
	// 前缀命中（带 query 的变体 URL 也应命中同 endpoint）。
	ids, err = as.ResolveHostAssets(taskID, nil, []string{"https://probe.example.com/prod-api/list?page=1"}, 5)
	if err != nil || len(ids) == 0 || ids[0] != ep {
		t.Fatalf("url prefix: ids=%v err=%v want first=%d", ids, err, ep)
	}
	// max 截断。
	ids, err = as.ResolveHostAssets(taskID, []string{"probe.example.com", "example.com"}, nil, 1)
	if err != nil || len(ids) != 1 {
		t.Fatalf("max cap: ids=%v err=%v want 1", ids, err)
	}
	_ = fmt.Sprint(root)
}

// 未测资产排序（v0.4.27）：静态资源沉底、同簇前缀相邻——不是严格断言顺序值，
// 而是「无扩展路径排在静态资源前面」+「同前缀相邻」两个性质。
func TestUntestedAssetsOrdering(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	// task_scope.task_id 有 FK → 先建真任务行。
	tkID, err := d.CreateTask("未测资产排序测试", "目标 ord.example.com", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascade(tkID.ID, true, true) })
	taskID := tkID.ID
	cleanup := func() {
		d.Exec(`DELETE FROM assets WHERE url LIKE 'https://ord.example.com/%'`)
		d.Exec(`DELETE FROM assets WHERE domain='ord.example.com' OR root_domain='ord.example.com'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	urls := []string{
		"https://ord.example.com/static/app.js",
		"https://ord.example.com/prod-api/user/info",
		"https://ord.example.com/prod-api/user/list",
		"https://ord.example.com/logo.png",
		"https://ord.example.com/HRMS/api/emp",
	}
	for _, u := range urls {
		if _, err := as.UpsertEndpoint(UpsertEndpointReq{TaskID: taskID, URL: u, Method: "GET"}); err != nil {
			t.Fatalf("upsert %s: %v", u, err)
		}
	}
	if err := as.AddAutoScope(taskID, "subdomain", "ord.example.com", "", ""); err != nil {
		t.Fatalf("add scope: %v", err)
	}
	backlog, total, err := as.ListUntestedAssetsWithSources(taskID, "endpoint", 20, 0)
	if err != nil {
		t.Fatalf("list untested: %v", err)
	}
	if total < 5 {
		t.Fatalf("total=%d want >=5", total)
	}
	got := map[string]string{}
	for _, a := range backlog {
		got[a.Label] = a.Label
	}
	_ = got
	// 静态两条应排在全部无扩展路径之后。
	staticSeenAt, pathSeenAt := -1, -1
	for i, a := range backlog {
		switch a.Label {
		case "https://ord.example.com/static/app.js", "https://ord.example.com/logo.png":
			if staticSeenAt < 0 || i < staticSeenAt {
				staticSeenAt = i
			}
		default:
			if pathSeenAt < i {
				pathSeenAt = i
			}
		}
	}
	if staticSeenAt >= 0 && staticSeenAt < len(backlog)-1 && staticSeenAt < pathSeenAt {
		t.Fatalf("static asset not last: backlog=%v", backlog)
	}
	// 同簇相邻：两条 /prod-api/user/* 在列表里应连续。
	pos := map[string]int{}
	for i, a := range backlog {
		pos[a.Label] = i
	}
	p1, ok1 := pos["https://ord.example.com/prod-api/user/info"]
	p2, ok2 := pos["https://ord.example.com/prod-api/user/list"]
	if ok1 && ok2 && abs(p1-p2) != 1 {
		t.Fatalf("same-prefix items not adjacent: pos=%v", pos)
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
