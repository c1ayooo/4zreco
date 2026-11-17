package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// 构造层（无 DB）：顶层 OR 必须整体成组，否则调用方追加的 AND 只绑最后一个分支
// =====================================================================

// 三个查询调用方（CountDSL / QueryDSL / QueryDSLInScope）都会在
// buildDSLWhere 的输出后面追加 ` AND ...`（type 过滤 / task_ids 归属 /
// 任务范围 target），而 SQL 里 AND 的优先级高于 OR。顶层 OR 没有外层括号时
// `a OR b AND scope` 只把 scope 绑到最后一个分支，前面分支命中的其他任务
// 资产会泄漏进本任务结果（跨任务资产泄露）。
func TestBuildDSLWhereGroupsTopLevelOr(t *testing.T) {
	for _, dsl := range []string{
		"url=profile OR url=token OR url=register",
		"port==80 OR port==443",
		"(url=profile AND port==443) OR url=token",
	} {
		node, err := ParseDSL(dsl)
		if err != nil {
			t.Fatalf("ParseDSL(%q): %v", dsl, err)
		}
		where, _, err := buildDSLWhere(node)
		if err != nil {
			t.Fatalf("buildDSLWhere(%q): %v", dsl, err)
		}
		if !strings.Contains(where, " OR ") {
			t.Fatalf("dsl=%q where=%q 未生成 OR，测试前提不成立", dsl, where)
		}
		if hasTopLevelOr(where) {
			t.Errorf("dsl=%q where=%q 的 OR 未整体成组：追加 AND 只会约束最后一个分支", dsl, where)
		}
	}
}

// 叶子、AND 组合、空值与 cidr 查询同样要能安全追加 AND——修复不能把原本
// 正确的子句改成括号不平衡，也不能引入新的裸 OR。
func TestBuildDSLWhereStaysComposable(t *testing.T) {
	for _, dsl := range []string{
		"url=profile",
		"port==443 AND technology=nginx",
		`service_name==""`,
		"cidr=10.10.0.0/16",
	} {
		node, err := ParseDSL(dsl)
		if err != nil {
			t.Fatalf("ParseDSL(%q): %v", dsl, err)
		}
		where, _, err := buildDSLWhere(node)
		if err != nil {
			t.Fatalf("buildDSLWhere(%q): %v", dsl, err)
		}
		if hasTopLevelOr(where) {
			t.Errorf("dsl=%q where=%q 无法安全追加 AND（括号不平衡或顶层 OR 裸露）", dsl, where)
		}
	}
}

// hasTopLevelOr 判断子句是否存在括号外的 OR，或括号不平衡——这两种情况都
// 不能再安全地追加 ` AND ...`。
func hasTopLevelOr(clause string) bool {
	depth := 0
	for i := 0; i < len(clause); i++ {
		switch clause[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return true
			}
		case 'O':
			if depth == 0 && i > 0 && clause[i-1] == ' ' && strings.HasPrefix(clause[i:], "OR ") {
				return true
			}
		}
	}
	return depth != 0
}

// =====================================================================
// DB 层（真实 PG）：OR 查询不得越出任务 scope
// =====================================================================

// TestQueryDSLInScopeOrDoesNotEscapeScope 覆盖 agent 的 list_assets 路径。
// 两个任务各自登记 endpoint，任务 A 用 OR DSL 查询时不得看到任务 B 的资产。
// 修复前 `url=profile OR url=token AND scope` 把 scope 只绑到 token 分支，
// profile 分支命中的任务 B 资产会泄漏。
func TestQueryDSLInScopeOrDoesNotEscapeScope(t *testing.T) {
	d, assets, _ := testSetup(t)
	defer d.Close()

	mark := fmt.Sprintf("orx%d", time.Now().UnixNano())
	taskA, err := d.CreateTask(mark+" A", "test goal A", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskA.ID) })

	taskB, err := d.CreateTask(mark+" B", "test goal B", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskB.ID) })

	// 两个任务各给一个互不重叠的 /24 scope
	if _, err := assets.AddAgentScope(taskA.ID, "cidr", "10.99.1.0/24", "test A", "agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.AddAgentScope(taskB.ID, "cidr", "10.99.2.0/24", "test B", "agent"); err != nil {
		t.Fatal(err)
	}

	// 直接用 SQL 造资产行，绕开 upsert 的自动范围归属逻辑
	var ids []int64
	ins := func(host, url string, taskID int64) int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,url,task_ids,last_seen)
			VALUES ('endpoint',$1,$1,$2,ARRAY[$3]::bigint[],now()) RETURNING id`,
			host, url, taskID).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", url, err)
		}
		ids = append(ids, id)
		return id
	}
	ins("10.99.1.10", "http://10.99.1.10/"+mark+"-profile", taskA.ID) // 命中 url=profile，属 A
	ins("10.99.1.10", "http://10.99.1.10/"+mark+"-token", taskA.ID)   // 命中 url=token，属 A
	ins("10.99.2.10", "http://10.99.2.10/"+mark+"-profile", taskB.ID) // 命中 url=profile，属 B —— 修复前会泄漏
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id = ANY($1::bigint[])`, ids) })

	got, err := assets.QueryDSLInScope(
		"url="+mark+"-profile OR url="+mark+"-token", "", taskA.ID, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("查询结果为空：修复后应至少返回任务 A 的两条资产（测试前提不成立）")
	}
	for _, a := range got {
		if strings.Contains(a.URL, "10.99.2.10") {
			t.Fatalf("任务 A 的 OR 查询返回了任务 B 网段的资产 id=%d url=%s —— scope 被绕过", a.ID, a.URL)
		}
		for _, tid := range a.TaskIDs {
			if tid == taskB.ID {
				t.Fatalf("任务 A 的 OR 查询返回了任务 B 的资产 id=%d domain=%s", a.ID, a.Domain)
			}
		}
	}
}
