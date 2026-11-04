package db

import (
	"testing"
)

// cleanupProject removes a project and its dependents (scope cascades;
// tasks/conversations detach via FK, but tests drop their own rows anyway).
func cleanupProject(d *DB, projectID, taskID, convID int64) {
	if convID > 0 {
		d.Exec(`DELETE FROM conversations WHERE id=$1`, convID)
	}
	if taskID > 0 {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
	}
	if projectID > 0 {
		d.Exec(`DELETE FROM projects WHERE id=$1`, projectID)
	}
}

func TestProjectScopeCRUD(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	ps := d.Projects()

	p, err := ps.CreateProject("测试项目", "范围 CRUD 用例")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProject(d, p.ID, 0, 0)

	// 多行解析：域名/IP/CIDR/关键词各一条 + 一条非法。
	added, skipped, invalid, errMsgs := ps.AddProjectScope(p.ID, []string{
		"example.com",
		"203.0.113.10",
		"198.51.100.0/24",
		"测试关键词",
		"10.0.0.0/8", // 过宽 IPv4 网段，ParseScopeInput 护栏拒绝
	}, "测试")
	if added != 4 || skipped != 0 || invalid != 1 || len(errMsgs) != 1 {
		t.Fatalf("added=%d skipped=%d invalid=%d errMsgs=%v, want 4/0/1/1", added, skipped, invalid, errMsgs)
	}

	// 重复追加 = skipped 不报错。
	added2, skipped2, invalid2, _ := ps.AddProjectScope(p.ID, []string{"example.com", "198.51.100.0/24", "10.0.0.0/8"}, "")
	if added2 != 0 || invalid2 != 1 || skipped2 != 2 {
		t.Fatalf("re-add: added=%d skipped=%d invalid=%d, want 0/2/1 (dup→skipped)", added2, skipped2, invalid2)
	}

	rules, err := ps.ProjectScopeRules(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("rules=%d, want 4", len(rules))
	}
	if rules[0].Kind != "domain" || rules[0].Domain != "example.com" {
		t.Errorf("rule0 = %+v, want domain example.com", rules[0])
	}
	if rules[1].Kind != "ip" || rules[1].Net == "" {
		t.Errorf("rule1 = %+v, want ip with net", rules[1])
	}

	// 富化计数。
	got, err := ps.GetProject(p.ID)
	if err != nil || got.ID == 0 {
		t.Fatalf("GetProject: %v %+v", err, got)
	}
	if len(got.Scope) != 4 || got.TaskCount != 0 {
		t.Errorf("enriched project: scope=%d taskCount=%d, want 4/0", len(got.Scope), got.TaskCount)
	}

	// 删除单条规则。
	if err := ps.DeleteProjectScope(p.ID, rules[0].ID); err != nil {
		t.Fatal(err)
	}
	remaining, _ := ps.ProjectScopeRules(p.ID)
	if len(remaining) != 3 {
		t.Fatalf("after delete rules=%d, want 3", len(remaining))
	}

	// 更新与归档。
	up, err := ps.UpdateProject(p.ID, "测试项目改", "更新后的描述", "archived")
	if err != nil {
		t.Fatal(err)
	}
	if up.Status != "archived" || up.Name != "测试项目改" {
		t.Errorf("update = %+v", up)
	}

	// 删除项目：scope 级联。
	if err := ps.DeleteProject(p.ID); err != nil {
		t.Fatal(err)
	}
	gone, err := ps.GetProject(p.ID)
	if err != nil || gone.ID != 0 {
		t.Fatalf("deleted project still readable: %v %+v", err, gone)
	}
}

func TestTaskProjectSeeding(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	p, err := d.Projects().CreateProject("种子项目", "")
	if err != nil {
		t.Fatal(err)
	}
	if added, _, _, _ := d.Projects().AddProjectScope(p.ID, []string{"seeded.example.com", "198.51.100.0/24"}, ""); added != 2 {
		t.Fatalf("scope added=%d, want 2", added)
	}
	pid := p.ID
	defer cleanupProject(d, pid, 0, 0)

	// 挂项目建任务：project_scope 种成 task_scope(source='project')。
	tk, err := d.CreateTaskWithOptions("项目任务", "目标", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	taskID := tk.ID
	defer cleanupProject(d, 0, taskID, 0)

	if got, err := d.TaskProjectID(taskID); err != nil || got != pid {
		t.Fatalf("TaskProjectID=%d err=%v, want %d", got, err, pid)
	}
	scope, err := d.Assets().ListTaskScope(taskID)
	if err != nil {
		t.Fatal(err)
	}
	var seeded int
	for _, s := range scope {
		if s.Source == "project" {
			seeded++
			if s.Kind != "root_domain" && s.Kind != "cidr" {
				t.Errorf("seeded kind=%s, want root_domain|cidr", s.Kind)
			}
		}
	}
	if seeded != 2 {
		t.Fatalf("seeded rows=%d, want 2 (scope=%+v)", seeded, scope)
	}
	if got, err := d.Projects().GetProject(pid); err != nil || got.TaskCount != 1 {
		t.Fatalf("task count=%d err=%v, want 1", got.TaskCount, err)
	}

	// 不挂项目建任务：无种子行。
	tk2, err := d.CreateTaskWithOptions("无项目任务", "目标", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProject(d, 0, tk2.ID, 0)
	if got, err := d.TaskProjectID(tk2.ID); err != nil || got != 0 {
		t.Fatalf("unattached TaskProjectID=%d err=%v, want 0", got, err)
	}
	scope2, _ := d.Assets().ListTaskScope(tk2.ID)
	for _, s := range scope2 {
		if s.Source == "project" {
			t.Errorf("unattached task got a project-seeded scope row: %+v", s)
		}
	}

	// 删项目：task.project_id 置空，任务本身还在。
	if err := d.Projects().DeleteProject(pid); err != nil {
		t.Fatal(err)
	}
	if got, err := d.TaskProjectID(taskID); err != nil || got != 0 {
		t.Fatalf("after project delete TaskProjectID=%d err=%v, want 0", got, err)
	}
}

func TestConversationBindingPatch(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	p, err := d.Projects().CreateProject("对话绑定项目", "")
	if err != nil {
		t.Fatal(err)
	}
	pid := p.ID
	tk, err := d.CreateTaskWithOptions("绑定目标任务", "目标", TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	taskID := tk.ID
	conv, err := d.CreateConversation("auto", "绑定测试", nil)
	if err != nil {
		t.Fatal(err)
	}
	convID := conv.ID
	defer cleanupProject(d, pid, taskID, convID)

	// 绑定任务 → project 对齐由 server 层做，这里直接双写。
	if _, err := d.UpdateConversation(convID, ConversationPatch{ProjectID: &pid, TaskID: &taskID}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetConversation(convID)
	if err != nil || got.ProjectID == nil || *got.ProjectID != pid || got.TaskID == nil || *got.TaskID != taskID {
		t.Fatalf("binding = %+v err=%v, want project=%d task=%d", got, err, pid, taskID)
	}

	// 省略 = 不改：只改标题，绑定保留。
	newTitle := "改标题"
	if _, err := d.UpdateConversation(convID, ConversationPatch{Title: &newTitle}); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetConversation(convID)
	if got.Title != newTitle || got.ProjectID == nil || got.TaskID == nil {
		t.Fatalf("partial patch lost bindings: %+v", got)
	}

	// 0 = 清除。
	zero := int64(0)
	if _, err := d.UpdateConversation(convID, ConversationPatch{ProjectID: &zero, TaskID: &zero}); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetConversation(convID)
	if got.ProjectID != nil || got.TaskID != nil {
		t.Fatalf("zero-clear failed: %+v", got)
	}

	// 删任务：task_id 置空（FK ON DELETE SET NULL）。
	if _, err := d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateConversation(convID, ConversationPatch{ProjectID: &pid}); err != nil {
		t.Fatal(err)
	}
	if err := d.Projects().DeleteProject(pid); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetConversation(convID)
	if got.ProjectID != nil || got.TaskID != nil {
		t.Fatalf("FK detach failed: %+v", got)
	}
}
