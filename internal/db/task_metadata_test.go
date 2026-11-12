package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTaskPinOrderingAndRename(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	first, err := d.CreateTask(fmt.Sprintf("task-pin-first-%d", suffix), "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateTask(fmt.Sprintf("task-pin-second-%d", suffix), "goal", nil, 0, 0)
	if err != nil {
		_ = d.DeleteTask(first.ID)
		t.Fatal(err)
	}
	defer func() {
		_ = d.DeleteTask(first.ID)
		_ = d.DeleteTask(second.ID)
	}()

	pinned := true
	first, err = d.UpdateTask(first.ID, TaskPatch{Pinned: &pinned})
	if err != nil || first == nil || !first.Pinned || first.PinnedAt == nil {
		t.Fatalf("pin first = %+v, %v", first, err)
	}
	firstPinnedAt := *first.PinnedAt
	// 无需 sleep：ListTasks 的排序 pinned_at 同刻时由 id DESC 决胜，
	// 后 pin 的 second（id 更大）必然排前。
	second, err = d.UpdateTask(second.ID, TaskPatch{Pinned: &pinned})
	if err != nil || second == nil || !second.Pinned || second.PinnedAt == nil {
		t.Fatalf("pin second = %+v, %v", second, err)
	}

	name := "renamed pinned task"
	first, err = d.UpdateTask(first.ID, TaskPatch{Name: &name, Pinned: &pinned})
	if err != nil || first == nil {
		t.Fatal(err)
	}
	if first.Name != name || first.PinnedAt == nil || !first.PinnedAt.Equal(firstPinnedAt) {
		t.Fatalf("repeat pin should preserve pin time: %+v (want %v)", first, firstPinnedAt)
	}

	tasks, err := d.ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	positions := map[int64]int{}
	for index, task := range tasks {
		positions[task.ID] = index
	}
	if positions[second.ID] >= positions[first.ID] {
		t.Fatalf("newer pin must sort first: second=%d first=%d", positions[second.ID], positions[first.ID])
	}

	pinned = false
	first, err = d.UpdateTask(first.ID, TaskPatch{Pinned: &pinned})
	if err != nil || first == nil || first.Pinned || first.PinnedAt != nil {
		t.Fatalf("unpin first = %+v, %v", first, err)
	}
}

func TestNormalizeTaskRemark(t *testing.T) {
	// 纯函数单测：trim 与上限校验（ARTEX 移植 A1）。
	got, err := NormalizeTaskRemark("  带空白的备注  ")
	if err != nil || got != "带空白的备注" {
		t.Fatalf("NormalizeTaskRemark = %q, %v", got, err)
	}
	if got, err := NormalizeTaskRemark("   "); err != nil || got != "" {
		t.Fatalf("whitespace remark = %q, %v, want empty with no error", got, err)
	}
	if _, err := NormalizeTaskRemark(strings.Repeat("界", MaxTaskRemarkRunes)); err != nil {
		t.Fatalf("boundary remark (%d runes) must pass: %v", MaxTaskRemarkRunes, err)
	}
	_, err = NormalizeTaskRemark(strings.Repeat("界", MaxTaskRemarkRunes+1))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("备注最多 %d 个字符", MaxTaskRemarkRunes)) {
		t.Fatalf("over-limit remark error = %v, want 备注最多 %d 个字符", err, MaxTaskRemarkRunes)
	}
}

func TestTaskRemarkPatchValidatedAndPersisted(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	task, err := d.CreateTask(fmt.Sprintf("task-remark-%d", suffix), "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()

	remark := strings.Repeat("界", MaxTaskRemarkRunes)
	updated, err := d.UpdateTask(task.ID, TaskPatch{Remark: &remark})
	if err != nil || updated == nil {
		t.Fatalf("boundary remark patch = %+v, %v", updated, err)
	}
	got, err := d.GetTask(task.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTask = %+v, %v", got, err)
	}
	if got.Remark != remark {
		t.Fatalf("remark not persisted (len=%d, want %d)", len([]rune(got.Remark)), MaxTaskRemarkRunes)
	}

	over := strings.Repeat("界", MaxTaskRemarkRunes+1)
	if _, err := d.UpdateTask(task.ID, TaskPatch{Remark: &over}); err == nil {
		t.Fatalf("over-limit remark patch must fail")
	}

	empty := "  "
	updated, err = d.UpdateTask(task.ID, TaskPatch{Remark: &empty})
	if err != nil || updated == nil || updated.Remark != "" {
		t.Fatalf("blank remark should normalize to empty: %+v, %v", updated, err)
	}
}

func TestDeleteConversationsReturnsExistingIDs(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	first, err := d.CreateConversation("mainagent", "batch-delete-first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateConversation("mainagent", "batch-delete-second", nil)
	if err != nil {
		_ = d.DeleteConversation(first.ID)
		t.Fatal(err)
	}
	defer func() {
		_ = d.DeleteConversation(first.ID)
		_ = d.DeleteConversation(second.ID)
	}()

	missing := int64(1<<62 - 1)
	deleted, err := d.DeleteConversations([]int64{first.ID, missing, second.ID})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int64]bool, len(deleted))
	for _, id := range deleted {
		seen[id] = true
	}
	if !seen[first.ID] || !seen[second.ID] || seen[missing] || len(deleted) != 2 {
		t.Fatalf("deleted=%v, want existing ids only", deleted)
	}
}
