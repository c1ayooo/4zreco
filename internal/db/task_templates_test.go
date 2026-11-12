package db

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTaskTemplateCRUDAndNormalizedUniqueness(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("Template %d", suffix)
	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        "  " + strings.ReplaceAll(name, " ", "   ") + "  ",
		Description: "  initial description  ",
		Goal:        "  initial goal  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })
	if created.Name != name || created.Description != "initial description" || created.Goal != "initial goal" {
		t.Fatalf("template was not normalized: %+v", created)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: strings.ToUpper(name), Description: "duplicate", Goal: "duplicate",
	}); !errors.Is(err, ErrTaskTemplateNameConflict) {
		t.Fatalf("duplicate create error = %v, want %v", err, ErrTaskTemplateNameConflict)
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil || got == nil || got.Name != name {
		t.Fatalf("GetTaskTemplate = %+v, %v", got, err)
	}
	listed, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, template := range listed {
		if template.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created template %d missing from list", created.ID)
	}

	updatedName := name + " updated"
	updated, err := d.UpdateTaskTemplate(created.ID, TaskTemplateInput{
		Name: updatedName, Description: "new description", Goal: "new goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != updatedName || updated.Description != "new description" || updated.Goal != "new goal" {
		t.Fatalf("unexpected updated template: %+v", updated)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{Name: "", Description: "x", Goal: "y"}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("empty name error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	deleted, err := d.DeleteTaskTemplate(created.ID)
	if err != nil || !deleted {
		t.Fatalf("DeleteTaskTemplate = %v, %v", deleted, err)
	}
	deleted, err = d.DeleteTaskTemplate(created.ID)
	if err != nil || deleted {
		t.Fatalf("second DeleteTaskTemplate = %v, %v", deleted, err)
	}
}

func TestTaskTemplateDisjointPatchesCompose(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        fmt.Sprintf("Concurrent template %d", time.Now().UnixNano()),
		Description: "initial description",
		Goal:        "initial goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })

	description := "description from concurrent patch"
	goal := "goal from concurrent patch"
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, patch := range []TaskTemplatePatch{{Description: &description}, {Goal: &goal}} {
		patch := patch
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.PatchTaskTemplate(created.ID, patch)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Description != description || got.Goal != goal {
		t.Fatalf("disjoint patches lost an update: %+v", got)
	}
}

func TestTaskTemplateRemarkValidatedAndPersisted(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        fmt.Sprintf("Remark template %d", suffix),
		Description: "description",
		Goal:        "goal",
		Remark:      "  初始备注  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })
	if created.Remark != "初始备注" {
		t.Fatalf("template remark was not normalized: %q", created.Remark)
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil || got == nil || got.Remark != "初始备注" {
		t.Fatalf("GetTaskTemplate remark = %+v, %v", got, err)
	}

	remark := strings.Repeat("界", MaxTaskRemarkRunes)
	updated, err := d.PatchTaskTemplate(created.ID, TaskTemplatePatch{Remark: &remark})
	if err != nil || updated == nil || updated.Remark != remark {
		t.Fatalf("boundary remark patch = %+v, %v", updated, err)
	}

	over := strings.Repeat("界", MaxTaskRemarkRunes+1)
	if _, err := d.PatchTaskTemplate(created.ID, TaskTemplatePatch{Remark: &over}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("over-limit remark patch error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: fmt.Sprintf("Remark over %d", suffix), Description: "d", Goal: "g", Remark: over,
	}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("over-limit create remark error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
}

func TestNormalizeTaskTemplateRemarkBounds(t *testing.T) {
	// 纯函数单测（无 PG）：normalize 层的备注上限与 trim。
	in, _, err := normalizeTaskTemplateInput(TaskTemplateInput{
		Name: "n", Description: "d", Goal: "g", Remark: "  ok  ",
	})
	if err != nil || in.Remark != "ok" {
		t.Fatalf("normalize input remark = %q, %v", in.Remark, err)
	}
	if _, _, err := normalizeTaskTemplateInput(TaskTemplateInput{
		Name: "n", Description: "d", Goal: "g", Remark: strings.Repeat("界", MaxTaskRemarkRunes+1),
	}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("over-limit input remark error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	remark := strings.Repeat("界", MaxTaskRemarkRunes)
	patch, _, err := normalizeTaskTemplatePatch(TaskTemplatePatch{Remark: &remark})
	if err != nil || patch.Remark == nil || *patch.Remark != remark {
		t.Fatalf("boundary patch remark = %+v, %v", patch.Remark, err)
	}
	over := strings.Repeat("界", MaxTaskRemarkRunes+1)
	if _, _, err := normalizeTaskTemplatePatch(TaskTemplatePatch{Remark: &over}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("over-limit patch remark error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
}
