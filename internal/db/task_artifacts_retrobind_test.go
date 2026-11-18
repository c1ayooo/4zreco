package db

import (
	"context"
	"testing"
)

// U6（上游 v0.4.47）：report_finding 回溯归属——同意图下全部未绑定证据一次性
// 归入本漏洞；其他意图/已绑定的证据不受影响。RetroBind 只走 db 句柄按
// task_id+intent_id 匹配，不需要真实 exploration 行（expID 不参与匹配）。
func TestRetroBindIntentEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	// 建表迁移由服务启动时调用（manager.go EnsureTaskArtifactsTable）；测试环境手动补。
	if err := d.EnsureTaskArtifactsTable(); err != nil {
		t.Fatal(err)
	}

	// RetroBind 的 taskID 参数是 int64（PG tasks.id），落库列是 text。
	taskID := "999901"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM task_artifacts WHERE task_id=$1`, taskID) })

	ins := func(intentID, findingID int64, name string) int64 {
		a := &TaskArtifact{TaskID: taskID, IntentID: intentID, FindingID: findingID,
			Name: name, Kind: "log", SizeBytes: 1, Storage: "tasks/x/artifacts/" + name}
		if err := d.InsertTaskArtifact(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	// 意图 7：2 条未绑定 + 1 条已绑定到其他漏洞；意图 8：1 条未绑定；任务级：1 条未绑定。
	i7a := ins(7, 0, "a-i7-unbound.png")
	i7b := ins(7, 0, "b-i7-unbound.log")
	i7c := ins(7, 999, "c-i7-bound-elsewhere.png")
	i8 := ins(8, 0, "d-i8-unbound.png")
	taskLevel := ins(0, 0, "e-task-level.png")

	ts := d.Exploration(0)
	n, err := ts.RetroBindIntentEvidence(999901, 7, 42)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应恰好归属 2 条未绑定证据，实际 %d", n)
	}
	get := func(id int64) int64 {
		a, err := d.GetTaskArtifact(id)
		if err != nil {
			t.Fatal(err)
		}
		return a.FindingID
	}
	if got := get(i7a); got != 42 {
		t.Errorf("意图 7 证据 a 应归入 finding 42，实际 %d", got)
	}
	if got := get(i7b); got != 42 {
		t.Errorf("意图 7 证据 b 应归入 finding 42，实际 %d", got)
	}
	if got := get(i7c); got != 999 {
		t.Errorf("已绑定其他漏洞的证据不得被抢占，实际 %d", got)
	}
	if got := get(i8); got != 0 {
		t.Errorf("其他意图的证据不得误绑，实际 %d", got)
	}
	if got := get(taskLevel); got != 0 {
		t.Errorf("任务级（无意图 provenance）证据不得误绑，实际 %d", got)
	}
}
