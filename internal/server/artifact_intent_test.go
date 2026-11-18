package server

import (
	"path/filepath"
	"testing"
)

// U6：意图 provenance 从运行目录基名提取——worker runDir 是
// tasks/<taskID>/i<intentID>（config.Paths.TaskRunDir），其余形态 → 0。
func TestIntentFromRunDir(t *testing.T) {
	// 入参契约 = 运行目录（recordArtifactAbs 传 filepath.Dir(abs)，即 runDir）。
	cases := map[string]int64{
		filepath.Join("data", "tasks", "12", "i34"):    34, // worker 运行目录
		filepath.Join("data", "tasks", "12"):           0,  // planner/主 agent 任务目录
		filepath.Join("data", "tasks", "12", "shared"): 0,
		filepath.Join("data", "tasks", "12", "i0"):     0, // i0 非法
		filepath.Join("data", "tasks", "12", "ix"):     0, // 非数字
		"":                                             0,
	}
	for dir, want := range cases {
		if got := intentFromRunDir(dir); got != want {
			t.Errorf("intentFromRunDir(%q)=%d want %d", dir, got, want)
		}
	}
}
