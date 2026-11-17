package agent

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KillJobsForTaskDir 终止任务目录下仍在运行的后台作业（任务暂停/删除/进入终态时调用）。
//
// 作业进程用独立进程组启动，跨 run 存活是设计目标；但任务一旦暂停/结束，继续打目标
// 就超出授权窗口，而且删除任务目录后 rc/日志路径消失，作业会变成无主进程。
// 返回被终止的作业数。读不到目录/元数据时静默跳过（清理是尽力而为）。
// 接线点：server 侧任务暂停（SetTaskPaused paused=true）与删除（DeleteTask）。
func KillJobsForTaskDir(taskDir string) int {
	if strings.TrimSpace(taskDir) == "" {
		return 0
	}
	// 等所有在途 job_start 完成「启动 + 元数据登记」再扫描。job_start 持读锁；
	// 没有这把锁时，清理可能恰好扫在进程已启动、JSON 尚未落盘的窗口，漏杀
	// （上游 issue #18）。
	jobLifecycleMu.Lock()
	defer jobLifecycleMu.Unlock()
	jobsDir := filepath.Join(taskDir, "shared", "jobs")
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		m, ok := readJobMeta(jobsDir, name)
		if !ok {
			continue
		}
		if st, _ := jobState(m); st != "running" || m.PID <= 0 {
			continue
		}
		if err := jobKillGroup(m.PID); err != nil {
			continue
		}
		jobWaitGone(m.PID, 2*time.Second)
		_ = os.WriteFile(m.RCFile, []byte("137"), 0o644)
		killed++
	}
	return killed
}
