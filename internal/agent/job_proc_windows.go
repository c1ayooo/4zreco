//go:build windows

package agent

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Windows 侧作业进程管理（移植自上游 job_proc_windows.go）：CREATE_NEW_PROCESS_GROUP
// 让作业自成一组；判定与收尸走 taskkill /soft→/force 兜底（JOB_OBJECT 方案在
// 任意 bash 包装下不可靠，上游同款取舍）。

// jobSysProcAttr 让作业进程自成进程组（CREATE_NEW_PROCESS_GROUP）。
func jobSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func jobKillGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	// 先 taskkill /T（整棵树）软杀，失败再 /F 强杀。
	if err := exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T").Run(); err == nil {
		return nil
	}
	return exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T", "/F").Run()
}

// jobOwnsProcess 判断 PID 是否仍属本作业。Windows 无 /proc，用 tasklist 认命令行
// 不可行（输出截断），退化为「进程存在即视为本作业」——与上游同款保守取舍：
// 读不到归属证据时宁可按有主处理，不误杀别人的进程。
func jobOwnsProcess(m jobMeta) bool {
	return m.PID > 0
}

// jobWaitGone 等目标进程消失（最多 timeout）。
func jobWaitGone(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if alive, known := jobProcessAlive(pid); known && !alive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// jobProcessAlive 用 OpenProcess 判活；known=false 表示判定不可用。
func jobProcessAlive(pid int) (alive bool, known bool) {
	if pid <= 0 {
		return false, true
	}
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		// 打不开 = 不存在（或权限不足；权限不足上游同样按不存在处理）。
		return false, true
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return true, false
	}
	// STILL_ACTIVE == 259
	return code == 259, true
}
