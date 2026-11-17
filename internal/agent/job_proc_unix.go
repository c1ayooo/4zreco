//go:build !windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// jobSysProcAttr 让作业进程自成进程组：job_stop 杀整组，内层脚本/子进程一起结束，
// 而不是只杀掉外层包装 shell（残留扫描进程继续打目标）。
func jobSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func jobKillGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

// jobOwnsProcess 判断 PID 是否仍是本作业的包装进程。
//
// 作业元数据跨重启保留，PID 可能被系统复用（服务器重启/进程崩溃后尤甚）；
// 只按 kill(pid,0) 判活会把无关进程当成作业，暂停/删除任务时甚至杀掉别人的进程组。
// 包装命令的 argv 里带有本作业唯一的 rc 路径：cmdline 不含它就不是我们的进程。
// 读不到 cmdline（权限/平台差异）时返回 true，保持旧行为，宁可不动也不误杀。
func jobOwnsProcess(m jobMeta) bool {
	if m.PID <= 0 || m.RCFile == "" {
		return m.PID > 0
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", m.PID)); err == nil {
		return strings.Contains(string(b), m.RCFile)
	}
	// macOS 等没有 /proc 的平台用 ps 兜底。
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(m.PID)).Output()
	if err != nil {
		return true
	}
	return strings.Contains(string(out), m.RCFile)
}

// jobWaitGone 在 SIGKILL 后等待目标真正消失（最多 timeout）。
// kill(2) 只是把信号排入队，目标可能还没被调度退出；CI 上紧接着断言进程已死
// 会因这个窗口假失败。进程被 cmd.Wait 收尸前是僵尸，kill(pid,0) 仍返回成功，
// 因此必须轮询到 ESRCH 而不是 kill 后立即返回。
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

// jobProcessAlive：known=false 表示当前平台不支持可靠判定（调用方按 pid>0 处理）。
func jobProcessAlive(pid int) (alive bool, known bool) {
	if pid <= 0 {
		return false, true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM, true
}
