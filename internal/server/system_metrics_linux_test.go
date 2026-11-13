//go:build linux

package server

import (
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/config"
)

// cgroupCPUAvailable 报告本机能否读到 cgroup CPU 计数（容器/裸机 Linux 都应可）。
// 仅 linux tag 文件可用——cgroupCPU 本体在 system_metrics_linux.go（同为 linux tag）。
func cgroupCPUAvailable() bool {
	_, _, ok := cgroupCPU()
	return ok
}

// CPU 百分比是跨请求差分：第一次采样建基线（lastCPUAt 从零值起算），第二次采样
// 必须更新基线且差分百分比落在 [0,100]（clampPercent 保证）。放 linux tag 文件，
// 非 Linux 平台 go vet/test 不会因 cgroupCPU 未定义而编译失败。
func TestSystemMetricsCPUBaselineAdvancesAcrossCalls(t *testing.T) {
	s := &Server{paths: config.DerivePaths(t.TempDir())}
	systemMetricsSnapshot(s)
	if s.lastCPUAt.IsZero() && cgroupCPUAvailable() {
		t.Fatalf("first snapshot did not establish cpu baseline")
	}
	time.Sleep(10 * time.Millisecond)
	second := systemMetricsSnapshot(s)
	if second.CPU.Percent < 0 || second.CPU.Percent > 100 {
		t.Fatalf("differential cpu percent out of range: %v", second.CPU.Percent)
	}
	if cgroupCPUAvailable() && s.lastCPUAt.IsZero() {
		t.Fatalf("second snapshot did not refresh cpu baseline")
	}
}
