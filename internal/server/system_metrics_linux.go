//go:build linux

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// systemMetricsSnapshot 采集一次系统资源快照（cgroup v1/v2 + /proc/meminfo + Statfs）。
// CPU 百分比是跨请求差分：首次调用无基线返回 0，之后按 cpu.stat 累计使用时长
// / 两次采样间隔 / CPU 配额（cgroup v2 cpu.max，v1 回落 NumCPU）折算，状态存
// Server 的 metricsMu/lastCPUUse/lastCPUAt（并发安全）。
func systemMetricsSnapshot(s *Server) systemMetricsResponse {
	use, limit, cpuOK := cgroupCPU()
	cpuPct := 0.0
	if cpuOK {
		now := time.Now()
		s.metricsMu.Lock()
		if !s.lastCPUAt.IsZero() && use >= s.lastCPUUse && limit > 0 {
			elapsed := now.Sub(s.lastCPUAt).Seconds()
			if elapsed > 0 {
				cpuPct = float64(use-s.lastCPUUse) / 1e6 / elapsed / limit * 100
			}
		}
		s.lastCPUUse, s.lastCPUAt = use, now
		s.metricsMu.Unlock()
	}
	memUsed, memTotal, memOK := cgroupMemory()
	root, data := diskMetric("/"), diskMetric(s.paths.Data)
	if data.TotalBytes == 0 {
		data = root
	}
	return systemMetricsResponse{
		Scope:     "container",
		Supported: true,
		Timestamp: time.Now().UTC(),
		Container: cpuOK || memOK,
		CPU:       metricValue{Percent: clampPercent(cpuPct)},
		Memory:    metricValue{UsedBytes: memUsed, TotalBytes: memTotal, Percent: percent(memUsed, memTotal)},
		Disk:      root,
		DataDisk:  data,
	}
}

// cgroupCPU 读 cgroup 的累计 CPU 使用（微秒）与配额。先试 v2 统一挂载点
// /sys/fs/cgroup，再回落 v1 的 /sys/fs/cgroup/cpu；v1 没有 cpu.max，配额取
// runtime.NumCPU()。
func cgroupCPU() (uint64, float64, bool) {
	for _, dir := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/cpu"} {
		b, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
		if err != nil {
			continue
		}
		var use uint64
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "usage_usec" {
				use, _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
		limit := float64(runtime.NumCPU())
		if q, err := os.ReadFile(filepath.Join(dir, "cpu.max")); err == nil {
			f := strings.Fields(string(q))
			if len(f) == 2 && f[0] != "max" {
				quota, _ := strconv.ParseFloat(f[0], 64)
				period, _ := strconv.ParseFloat(f[1], 64)
				if period > 0 {
					limit = quota / period
				}
			}
		}
		if use > 0 {
			return use, limit, true
		}
	}
	return 0, 0, false
}

// cgroupMemory 读 cgroup 内存用量与上限：v2（memory.current/memory.max，max 值
// "max" 表示无上限 → 回落 /proc/meminfo 的宿主总量），再试 v1
// （memory.usage_in_bytes/memory.limit_in_bytes，上限为天文数字时视为无效）。
func cgroupMemory() (uint64, uint64, bool) {
	for _, dir := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/memory"} {
		cur, ce := readUint(filepath.Join(dir, "memory.current"))
		max, me := readUint(filepath.Join(dir, "memory.max"))
		if ce == nil && me == nil {
			return cur, max, max > 0
		}
		if ce == nil {
			if b, err := os.ReadFile(filepath.Join(dir, "memory.max")); err == nil && strings.TrimSpace(string(b)) == "max" {
				return cur, hostMemoryTotal(), true
			}
		}
		cur, ce = readUint(filepath.Join(dir, "memory.usage_in_bytes"))
		max, me = readUint(filepath.Join(dir, "memory.limit_in_bytes"))
		if ce == nil && me == nil && max < ^uint64(0)/2 {
			return cur, max, true
		}
	}
	return 0, 0, false
}

// hostMemoryTotal 从 /proc/meminfo 读宿主物理内存总量（kB → 字节）。
func hostMemoryTotal() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemTotal:" {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n * 1024
		}
	}
	return 0
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// diskMetric 用 Statfs 读单个挂载点的用量（以 Bavail 计可用，不含 root 保留块）。
func diskMetric(path string) metricValue {
	var st syscall.Statfs_t
	if path == "" || syscall.Statfs(path, &st) != nil {
		return metricValue{}
	}
	total, free := st.Blocks*uint64(st.Bsize), st.Bavail*uint64(st.Bsize)
	used := total - free
	return metricValue{UsedBytes: used, TotalBytes: total, Percent: percent(used, total)}
}

func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return clampPercent(float64(used) / float64(total) * 100)
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
