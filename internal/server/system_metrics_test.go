package server

import (
	"encoding/json"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/c1ayooo/4zreco/internal/config"
)

// 移植自 ARTEX 0.3.29 system_metrics_test.go：响应结构（scope/timestamp/disk）+
// 非 Linux 的 unsupported 回退。全平台可编译可执行——Linux 分支与 !linux 分支
// 各自在对应平台真实跑（CPU 差分用例在 system_metrics_linux_test.go，带 linux tag）。
func TestSystemMetricsReturnsContainerAndDiskValues(t *testing.T) {
	s := &Server{paths: config.DerivePaths(t.TempDir())}
	r := httptest.NewRequest("GET", "/api/system/metrics", nil)
	w := httptest.NewRecorder()
	s.systemMetrics(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	var got systemMetricsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Scope == "" || got.Timestamp.IsZero() {
		t.Fatalf("unexpected response metadata: %+v", got)
	}
	if got.CPU.Percent < 0 || got.CPU.Percent > 100 {
		t.Fatalf("cpu percent out of range: %v", got.CPU.Percent)
	}
	if runtime.GOOS != "linux" {
		if got.Supported || got.Scope != "unsupported" {
			t.Fatalf("unsupported platform returned metrics: %+v", got)
		}
		return
	}
	if got.Disk.TotalBytes == 0 || got.DataDisk.TotalBytes == 0 {
		t.Fatalf("disk metrics missing: %+v", got)
	}
}
