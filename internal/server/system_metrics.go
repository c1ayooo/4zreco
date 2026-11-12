package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// 系统资源指标（移植自 ARTEX 0.3.29 A3）：CPU/内存/根盘/数据盘的即时快照，
// 供 dashboard 顶部 5s 轮询展示。判定逻辑纯 Go（cgroup v1/v2 + /proc/meminfo +
// Statfs），不感知 eino（R4）；数据盘根取 config.Paths.Data（运行时目录唯一解析点）。

type metricValue struct {
	UsedBytes  uint64  `json:"used_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
	Percent    float64 `json:"percent"`
}

type systemMetricsResponse struct {
	Scope     string      `json:"scope"`
	Supported bool        `json:"supported"`
	Timestamp time.Time   `json:"timestamp"`
	CPU       metricValue `json:"cpu"`
	Memory    metricValue `json:"memory"`
	Disk      metricValue `json:"disk"`
	DataDisk  metricValue `json:"data_disk"`
	Container bool        `json:"container_metrics"`
}

func (s *Server) systemMetrics(w http.ResponseWriter, r *http.Request) {
	out := systemMetricsSnapshot(s)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
