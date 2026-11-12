//go:build !linux

package server

import "time"

// systemMetricsSnapshot 在非 Linux 平台返回 unsupported 占位（前端据此隐藏资源条）。
func systemMetricsSnapshot(_ *Server) systemMetricsResponse {
	return systemMetricsResponse{Scope: "unsupported", Supported: false, Timestamp: time.Now().UTC()}
}
