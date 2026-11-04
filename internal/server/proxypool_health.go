// 代理池的主动健康检查与 Agent 侧工具。
//
// 被动熔断要等「连败 5 次」,而一个已经挂掉的代理再试 5 次只是白白拖慢请求。
// 这里加一条后台巡检:每隔 N 分钟并发验证所有已启用上游,不通的立刻熔断。
//
// Agent 侧给两个工具:proxy_status(看池状态)与 proxy_report(上报「这个目标被限速/
// 不通」,平台据此换出口)。Agent 不需要知道每条命令走了哪个代理——出口选择
// 始终由平台按策略做,Agent 只负责反馈「这个出口对我不好使」。
package server

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/internal/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

// StartProxyPoolHealthCheck launches the background probe loop. It is a no-op
// when the interval is 0 (health check disabled).
func (m *Manager) StartProxyPoolHealthCheck() {
	if m == nil || m.pg == nil {
		return
	}
	interval := time.Duration(intSetting(m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes)) * time.Minute
	if interval <= 0 {
		log.Printf("[proxypool] 主动健康检查已关闭（proxypool_health_minutes=0）")
		return
	}
	go func() {
		// 启动延迟：避开进程刚起来的流量高峰，也给 hostd/traffic 代理留出时间。
		time.Sleep(90 * time.Second)
		for {
			m.RunProxyPoolHealthCheck()
			time.Sleep(interval)
		}
	}()
}

// RunProxyPoolHealthCheck probes every enabled upstream once and melts down the
// dead ones. Safe to call from the API (manual "check all") as well.
func (m *Manager) RunProxyPoolHealthCheck() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	if !m.proxyCheckInFlight.CompareAndSwap(false, true) {
		return // 已有一轮在跑
	}
	defer m.proxyCheckInFlight.Store(false)

	st := loadProxyPoolState(m.pg)
	enabled := make([]traffic.PoolEntry, 0, len(st.Entries))
	for _, e := range st.Entries {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}
	if len(enabled) == 0 {
		return
	}
	target := settingOr(m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	cooldown := time.Duration(intSetting(m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	results := s_probeAll(ctx, m, enabled, target)
	dead := 0
	for i, res := range results {
		raw := enabled[i].URL
		if res.OK {
			m.traffic.ProxyPoolReportOK(raw)
			continue
		}
		dead++
		m.traffic.ProxyPoolMarkBad(raw, cooldown)
	}
	if dead > 0 {
		log.Printf("[proxypool] 健康检查：%d/%d 个上游不可用，已熔断", dead, len(enabled))
	}
	// 页面上的「最近检查」时间戳与手动验证共用同一份快照。
	m.proxyCheckMu.Lock()
	m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
		"auto":     true,
	}
	m.proxyCheckMu.Unlock()
}

// proxyTools 返回给 agent 的代理池工具。采集中关闭时池不生效,工具会明确说明
// 这一点而不是报错——agent 需要知道「现在走的是直连/全局代理」。
func (s *Server) proxyTools() []actool.CoreTool {
	proxyStatus := actool.Build(actool.Spec{
		Name:        "proxy_status",
		Description: "查当前出口代理池的状态：策略、每个上游的可用性/熔断剩余/最近一次成功失败时间、当前是否在生效。判断「目标连不通」是不是出口的问题时先看这里。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyStatusResult()
		},
	})
	proxyReport := actool.Build(actool.Spec{
		Name: "proxy_report",
		Description: "上报「当前出口对这个目标不好使」（被限速 / 连不通 / 被封），平台会立即熔断该出口并换一个。" +
			"target 填你刚才访问的目标 host（可带端口）。只有确认是出口问题才调——目标本身拒绝服务不算。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "刚才访问的目标 host（可带端口，如 10.10.0.5:8080）"},
				"reason": map[string]any{"type": "string", "description": "原因（限速/超时/拒绝连接等），便于审计"},
			},
			"required": []any{"target"},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyReportResult(in)
		},
	})
	return []actool.CoreTool{proxyStatus, proxyReport}
}

func (s *Server) proxyStatusResult() (actool.Result, error) {
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("代理池未初始化"), nil
	}
	st := s.loadProxyPool()
	out := map[string]any{
		"strategy":      st.Strategy,
		"total":         len(st.Entries),
		"capturing":     s.m.TrafficEnabled(),
		"global_proxy":  s.m.GlobalProxy() != "",
		"upstreams":     s.m.traffic.ProxyPoolStatus(),
		"health_check":  settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
	}
	if len(st.Entries) == 0 {
		out["note"] = "代理池为空：流量直接出本机（或走「全局出口代理」）。要轮换出口请在 系统 → 代理池 配置。"
	} else if !s.m.TrafficEnabled() {
		out["note"] = "代理池已配置但【流量捕获未开启】，池不生效——worker 的目标流量需经捕获代理才会走出口轮换。"
	}
	return jsonResult(out)
}

func (s *Server) proxyReportResult(in json.RawMessage) (actool.Result, error) {
	var a struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(in, &a)
	target := strings.TrimSpace(a.Target)
	if target == "" {
		return actool.Errorf("target 为必填"), nil
	}
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("代理池未初始化"), nil
	}
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	broken := s.m.traffic.ProxyPoolReportBad(target, cooldown)
	if broken == "" {
		return jsonResult(map[string]any{
			"ok":   false,
			"note": "该目标没有走代理池（直连或走全局出口代理），没有可切换的出口。",
		})
	}
	return jsonResult(map[string]any{
		"ok":              true,
		"broken_upstream": broken,
		"cooldown_min":    int(cooldown / time.Minute),
		"note":            "已熔断该出口，后续请求会自动换用其它上游；若仍不通说明是目标侧问题。",
	})
}
