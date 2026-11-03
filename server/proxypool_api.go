// 代理池 API:CRUD + 批量导入 + 连通性验证 + 主动健康检查。
//
// 持久化仍在 settings(proxy_pool_entries JSONB + proxy_pool_strategy),内存态经
// Traffic.SetProxyPool 原子推送。批量导入与验证解决原页面「只能一行行加、坏没坏
// 看不出、筛不掉」的问题;健康检查是后台协程,把「连败 5 次才熔断」升级成「主动
// 发现不通就立刻熔断」。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pgdb "github.com/c1ayooo/4zreco/db"
	"github.com/c1ayooo/4zreco/traffic"
	"golang.org/x/net/proxy"
)

const (
	settingProxyPoolEntries    = "proxy_pool_entries"
	settingProxyPoolStrategy   = "proxy_pool_strategy"
	settingProxyCheckTarget    = "proxypool_check_target"
	settingProxyHealthMinutes  = "proxypool_health_minutes"
	settingProxyHealthCooldown = "proxypool_health_cooldown_minutes"
)

const (
	defaultProxyCheckTarget    = "https://api.ipify.org?format=json"
	defaultProxyHealthMinutes  = 10 // 0 = 关闭主动健康检查
	defaultProxyHealthCooldown = 30 // 主动熔断的冷却时长(分钟)
	defaultProxyCheckTimeout   = 8 * time.Second
	proxyCheckConcurrency      = 8
)

// proxyPoolState 是持久化的池配置。URL 明文入库(与 LLM 配置密码同级别,
// settings 表不对外),对外输出掩码。
type proxyPoolState struct {
	Entries  []traffic.PoolEntry `json:"entries"`
	Strategy string              `json:"strategy"`
}

func (s *Server) loadProxyPool() *proxyPoolState {
	return loadProxyPoolState(s.m.pg)
}
func loadProxyPoolState(pg *pgdb.DB) *proxyPoolState {
	st := proxyPoolState{Strategy: "round_robin"}
	if raw, ok, _ := pg.GetSetting(settingProxyPoolEntries); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if v, ok, _ := pg.GetSetting(settingProxyPoolStrategy); ok && v != "" {
		st.Strategy = v
	}
	if st.Entries == nil {
		st.Entries = []traffic.PoolEntry{}
	}
	return &st
}

func (s *Server) saveProxyPool(st proxyPoolState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.m.pg.SetSetting(settingProxyPoolEntries, string(raw)); err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingProxyPoolStrategy, st.Strategy)
}

// proxyPoolGet 返回当前配置(含运行状态:熔断计数/掩码/最近一次验证)。
func (s *Server) proxyPoolGet(w http.ResponseWriter, r *http.Request) {
	st := s.loadProxyPool()
	running := []traffic.PoolEntry{}
	if t := s.m.traffic; t != nil {
		running = t.ProxyPoolStatus()
	}
	s.m.proxyCheckMu.Lock()
	last := s.m.proxyCheckLast
	s.m.proxyCheckMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"entries":         st.Entries,
		"strategy":        st.Strategy,
		"running":         running,
		"capturing":       s.m.TrafficEnabled(),
		"check_target":    settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
		"health_minutes":  intSetting(s.m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes),
		"health_cooldown": intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown),
		"last_check":      last,
	})
}

// settingOr 读字符串设置,缺失/空时用默认值。
func settingOr(pg *pgdb.DB, key, def string) string {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// proxyPoolPut 全量替换配置并热应用。
func (s *Server) proxyPoolPut(w http.ResponseWriter, r *http.Request) {
	var in proxyPoolState
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Entries == nil {
		in.Entries = []traffic.PoolEntry{}
	}
	// 校验:URL 可解析、权重下限、名称去重留白
	seen := map[string]bool{}
	for i := range in.Entries {
		e := &in.Entries[i]
		if _, err := traffic.ValidateProxyURL(e.URL); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if e.Weight < 1 {
			e.Weight = 1
		}
		if seen[e.URL] {
			writeErr(w, 400, "重复的代理地址: "+e.URL)
			return
		}
		seen[e.URL] = true
	}
	if t := s.m.traffic; t != nil {
		if err := t.SetProxyPool(in.Entries, in.Strategy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if err := s.saveProxyPool(in); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.proxyPoolGet(w, r)
}

// --- 批量导入 ---

type proxyBulkInvalid struct {
	Line   int    `json:"line"`
	Raw    string `json:"raw"`
	Reason string `json:"reason"`
}

// parseProxyLine 解析一行代理。支持的形态(用户从付费站导出的常见格式):
//
//	1.2.3.4:8080
//	http://1.2.3.4:8080  /  socks5://user:pass@1.2.3.4:1080
//	1.2.3.4:8080:user:pass
//	名字 | 1.2.3.4:8080     (名字用竖线,避免与 URL 里的冒号混淆)
//	以 # 开头或空行 = 注释
//
// 省略 scheme 一律按 http 补——socks5 必须显式写出来,否则会被当 http 代理连失败。
func parseProxyLine(raw string) (name, u string, comment bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", "", true, nil
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return "", "", true, nil
	}
	if i := strings.Index(line, "|"); i >= 0 {
		name = strings.TrimSpace(line[:i])
		line = strings.TrimSpace(line[i+1:])
	}
	// host:port:user:pass(最常见的付费商导出格式)
	if strings.Count(line, ":") == 3 && !strings.Contains(line, "://") {
		parts := strings.SplitN(line, ":", 4)
		if strings.Contains(parts[0], ".") && parts[1] != "" {
			u = fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
			return name, u, false, nil
		}
	}
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}
	if _, err := url.Parse(line); err != nil {
		return name, line, false, err
	}
	return name, line, false, nil
}

// proxyPoolBulk 批量导入。mode=append 追加(默认),replace 整体替换。
// 返回逐行结果,让前端能明确指出哪一行错在哪。
func (s *Server) proxyPoolBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		Mode     string `json:"mode"`
		Strategy string `json:"strategy"`
		Weight   int    `json:"weight"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "append"
	}
	if req.Mode != "append" && req.Mode != "replace" {
		writeErr(w, 400, "mode 只能是 append 或 replace")
		return
	}
	weight := req.Weight
	if weight < 1 {
		weight = 1
	}

	st := s.loadProxyPool()
	if req.Mode == "replace" {
		st.Entries = []traffic.PoolEntry{}
	}
	byURL := map[string]int{}
	for i, e := range st.Entries {
		byURL[e.URL] = i
	}

	var invalid []proxyBulkInvalid
	added, updated := 0, 0
	lines := strings.Split(req.Text, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		name, raw, isComment, _ := parseProxyLine(ln)
		if isComment {
			continue
		}
		norm, verr := traffic.ValidateProxyURL(raw)
		if verr != nil {
			invalid = append(invalid, proxyBulkInvalid{Line: i + 1, Raw: strings.TrimSpace(ln), Reason: verr.Error()})
			continue
		}
		if name == "" {
			name = norm.Host
		}
		key := norm.String()
		if idx, ok := byURL[key]; ok {
			st.Entries[idx].Name = name
			st.Entries[idx].Enabled = true
			if st.Entries[idx].Weight < 1 {
				st.Entries[idx].Weight = weight
			}
			updated++
			continue
		}
		st.Entries = append(st.Entries, traffic.PoolEntry{
			URL: key, Name: name, Enabled: true, Weight: weight,
		})
		byURL[key] = len(st.Entries) - 1
		added++
	}
	if req.Strategy != "" {
		st.Strategy = req.Strategy
	}
	if t := s.m.traffic; t != nil {
		if err := t.SetProxyPool(st.Entries, st.Strategy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if err := s.saveProxyPool(*st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "added": added, "updated": updated, "invalid": invalid,
		"total": len(st.Entries),
	})
}

// --- 连通性验证 ---

type proxyCheckResult struct {
	Index     int    `json:"index"`
	URL       string `json:"url"` // 掩码
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at"`
}

// proxyPoolCheck 验证给定（或全部）代理的真实可用性。结果写回内存态的
// last_ok/last_fail,失败直接熔断——「一键筛选可用」正是建立在这些结果上。
func (s *Server) proxyPoolCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URLs        []string `json:"urls"` // 空 = 全部已启用条目
		Target      string   `json:"target"`
		TimeoutSec  int      `json:"timeout_seconds"`
		BreakOnFail bool     `json:"break_on_fail"`
	}
	_ = decode(r, &req)
	st := s.loadProxyPool()
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = defaultProxyCheckTimeout
	}

	want := map[string]bool{}
	for _, u := range req.URLs {
		want[u] = true
	}
	selected := st.Entries
	if len(want) > 0 {
		selected = nil
		for _, e := range st.Entries {
			if want[e.URL] {
				selected = append(selected, e)
			}
		}
	}
	results := make([]proxyCheckResult, len(selected))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, e := range selected {
		// 掩码 URL 用于回显;真实凭据只在请求时用。
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(context.Background(), idx, echo, entry.URL, target, timeout)
		}(i, e, masked)
	}
	wg.Wait()

	// 把验证结果写回池状态(成功清零连败、失败按需熔断),让下一次 Pick
	// 立刻避开坏出口,同时刷新页面上的 last_ok/last_fail。
	t := s.m.traffic
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	for i, res := range results {
		if t == nil {
			continue
		}
		raw := selected[i].URL
		if res.OK {
			t.ProxyPoolReportOK(raw)
		} else if req.BreakOnFail {
			t.ProxyPoolMarkBad(raw, cooldown)
		} else {
			t.ProxyPoolReportFail(raw)
		}
	}

	// 记录一次「最近检查」供 UI 展示时间戳。
	s.m.proxyCheckMu.Lock()
	s.m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
	}
	s.m.proxyCheckMu.Unlock()

	writeJSON(w, 200, map[string]any{
		"target":  target,
		"results": results,
	})
}

func countOK(list []proxyCheckResult) int {
	n := 0
	for _, r := range list {
		if r.OK {
			n++
		}
	}
	return n
}

// s_probeAll 并发验证一批上游。手动验证与后台健康检查共用同一套探测逻辑——
// 两条路径对「什么叫可用」的理解必须一致,否则页面显示可用但实际不通。
func s_probeAll(ctx context.Context, m *Manager, entries []traffic.PoolEntry, target string) []proxyCheckResult {
	results := make([]proxyCheckResult, len(entries))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, e := range entries {
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(ctx, idx, echo, entry.URL, target, defaultProxyCheckTimeout)
		}(i, e, masked)
	}
	wg.Wait()
	return results
}

// checkOneProxy 经由该代理请求 target,记录耗时与出口 IP。
func checkOneProxy(ctx context.Context, idx int, masked, raw, target string, timeout time.Duration) proxyCheckResult {
	res := proxyCheckResult{Index: idx, URL: masked, CheckedAt: time.Now().Format(time.RFC3339)}
	proxyURL, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	transport := &http.Transport{}
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 交给 x/net/proxy 拨号:http.Transport 只认 HTTP 代理。
		transport.Proxy = nil
		transport.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			return socksDial(c, proxyURL, addr)
		}
	default:
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	hc := &http.Client{Timeout: timeout, Transport: transport}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !res.OK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.ExitIP = extractIP(string(body))
	return res
}

// socksDial 通过 SOCKS5 代理建立到 addr 的连接。
func socksDial(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return dialer.Dial("tcp", addr)
}

// extractIP 从探测响应里抓出口 IP(抓不到就留空,不影响可用性判定)。
func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, key := range []string{`"ip"`, `"origin"`, `"query"`} {
		if i := strings.Index(s, key); i >= 0 {
			rest := s[i+len(key):]
			if j := strings.IndexAny(rest, "\"'"); j >= 0 {
				rest = rest[j+1:]
			}
			if k := strings.IndexAny(rest, "\"'} \n"); k >= 0 {
				rest = rest[:k]
			}
			if looksLikeIP(rest) {
				return rest
			}
		}
	}
	if looksLikeIP(s) {
		return s
	}
	return ""
}

func looksLikeIP(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// maskProxy 隐藏凭据,只用于回显。
func maskProxy(raw string) string {
	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		return raw
	}
	return u.String()
}
