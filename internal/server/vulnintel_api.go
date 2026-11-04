// 漏洞情报 API:状态与配置、手动同步、连通性诊断。
//
// 状态页原先是纯只读的:只能看到条数和「正常/有错误」两个 badge,失败原因藏在
// badge 的 title 里,没有任何配置入口也不能手动重试。这里把它补成「能配、能测、
// 能修」——配置从 settings 读写,同步与模板更新共用同一条 pass(互斥),连通性
// 诊断直接按当前代理逐源探测并返回可执行的修复建议。
package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	pgdb "github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/traffic"
	"github.com/c1ayooo/4zreco/internal/vulnintel"
)

// 情报配置（对外脱敏：key/token 只回 set 布尔与尾号）。
type vulnintelConfigDTO struct {
	Enabled        bool   `json:"enabled"`
	NvdAPIKey      string `json:"nvd_api_key"` // 写入用；读取时为掩码
	NvdKeySet      bool   `json:"nvd_key_set"`
	GitHubToken    string `json:"github_token"` // 写入用；读取时为掩码
	GitHubSet      bool   `json:"github_token_set"`
	Proxy          string `json:"proxy"`
	PocEnabled     bool   `json:"poc_enabled"`
	BackfillDays   int    `json:"backfill_days"`
	MaxRuntimeMin  int    `json:"max_runtime_minutes"`
	MaintenanceURL string `json:"maintenance_proxy"` // 只读回显：走「跟随维护代理」时的兜底值
}

func (s *Server) vulnintelConfigForWrite() vulnintelConfigDTO {
	pg := s.m.pg
	return vulnintelConfigDTO{
		Enabled:        pg.GetBool(settingVulnIntelOn, true),
		NvdAPIKey:      strings.TrimSpace(settingString(pg, settingNvdApiKey)),
		GitHubToken:    strings.TrimSpace(settingString(pg, settingVulnIntelGitHubToken)),
		Proxy:          strings.TrimSpace(settingString(pg, settingVulnIntelProxy)),
		PocEnabled:     pg.GetBool(settingVulnIntelPocEnabled, false),
		BackfillDays:   intSetting(pg, settingVulnIntelBackfillDays, 0),
		MaxRuntimeMin:  intSetting(pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin),
		MaintenanceURL: s.m.maintenanceProxy(),
	}
}

// vulnintelStatus 读状态。除原样返回 store 的 sources/counts 外,额外补:
// 脱敏配置、每源错误的人话建议、正在运行状态、nuclei 模板树现状。
func (s *Server) vulnintelStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	m := s.m
	if m == nil || m.vulnintel == nil {
		writeErr(w, 503, "漏洞情报库未初始化")
		return
	}
	st := m.vulnintel.StatusSnapshot(r.Context())
	st["enabled"] = pg.GetBool(settingVulnIntelOn, true)
	st["nuclei_templates_dir"] = m.nucleiDir

	// 每源补错误诊断,原样保留 last_error 全文(前端可展开)。
	if raw, ok := st["sources"].([]vulnintel.SyncState); ok {
		rows := make([]map[string]any, 0, len(raw))
		for _, src := range raw {
			rows = append(rows, map[string]any{
				"source":       src.Source,
				"last_sync_at": src.LastSyncAt,
				"cursor":       src.Cursor,
				"total_synced": src.TotalSynced,
				"last_error":   src.LastError,
				"enabled":      src.Enabled,
				"error_hint":   vulnIntelErrorHint(src.LastError),
				"ok":           src.LastError == "" && src.LastSyncAt != nil,
			})
		}
		st["sources"] = rows
	}

	cfg := s.vulnintelConfigForWrite()
	// 读取路径只回掩码，明文永远不进响应体。
	cfg.NvdAPIKey = maskSecret(cfg.NvdAPIKey)
	cfg.GitHubToken = maskSecret(cfg.GitHubToken)
	cfg.NvdKeySet = settingString(pg, settingNvdApiKey) != ""
	cfg.GitHubSet = settingString(pg, settingVulnIntelGitHubToken) != ""
	st["config"] = cfg
	running, startedAt := m.VulnIntelSyncState()
	st["sync_running"] = running
	st["sync_started_at"] = startedAt
	st["sync_phase"] = m.SyncPhase()
	st["next_tick_hint"] = "定时同步每 6 小时一轮（启动后约 90 秒跑第一轮）"
	st["nuclei"] = nucleiTemplatesStatus(m.nucleiDir)
	writeJSON(w, 200, st)
}

// maskSecret 遮掉凭据：空串原样返回（UI 显示"未配置"），有值只留长度与尾段。
func maskSecret(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return "****"
	}
	return "••••••••" + v[len(v)-4:]
}

// nucleiTemplateStats reports the local template tree at a glance: 是否已克隆、
// yaml 模板数、最近一次 git 更新时间。用户判断"模板不可用"到底是没拉下来还是
// 拉下来了但过期。
type nucleiTemplatesDTO struct {
	Dir       string `json:"dir"`
	Exists    bool   `json:"exists"`
	IsGit     bool   `json:"is_git"`
	Templates int    `json:"templates"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Hint      string `json:"hint"`
}

func nucleiTemplatesStatus(dir string) nucleiTemplatesDTO {
	out := nucleiTemplatesDTO{Dir: dir}
	if dir == "" {
		out.Hint = "模板目录未配置"
		return out
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		out.Hint = "模板树尚未克隆：点上方「立即同步」拉取（失败时看同步日志里的代理问题）"
		return out
	}
	out.Exists = true
	_, err = os.Stat(filepath.Join(dir, ".git"))
	out.IsGit = err == nil
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
			out.Templates++
		}
		return nil
	})
	if out.IsGit {
		if fi, err := os.Stat(filepath.Join(dir, ".git", "FETCH_HEAD")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		} else if fi, err := os.Stat(filepath.Join(dir, ".git", "index")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		}
	}
	if out.Templates == 0 {
		out.Hint = "目录存在但没有 yaml 模板——克隆未完成或被中断，删除该目录后点「立即同步」重来"
	} else {
		out.Hint = fmt.Sprintf("已就绪：%d 个模板", out.Templates)
	}
	return out
}

// vulnintelSaveConfig 保存配置。key/token 传空串表示"保持不变"，传 "-" 清除。
func (s *Server) vulnintelSaveConfig(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Enabled       *bool   `json:"enabled"`
		NvdAPIKey     *string `json:"nvd_api_key"`
		GitHubToken   *string `json:"github_token"`
		Proxy         *string `json:"proxy"`
		PocEnabled    *bool   `json:"poc_enabled"`
		BackfillDays  *int    `json:"backfill_days"`
		MaxRuntimeMin *int    `json:"max_runtime_minutes"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Enabled != nil {
		if err := pg.SetBool(settingVulnIntelOn, *req.Enabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// 凭据：省略字段 = 不改；传 "-" = 清除；其它 = 覆盖。
	setSecret := func(key string, val *string) error {
		if val == nil {
			return nil
		}
		v := strings.TrimSpace(*val)
		if v == "-" {
			return pg.SetSetting(key, "")
		}
		if v == "" {
			return nil // 留空 = 保持当前值,避免前端清空输入框就丢凭据
		}
		return pg.SetSetting(key, v)
	}
	if err := setSecret(settingNvdApiKey, req.NvdAPIKey); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := setSecret(settingVulnIntelGitHubToken, req.GitHubToken); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.Proxy != nil {
		p := strings.TrimSpace(*req.Proxy)
		if p != "" {
			if _, err := traffic.ValidateProxyURL(p); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
		}
		if err := pg.SetSetting(settingVulnIntelProxy, p); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.PocEnabled != nil {
		if err := pg.SetBool(settingVulnIntelPocEnabled, *req.PocEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.BackfillDays != nil {
		d := *req.BackfillDays
		if d < 0 {
			d = 0
		}
		if err := pg.SetSetting(settingVulnIntelBackfillDays, fmt.Sprintf("%d", d)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.MaxRuntimeMin != nil {
		mn := *req.MaxRuntimeMin
		if mn < 5 {
			mn = 5
		}
		if err := pg.SetSetting(settingVulnIntelMaxRuntimeMin, fmt.Sprintf("%d", mn)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// vulnintelSyncNow 手动触发一轮同步（含资产联动与模板树）。
func (s *Server) vulnintelSyncNow(w http.ResponseWriter, r *http.Request) {
	if pg := s.pg(w); pg == nil {
		return
	}
	if !s.m.SyncVulnIntelNow() {
		writeErr(w, 409, "已有一轮同步在进行中（可点「中断」后再发起）")
		return
	}
	writeJSON(w, 200, map[string]any{"accepted": true})
}

// vulnintelSyncCancel 中断当前同步轮（v0.3.96：此前一轮最长 45 分钟且无法中断，
// 卡住时用户只能干等）。协作式取消：ctx 贯穿 NVD/GHSA 请求与 nuclei git 子进程。
func (s *Server) vulnintelSyncCancel(w http.ResponseWriter, r *http.Request) {
	if pg := s.pg(w); pg == nil {
		return
	}
	if !s.m.CancelVulnIntelSync() {
		writeErr(w, 409, "当前没有在跑的同步轮")
		return
	}
	writeJSON(w, 200, map[string]any{"cancelling": true})
}

// --- 连通性诊断 ---

type probeResult struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
	ProxyUsed string `json:"proxy_used,omitempty"`
}

// vulnintelProbe 逐源真实探测一次，回答"到底是源挂了、代理挂了、还是网络不通"。
// 每项 10s 超时，整体不受慢源拖死。
func (s *Server) vulnintelProbe(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Proxy *string `json:"proxy"`
	}
	_ = decode(r, &req)
	proxy := s.m.vulnIntelProxy()
	if req.Proxy != nil && strings.TrimSpace(*req.Proxy) != "" {
		proxy = strings.TrimSpace(*req.Proxy)
	}
	client, err := vulnintel.NewNvdClient("", proxy)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 心跳比整份 feed 快得多；能连通即可，不需要整份下载。
	checks := []struct{ source, target string }{
		{"nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"},
		{"kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
		{"github", "https://api.github.com/rate_limit"},
		// GHSA 的真实端点：advisories API 匿名可读。探它而不是探
		// api.github.com 根路径——根路径能通不代表 advisory 能取到。
		{"ghsa", "https://api.github.com/advisories?per_page=1"},
	}
	results := make([]probeResult, 0, len(checks)+1)
	for _, c := range checks {
		results = append(results, probeURL(r.Context(), client.HTTP, c.source, c.target, proxy))
	}
	// 模板树：直接在本地测一次 fetch，比单纯 ls-remote 更接近真实更新路径。
	tplTarget := "https://github.com/projectdiscovery/nuclei-templates.git/info/refs?service=git-upload-pack"
	results = append(results, probeURL(r.Context(), client.HTTP, "nuclei_templates", tplTarget, proxy))

	writeJSON(w, 200, map[string]any{
		"proxy":     proxy,
		"effective": proxy == "",
		"results":   results,
	})
}

func probeURL(ctx context.Context, hc *http.Client, source, target, proxy string) probeResult {
	res := probeResult{Source: source, Target: target, ProxyUsed: proxy}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.Status = resp.StatusCode
	res.OK = resp.StatusCode == http.StatusOK
	if !res.OK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	res.Hint = vulnIntelErrorHint(res.Error)
	return res
}

// vulnIntelErrorHint 把底层错误翻成「能照着修」的中文建议。
// 这是同步失败在页面上唯一的解释入口，宁可啰嗦也要给出下一步动作。
func vulnIntelErrorHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case err == "":
		return ""
	case strings.Contains(e, "proxyconnect") || strings.Contains(e, "socks") ||
		strings.Contains(e, "proxy is unreachable"):
		return "代理连不上：检查代理地址/端口是否可用，或清空「同步代理」改走系统配置里的装机代理。"
	case strings.Contains(e, "no such host") || strings.Contains(e, "dial tcp: lookup"):
		return "DNS 解析失败：直连解析不了该域名（常见于 cisa.gov / github.com）。填写一个能出网的代理即可。"
	case strings.Contains(e, "context deadline") || strings.Contains(e, "client.timeout"):
		return "请求超时：网络慢或代理节点不可用。换一个代理，或增大「单轮上限」让重试有更多时间。"
	case strings.Contains(e, "status 401"):
		return "401 未授权：API Key / Token 无效或过期，重新填一个。"
	case strings.Contains(e, "status 403"):
		return "403 被拒：多为触发了数据源限速（NVD 匿名仅 5 次/30 秒）。填 NVD API Key 或换代理。"
	case strings.Contains(e, "status 404"):
		return "404：数据源路径变了，或代理返回了拦截页。点上方「测试连通性」看是哪一环。"
	case strings.Contains(e, "429") || strings.Contains(e, "rate limit"):
		return "被限速：稍后自动重试（游标会续跑），或配置 NVD API Key / GitHub Token 提升配额。"
	case strings.Contains(e, "x509") || strings.Contains(e, "tls"):
		return "TLS 证书校验失败：多半是代理做了 MITM。用带 CA 的记录代理，或换普通 http 代理。"
	case strings.Contains(e, "i/o timeout"):
		return "连接超时：换代理或稍后重试。"
	default:
		return "看完整错误；先点「测试连通性」区分是网络/代理问题还是数据源问题。"
	}
}

// egressHint / egressPortMap 读回连配置(settings;读失败按空串处理)。
func egressHint(pg *pgdb.DB) string {
	v, _, _ := pg.GetSetting("egress_hint")
	return strings.TrimSpace(v)
}

func egressPortMap(pg *pgdb.DB) string {
	v, _, _ := pg.GetSetting("egress_port_map")
	return strings.TrimSpace(v)
}
