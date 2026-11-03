// 漏洞情报同步的运行时配置、手动触发与并发控制。
//
// 定时循环（runVulnIntelSync）与页面上的「立即同步」共用同一条 pass：同一时刻
// 只允许一轮，避免两个 goroutine 并发写 vuln_sync_state / 抢 NVD 限速。
package server

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/vulnintel"
)

// 漏洞情报的可配置项（settings）。
const (
	settingVulnIntelGitHubToken   = "vulnintel_github_token"
	settingVulnIntelPocEnabled    = "vulnintel_poc_enabled"
	settingVulnIntelBackfillDays  = "vulnintel_backfill_days"
	settingVulnIntelMaxRuntimeMin = "vulnintel_max_runtime_minutes"
	// 同步专用出网代理。空 = 走维护出网回退链（装机代理 → 全局 → 搜索代理）。
	settingVulnIntelProxy = "vulnintel_proxy"
)

const (
	defaultVulnIntelMaxRuntimeMin = 30
	defaultVulnIntelInterval      = 6 * time.Hour
)

// errVulnSyncRunning 表示已有一轮同步在跑；调用方按「已接受/稍后再试」处理。
var errVulnSyncRunning = errors.New("vulnintel sync already running")

// vulnIntelProxy resolves the egress proxy for intel sync. 专用代理优先，然后
// 复用维护链（装机代理 → 全局 → 搜索代理）——和拉更新/装工具走同一条出口。
func (m *Manager) vulnIntelProxy() string {
	if m == nil || m.pg == nil {
		return ""
	}
	if v, _, _ := m.pg.GetSetting(settingVulnIntelProxy); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return m.maintenanceProxy()
}

// vulnIntelConfig assembles the full sync config from settings. Every field is
// read fresh so a change in the UI applies on the next pass without a restart.
func (m *Manager) vulnIntelConfig() vulnintel.Config {
	cfg := vulnintel.Config{
		PocEnabled:   m.pg.GetBool(settingVulnIntelPocEnabled, false),
		BackfillDays: intSetting(m.pg, settingVulnIntelBackfillDays, 0),
	}
	cfg.ProxyURL = m.vulnIntelProxy()
	cfg.NvdAPIKey = strings.TrimSpace(settingString(m.pg, settingNvdApiKey))
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	cfg.GitHubToken = strings.TrimSpace(settingString(m.pg, settingVulnIntelGitHubToken))
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if mins := intSetting(m.pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin); mins > 0 {
		cfg.MaxRuntime = time.Duration(mins) * time.Minute
	}
	return cfg
}

// SyncVulnIntelNow starts one pass in the background (manual trigger). Returns
// false when a pass is already running. The enabled switch is intentionally
// ignored: clicking "sync now" means sync now.
func (m *Manager) SyncVulnIntelNow() bool {
	if m == nil || m.vulnintel == nil {
		return false
	}
	if !m.vulnSyncMu.TryLock() {
		return false
	}
	m.vulnSyncRunning.Store(true)
	m.vulnSyncStartedAt.Store(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	m.storeSyncCancel(cancel)
	go func() {
		defer m.vulnSyncMu.Unlock()
		defer m.vulnSyncRunning.Store(false)
		defer m.clearSyncCancel()
		if err := m.vulnIntelPassLocked(ctx); err != nil {
			log.Printf("[vulnintel] 手动同步未完整完成: %v", err)
		}
	}()
	return true
}

// storeSyncCancel / clearSyncCancel / CancelVulnIntelSync / SyncPhase：
// 「可中断的同步」三件套（v0.3.96）。此前一轮最长跑 45 分钟且零中断路径，
// 卡住时用户既停不了也开不了新一轮（TryLock 拒绝），只能干等——UI 上就是
// 「一直同步中」。
func (m *Manager) storeSyncCancel(cancel context.CancelFunc) {
	m.vulnSyncCancel.Store(cancel)
}

func (m *Manager) clearSyncCancel() {
	m.vulnSyncCancel.Store(context.CancelFunc(func() {}))
}

// CancelVulnIntelSync 中断当前那轮同步（若有）。返回 false = 当前没有在跑的轮。
// 取消是协作式的：ctx 到达 vulnintel.Run / EnsureTemplates 的 exec.CommandContext，
// 子进程（git/curl）被杀、本轮带着「已取消」错误退出，锁与状态由 defer 复位。
func (m *Manager) CancelVulnIntelSync() bool {
	if !m.vulnSyncRunning.Load() {
		return false
	}
	if cancel, ok := m.vulnSyncCancel.Load().(context.CancelFunc); ok {
		cancel()
		log.Printf("[vulnintel] 收到中断请求，当前同步轮将被取消")
		return true
	}
	return false
}

// SetVulnSyncPhase 更新当前轮的阶段描述（状态页展示）。f = "漏洞情报同步中（CVE/KEV/GHSA/PoC）" 等。
func (m *Manager) SetVulnSyncPhase(f string) {
	if m == nil {
		return
	}
	m.vulnSyncPhase.Store(f)
}

// SyncPhase 返回当前阶段描述（空串 = 未在跑或尚未设置）。
func (m *Manager) SyncPhase() string {
	if m == nil {
		return ""
	}
	if v, ok := m.vulnSyncPhase.Load().(string); ok {
		return v
	}
	return ""
}

// VulnIntelSyncState reports whether a pass is running and when it started
// (unix seconds, 0 = never). Used by the status API.
func (m *Manager) VulnIntelSyncState() (running bool, startedAt int64) {
	if m == nil {
		return false, 0
	}
	return m.vulnSyncRunning.Load(), m.vulnSyncStartedAt.Load()
}

// runVulnIntelPass is the scheduled-loop entry: it takes the same lock, so a
// manual trigger and the timer can never overlap.
func (m *Manager) runVulnIntelPass(ctx context.Context) error {
	if !m.vulnSyncMu.TryLock() {
		return errVulnSyncRunning
	}
	defer m.vulnSyncMu.Unlock()
	m.vulnSyncRunning.Store(true)
	m.vulnSyncStartedAt.Store(time.Now().Unix())
	runCtx, runCancel := context.WithCancel(ctx)
	m.storeSyncCancel(runCancel)
	defer m.vulnSyncRunning.Store(false)
	defer m.clearSyncCancel()
	return m.vulnIntelPassLocked(runCtx)
}

// ── 近期高危快通道 ──────────────────────────────────────────────────────
//
// 主同步走 lastModifiedDate 窗口（≤120 天），游标按窗口推进、一轮 MaxRuntime
// 翻不完——这个结构适合「补全历史目录」，但对「刚爆出来的漏洞」是错的：
// 一条昨天披露的 CRITICAL 要等主同步的游标爬到它那个窗口才进库。
//
// 快通道按 publishedDate 拉小窗口、只留 CVSS≥9.0 或 CISA KEV，把「刚披露
// 的高危」压缩到几十分钟进库。它与主同步**共用 vuln_cves 表**（agent 查同一
// 个库），但**游标独立**、**锁独立**（主同步一轮 30 分钟，快通道不该被它拖住，
// 反之亦然）。
//
// 2026-10-22 的实测是两个真实靶子：CVE-2026-109618 / CVE-2026-109619
// （昨天披露的 PHP CRITICAL RCE）——主同步还没爬到那个窗口，而它们的 NVD
// 版本区间是空的（「版本待定」由 vulnintel.VersionRangeUndetermined 标记）。

const (
	// settingVulnIntelFastLaneOn 是快通道的独立开关。
	settingVulnIntelFastLaneOn = "vulnintel_fast_lane_enabled"
	// settingVulnIntelFastLaneMinutes 是快通道的轮询间隔（分钟）。
	settingVulnIntelFastLaneMinutes = "vulnintel_fast_lane_interval_minutes"
	// settingVulnIntelFastLaneWindowDays 是快通道的回看窗口（天）。
	settingVulnIntelFastLaneWindowDays = "vulnintel_fast_lane_window_days"
	// settingVulnIntelGhsaCursor 是 GHSA 同步的游标（上次同步到的最新 updated 时间）。
	settingVulnIntelGhsaCursor = "vulnintel_ghsa_cursor"
)

// vulnintelSourceGhsa 是 GHSA 这个数据源在 vuln_sync_state 里的 source 名。
const vulnintelSourceGhsa = "ghsa"

const (
	// defaultVulnIntelGhsaMaxPages 是 GHSA 单轮最多拉几页。
	//
	// 3 页 × 100 条 = 300 条/轮，30 分钟一轮足够——GHSA 的价值是补版本区间，
	// 不是补全历史目录（历史由 NVD 主同步负责）。
	defaultVulnIntelGhsaMaxPages = 3
)

const (
	// defaultVulnIntelFastLaneInterval 是快通道默认轮询间隔。
	//
	// 30 分钟：实测 7 天窗口拉完只要 17 秒，间隔主要决定「多快能进库」。
	// 15 分钟意义不大（NVD 侧对新记录的索引延迟是小时级），1 小时又太慢
	// （「刚爆出来」的价值就在几小时内）。
	defaultVulnIntelFastLaneInterval = 30 * time.Minute
	// defaultVulnIntelFastLaneWindowDays 是快通道默认回看窗口。
	//
	// 下限由 vulnintel.fastLaneMinWindowDays 兜住（实测 1~3 天的窗口会超时）。
	defaultVulnIntelFastLaneWindowDays = 7
	// defaultVulnIntelFastLaneMaxRuntime 是快通道单轮墙钟上限。
	//
	// 比主同步短：快通道的价值在及时性，不该占满一整轮的预算。
	defaultVulnIntelFastLaneMaxRuntime = 5 * time.Minute
)

// fastLaneEnabled reports whether the recent-critical fast lane is on.
//
// 跟随总开关（vulnintel_enabled）：情报同步整体关了，快通道也没必要跑。
// 另有一个独立开关，用于「先关掉快通道观察主同步表现」的场景。
func (m *Manager) fastLaneEnabled() bool {
	if m == nil || m.pg == nil {
		return false
	}
	if !m.pg.GetBool(settingVulnIntelOn, true) {
		return false
	}
	return m.pg.GetBool(settingVulnIntelFastLaneOn, true)
}

// fastLaneConfig 组装快通道配置。
func (m *Manager) fastLaneConfig() vulnintel.FastLaneConfig {
	cfg := vulnintel.FastLaneConfig{
		ProxyURL:  m.vulnIntelProxy(),
		NvdAPIKey: strings.TrimSpace(settingString(m.pg, settingNvdApiKey)),
		WindowDays: intSetting(m.pg, settingVulnIntelFastLaneWindowDays,
			defaultVulnIntelFastLaneWindowDays),
		MaxRuntime: defaultVulnIntelFastLaneMaxRuntime,
	}
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	// 页间隔必须按 API key 推导，不能拍脑袋。
	//
	// NVD 匿名访问限速约 5 次/30s（约 6.5s/次），有 key 则是 50 次/30s
	// （0.7s/次）。原来快通道硬编码 1 秒 —— 无 key 时必然撞 429
	// （2026-10-22 首次实跑就撞了：nvd rate limited，一页都没拉下来）。
	//
	// 推导逻辑与主同步共用（vulnintel 包的 pageDelayFor），免得两处各写一份
	// 限速数字、以后改一处忘另一处。
	cfg.PageDelay = vulnintel.PageDelayFor(cfg.NvdAPIKey)
	return cfg
}

// runVulnIntelFastLane drives the recent-critical fast lane.
//
// 独立 goroutine、独立锁：主同步一轮最长 30 分钟，快通道必须能在那期间照常
// 把新披露的高危送进库。两者共用 vuln_cves 表，upsert 是幂等的，重叠拉到
// 同一条记录不会出问题。
func (m *Manager) runVulnIntelFastLane() {
	// 起跑延迟要**大幅错开**主同步的 90s。
	//
	// 原来只错开 30 秒 —— 主同步 90s 起跑、快通道 120s 起跑，两者都要打
	// NVD，而 NVD 匿名访问限速是 5 次/30s（**共享额度**）。实测首次实跑：
	// 快通道第 0 页就 "nvd rate limited"，一页都没拉下来。
	//
	// 错开到 7 分钟：主同步那一轮（最长 30 分钟）基本跑完或接近跑完时，
	// 快通道才开始，两边不抢额度。
	time.Sleep(7 * time.Minute)
	for {
		if m.fastLaneEnabled() {
			m.fastLaneOnce()
		}
		interval := defaultVulnIntelFastLaneInterval
		if m.pg != nil {
			if mins := intSetting(m.pg, settingVulnIntelFastLaneMinutes, 0); mins > 0 {
				interval = time.Duration(mins) * time.Minute
			}
		}
		time.Sleep(interval)
	}
}

// fastLaneOnce runs one fast-lane pass: pull → store → link assets.
//
// 与主同步一样，快通道拉完也要做资产联动——不然新漏洞进了库但任务那边
// 看不到 hint，「刚爆出来的」就只停在库里。
func (m *Manager) fastLaneOnce() {
	if m == nil || m.vulnintel == nil {
		return
	}
	// 独立锁：快通道之间自己也不该并发（会重复拉同一窗口）。
	if !m.vulnFastLaneMu.TryLock() {
		return
	}
	defer m.vulnFastLaneMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), defaultVulnIntelFastLaneMaxRuntime+time.Minute)
	defer cancel()

	res, err := vulnintel.RunFastLane(ctx, m.vulnintel, m.fastLaneConfig())
	if err != nil {
		log.Printf("[vulnintel] 快通道本轮失败: %v", err)
		return
	}
	if res.Stored > 0 {
		log.Printf("[vulnintel] 快通道: 扫 %d 条，入库 %d 条（其中版本待定 %d 条），游标 %s",
			res.Scanned, res.Stored, res.VersionUndetermined, res.Cursor)
		// 新漏洞进了库 → 立刻做资产联动，让受影响的任务看到。
		m.linkVulnIntelAssets()
	}
	if res.Truncated {
		log.Printf("[vulnintel] 快通道本轮未拉完（页数/时间上限），游标 %s 已保留", res.Cursor)
	}

	// GHSA 补充版本区间（第二数据源）。
	//
	// 为什么要接：NVD 对新披露的 CVE 常常不填版本区间（PHP 那两个 CVE 就是
	// `cpe:2.3:a:php:php:*:*`），我们只能标「版本待定」——那是止损不是解法。
	// GHSA 的版本区间是必填的，能补上这块。
	//
	// 放在快通道里而不是主同步里：GHSA 的价值就是「及时补上版本区间」，
	// 而快通道的定位正是「刚披露的漏洞优先」。
	m.syncGhsaVersions(ctx)
}

// syncGhsaVersions 跑一轮 GHSA 同步，补版本区间。
//
// 复用已有的 GitHub token（settingVulnIntelGitHubToken）——同一套凭据，
// 不新增配置项。token 为空也能用（GHSA 公开 advisory 匿名可读，限速较松）。
//
// 失败不影响主流程：GHSA 只是补充来源，挂了不该让 NVD 同步跟着挂。
func (m *Manager) syncGhsaVersions(ctx context.Context) {
	if m == nil || m.vulnintel == nil {
		return
	}
	token := strings.TrimSpace(settingString(m.pg, settingVulnIntelGitHubToken))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	client, err := vulnintel.NewGhsaClient(token, m.vulnIntelProxy())
	if err != nil {
		log.Printf("[vulnintel] GHSA 客户端初始化失败: %v", err)
		return
	}
	// 游标：上次同步时间。首轮用「7 天前」——GHSA 的 updated_at 排序配合
	// since 过滤就是增量；首轮不追历史（历史补全交给 NVD 主同步）。
	since := time.Now().Add(-7 * 24 * time.Hour)
	if v := strings.TrimSpace(settingString(m.pg, settingVulnIntelGhsaCursor)); v != "" {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			since = t
		}
	}
	res, err := m.vulnintel.SyncGhsa(ctx, client, since, defaultVulnIntelGhsaMaxPages)
	if err != nil {
		log.Printf("[vulnintel] GHSA 同步失败: %v", err)
		m.recordGhsaState(ctx, since, 0, err)
		return
	}
	if res.Upserted > 0 || res.Merged > 0 {
		log.Printf("[vulnintel] GHSA: 拉 %d 条，新增 %d 条，补版本区间 %d 条",
			res.Fetched, res.Upserted, res.Merged)
	}
	if len(res.Errors) > 0 {
		log.Printf("[vulnintel] GHSA 本轮 %d 条出错（首个: %s）", len(res.Errors), res.Errors[0])
	}
	// 记游标：取本轮最晚的 updated。
	latest := m.latestGhsaUpdated(ctx)
	if latest.After(since) {
		_ = m.pg.SetSetting(settingVulnIntelGhsaCursor, latest.UTC().Format(time.RFC3339))
		since = latest
	}
	m.recordGhsaState(ctx, since, int64(res.Upserted+res.Merged), nil)
}

// recordGhsaState 记 GHSA 这个源的同步状态（状态页按源展示）。
//
// 失败时把错误写进 last_error —— 状态页会据此给人话建议。
func (m *Manager) recordGhsaState(ctx context.Context, cursor time.Time, total int64, syncErr error) {
	if m == nil || m.pg == nil {
		return
	}
	st, err := m.vulnintel.GetSyncState(ctx, vulnintelSourceGhsa)
	if err != nil {
		return
	}
	st.Source = vulnintelSourceGhsa
	st.Enabled = true
	st.Cursor = cursor.UTC().Format(time.RFC3339)
	st.TotalSynced += total
	if syncErr != nil {
		st.LastError = syncErr.Error()
	} else {
		st.LastError = ""
	}
	_ = m.vulnintel.SaveSyncState(ctx, st)
}

// latestGhsaUpdated 查最近一次同步到的 GHSA 条目的 updated 时间。
func (m *Manager) latestGhsaUpdated(ctx context.Context) time.Time {
	if m == nil || m.pg == nil {
		return time.Time{}
	}
	var v string
	err := m.pg.QueryRowContext(ctx, `SELECT COALESCE(MAX(modified_at)::text,'') FROM vuln_cves WHERE source='ghsa'`).Scan(&v)
	if err != nil || v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// vulnIntelPassLocked is one full pass: CVE/KEV/PoC sync → asset linking →
// nuclei template tree. The caller holds vulnSyncMu.
func (m *Manager) vulnIntelPassLocked(ctx context.Context) error {
	cfg := m.vulnIntelConfig()
	m.SetVulnSyncPhase("漏洞情报同步中（CVE / KEV / GHSA / PoC）")
	err := vulnintel.Run(ctx, m.vulnintel, cfg)
	if ctx.Err() != nil {
		m.SetVulnSyncPhase("已中断")
		log.Printf("[vulnintel] 本轮同步被中断（进度保留，可重新发起）")
		return ctx.Err()
	}
	if err != nil {
		log.Printf("[vulnintel] 本轮同步未完整完成: %v（游标已保留，下轮续跑）", err)
	}
	// 资产联动：新同步的 CVE 反向匹配 service 资产指纹，受影响任务挂 hint。
	// 同步没完整完成也照跑——KEV stub 与已 upsert 的记录都已可查。
	m.SetVulnSyncPhase("资产指纹联动")
	m.linkVulnIntelAssets()
	m.SetVulnSyncPhase("nuclei 模板树更新")
	m.refreshNucleiTemplates(cfg.ProxyURL)
	m.SetVulnSyncPhase("")
	return nil
}

// refreshNucleiTemplates keeps the local template tree moving. It is deliberately
// called outside the "enabled" gate: scan_with_nuclei is an independent feature
// and the tree must not rot when intel sync is switched off. Caller owns
// vulnSyncMu.
func (m *Manager) refreshNucleiTemplates(proxyURL string) {
	// 15 分钟：nuclei-templates depth-1 约 100-200MB，经慢代理 5 分钟必然超时——
	// 超时杀掉的 clone 留下半成品目录，正是 Kali「0 个模板」事故的根因（v0.3.96）。
	tplCtx, tplCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer tplCancel()
	if err := vulnintel.EnsureTemplates(tplCtx, m.nucleiDir, proxyURL); err != nil {
		log.Printf("[vulnintel] nuclei 模板树更新失败: %v", err)
	}
}

// intSetting reads an integer setting with a default.
func intSetting(pg interface {
	GetSetting(string) (string, bool, error)
}, key string, def int) int {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func settingString(pg interface {
	GetSetting(string) (string, bool, error)
}, key string) string {
	v, _, _ := pg.GetSetting(key)
	return v
}
