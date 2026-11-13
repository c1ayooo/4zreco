package agent

// 扫描器领域工具（AGENTS.md §5.5 P2）：gogo_scan / spray_finger。
//
// 进程内接 chainreactors 官方 Go SDK（gogo v2 / spray，pseudo-version 锁死在 go.mod），
// 不拉外部进程。两个工具都是【只读发现类】：只做端口/服务发现与 Web 指纹识别，
// gogo 走默认 Exploit="none"（pkg/config.go DefaultRunnerOption），不启用漏洞利用。
// 用 readTool 包装（ReadOnly+Concurrent），避免 writeTool 丢标记被调度串行化。
//
// 出口代理：预留注入点（SetScannerEgressProxy），当前 server 侧未接线——
// 扫描流量默认直连（与手写 curl 无代理时行为一致）。是否让扫描流量过录制代理
// 属部署选择，且接线非纯地址传递：录制代理是 MITM（HTTP(S) 客户端需信任 traffic
// CA 才能过），gogo 原始 TCP 探测经 HTTP CONNECT 会失真，接线时需一并处理这两点。
// Context 级 WithProxy 优先于引擎级配置，因此运行中改代理对下一次调用即生效。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdkgogo "github.com/chainreactors/sdk/gogo"
	sdkprovider "github.com/chainreactors/sdk/pkg/provider"
	sdkspray "github.com/chainreactors/sdk/spray"
	"github.com/chainreactors/utils/parsers"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// ---------- 出口代理注入点 ----------

// scannerEgressProxy 是扫描工具的可选出口代理（http/https/socks5 URL 形式）。
// 空 = 直连。预留注入点：当前没有调用方，默认直连；要接录制代理须先解决
// MITM CA 信任与 gogo 原始探测经代理失真两个问题（见文件头注释）。
var scannerEgressProxy atomic.Value

// SetScannerEgressProxy wires the egress proxy URL used by scanner tools;
// empty restores direct dialing. Atomic, effective on the next tool call.
// Reserved injection point: no server-side caller yet, tools dial directly
// until something wires it (see the file-header note for what wiring entails).
func SetScannerEgressProxy(proxyURL string) { scannerEgressProxy.Store(strings.TrimSpace(proxyURL)) }

func scannerEgressProxyURL() string {
	v, _ := scannerEgressProxy.Load().(string)
	return v
}

// ---------- 引擎单例（懒初始化） ----------

// 两个引擎初始化都要加载内嵌指纹库（embed provider），开销不小且天然进程级共享，
// 因此懒初始化为单例；init 失败会缓存错误，同一进程内不反复重试。
var (
	scannerMu    sync.Mutex
	gogoEngine   *sdkgogo.Engine
	gogoInitErr  error
	sprayEngine  *sdkspray.Engine
	sprayInitErr error
)

func gogoScanEngine() (*sdkgogo.Engine, error) {
	scannerMu.Lock()
	defer scannerMu.Unlock()
	if gogoEngine != nil || gogoInitErr != nil {
		return gogoEngine, gogoInitErr
	}
	gogoEngine, gogoInitErr = sdkgogo.NewEngine(
		sdkgogo.NewConfig().WithProvider(sdkprovider.NewEmbedProvider()))
	return gogoEngine, gogoInitErr
}

func sprayFingerEngine() (*sdkspray.Engine, error) {
	scannerMu.Lock()
	defer scannerMu.Unlock()
	if sprayEngine != nil || sprayInitErr != nil {
		return sprayEngine, sprayInitErr
	}
	sprayEngine, sprayInitErr = sdkspray.NewEngine(
		sdkspray.NewConfig().WithProvider(sdkprovider.NewEmbedProvider()))
	return sprayEngine, sprayInitErr
}

// ---------- 参数归一 ----------

// scannerTimeout 从入参取超时秒数：默认 300s，上限 900s，正整数以外一律取默认。
func scannerTimeout(sec int) time.Duration {
	if sec <= 0 || sec > 900 {
		return 300 * time.Second
	}
	return time.Duration(sec) * time.Second
}

// normalizeScanTarget 把 IP / CIDR / URL 三种入参归一成 gogo 的扫描目标：
//   - URL → 取 hostname（带端口则剥掉端口）
//   - 域名 → DNS 解析取第一个 IPv4（无 IPv4 取第一个地址）
//
// gogo 的 -i 只吃 IP/CIDR，不吃域名——域名必须先落成 IP，避免引擎侧行为不可预期。
func normalizeScanTarget(ctx context.Context, target string) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", fmt.Errorf("target 不能为空")
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", fmt.Errorf("URL 解析失败: %v", err)
		}
		t = u.Hostname()
		if t == "" {
			return "", fmt.Errorf("URL 里取不到主机名: %s", target)
		}
	}
	// 允许 "1.2.3.4:8080" / "host:port" 这类笔误，剥掉端口。
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String(), nil
	}
	if _, _, err := net.ParseCIDR(t); err == nil {
		return t, nil // CIDR 原样交给 gogo
	}
	// 域名：在调用 ctx 上解析（超时由 ctx 控制），优先 IPv4。
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(rctx, t)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("域名 %s 解析失败（%v）——请直接给 IP 或 CIDR", t, err)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a, nil
		}
	}
	return addrs[0], nil
}

// validateScanPorts 校验 ports 参数：允许 top1/top2/top3/all 预设或显式端口
// （数字/范围/逗号组合）。空 → 默认 top2。非法字符直接拒绝，避免把自由文本
// 塞给引擎造成不可预期的行为。
func validateScanPorts(ports string) (string, error) {
	p := strings.TrimSpace(ports)
	if p == "" {
		return "top2", nil
	}
	switch strings.ToLower(p) {
	case "top1", "top2", "top3", "all":
		return strings.ToLower(p), nil
	}
	for _, part := range strings.Split(p, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", fmt.Errorf("ports 含空段: %q", ports)
		}
		lo, hi, found := strings.Cut(part, "-")
		lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
		if !isDigits(lo) || (found && !isDigits(hi)) {
			return "", fmt.Errorf("ports 段 %q 不是端口数字/范围（预设只有 top1/top2/top3/all，显式端口如 80,443 或 1-1000）", part)
		}
		if n := len(lo); n == 0 || n > 5 {
			return "", fmt.Errorf("ports 段 %q 端口号非法", part)
		}
	}
	return p, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ---------- 指纹紧凑摘要 ----------

// frameworkSummary 把 parsers.Frameworks（name→*Framework）压成定长小条目，
// 按 name 排序保证输出确定性（map 序随机，不排会让同一次扫描两次结果长得不一样）。
func frameworkSummary(fs parsers.Frameworks) []map[string]any {
	out := make([]map[string]any, 0, len(fs))
	for name, f := range fs {
		if f == nil {
			continue
		}
		m := map[string]any{"name": name}
		if f.Attributes != nil && f.Attributes.Version != "" {
			m["version"] = f.Attributes.Version
		}
		if f.IsFocus {
			m["focus"] = true
		}
		if len(f.Tags) > 0 {
			m["tags"] = f.Tags
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := out[i]["name"].(string)
		b, _ := out[j]["name"].(string)
		return a < b
	})
	return out
}

// maxScannerResults 是单次扫描回显的条目上限：/24 + all 这类大扫描可能产出
// 上千条，全部回显会把对话灌爆。超限截断并带 truncated 标记，模型可收窄范围重扫。
const maxScannerResults = 200

// ---------- 工具 ----------

// gogoScan 端口/服务/指纹扫描（只读发现，进程内 SDK 直跑）。
func (t *ToolSet) gogoScan() actool.CoreTool {
	return readTool(
		"gogo_scan",
		"对 IP/CIDR/URL 做【端口与服务发现 + 服务指纹识别】（只读，gogo 内核进程内执行，不需要 Bash）。"+
			"返回紧凑 JSON 摘要：每条 = ip/port/protocol/status/title/中间件/指纹（含版本）+ http 服务的 url。"+
			"参数：target 必填（IP、CIDR 如 10.0.0.0/24、或 URL——URL 会取主机名并解析成 IP）；"+
			"ports 可选（预设 top1/top2/top3/all 或显式 80,443 / 1-1000，默认 top2 快扫常见端口）；"+
			"timeout_sec 可选（默认 300，上限 900）。"+
			"本工具只做发现、不启用漏洞利用——拿到服务与指纹后：新资产用 insert_assets 登记，"+
			"组件有版本就配 search_vulns 查已知漏洞，验证用 scan_with_nuclei 或手工构造。"+
			"CIDR 大范围扫 all 会很慢，先用 top2 摸面再对单机收窄。",
		obj(map[string]any{
			"target":      str("扫描目标：IP、CIDR（10.0.0.0/24）或 URL（https://example.com）"),
			"ports":       str("端口(可选)：top1/top2/top3/all 预设，或显式 80,443、1-1000；默认 top2"),
			"timeout_sec": intp("总超时秒数(可选，默认 300，上限 900)"),
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			eng, err := gogoScanEngine()
			if err != nil {
				return actool.Errorf("gogo_scan 未启用: 扫描引擎初始化失败: " + err.Error()), nil
			}
			var a struct {
				Target     string `json:"target"`
				Ports      string `json:"ports"`
				TimeoutSec int    `json:"timeout_sec"`
			}
			_ = json.Unmarshal(in, &a)
			target, err := normalizeScanTarget(ctx, a.Target)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ports, err := validateScanPorts(a.Ports)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			sctx, cancel := context.WithTimeout(ctx, scannerTimeout(a.TimeoutSec))
			defer cancel()
			gctx := sdkgogo.NewContext().WithContext(sctx).WithThreads(256)
			if p := scannerEgressProxyURL(); p != "" {
				gctx = gctx.WithProxy(p)
			}
			results, err := eng.Scan(gctx, target, ports)
			if err != nil {
				return actool.Errorf("扫描失败: " + err.Error()), nil
			}
			services := make([]map[string]any, 0, len(results))
			for _, r := range results {
				if r == nil {
					continue
				}
				if len(services) >= maxScannerResults {
					break
				}
				m := map[string]any{
					"ip": r.Ip, "port": r.Port, "protocol": r.Protocol, "status": r.Status,
				}
				if r.Host != "" {
					m["host"] = r.Host
				}
				if r.Title != "" {
					m["title"] = r.Title
				}
				if r.Midware != "" {
					m["midware"] = r.Midware
				}
				if len(r.Frameworks) > 0 {
					m["frameworks"] = frameworkSummary(r.Frameworks)
				}
				if r.IsHttp() {
					m["url"] = r.GetBaseURL()
				}
				services = append(services, m)
			}
			res := map[string]any{
				"target":   target,
				"ports":    ports,
				"count":    len(services),
				"services": services,
			}
			if len(results) > maxScannerResults {
				res["truncated"] = true
				res["note"] = fmt.Sprintf("命中 %d 条、只回显前 %d 条——收窄 target/ports 后重扫拿全量", len(results), maxScannerResults)
			}
			if len(services) == 0 {
				res["note"] = "没有存活端口/服务（端口关闭或被防火墙过滤）。top2 没扫到不代表没有服务，可试显式端口或 all。"
			}
			return jsonResult(res)
		},
	)
}

// sprayFinger Web 指纹与路径探测（只读发现，进程内 SDK 直跑）。
func (t *ToolSet) sprayFinger() actool.CoreTool {
	return readTool(
		"spray_finger",
		"批量探测一批 http(s) URL 的【存活状态 + Web 指纹】（只读，spray 内核进程内执行，不需要 Bash）。"+
			"返回紧凑 JSON 摘要：每条 = url/status/valid/title/bytes/content_type/redirect/指纹（含版本与 tags）。"+
			"参数：urls 必填（1-40 个绝对地址，可混用 http/https）；finger 可选（默认 true 开启主动指纹"+
			"识别；false 只探活不打指纹，更快更隐蔽）；timeout_sec 可选（默认 300，上限 900）。"+
			"与 http_probe 的分工：http_probe 轻量概要（server 头级别），本工具带完整指纹库识别"+
			"（框架/CMS/中间件，含主动路径探测）。拿到指纹后配 search_vulns 查已知漏洞。"+
			"发现的组件用 insert_assets 登记，结论用 record_fact。",
		obj(map[string]any{
			"urls": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "要探测的 URL 列表（1-40 个，绝对地址）",
			},
			"finger":      map[string]any{"type": "boolean", "description": "是否开启主动指纹识别(默认 true；false 只探活)"},
			"timeout_sec": intp("总超时秒数(可选，默认 300，上限 900)"),
		}, "urls"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			eng, err := sprayFingerEngine()
			if err != nil {
				return actool.Errorf("spray_finger 未启用: 指纹引擎初始化失败: " + err.Error()), nil
			}
			var a struct {
				URLs       []string `json:"urls"`
				Finger     *bool    `json:"finger"`
				TimeoutSec int      `json:"timeout_sec"`
			}
			_ = json.Unmarshal(in, &a)
			urls := make([]string, 0, len(a.URLs))
			seen := map[string]bool{}
			for _, u := range a.URLs {
				u = strings.TrimSpace(u)
				if u == "" || seen[u] || (!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://")) {
					continue
				}
				seen[u] = true
				urls = append(urls, u)
				if len(urls) >= 40 {
					break
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("urls 至少要有一个合法的 http(s) 绝对地址"), nil
			}
			finger := true
			if a.Finger != nil {
				finger = *a.Finger
			}
			sctx, cancel := context.WithTimeout(ctx, scannerTimeout(a.TimeoutSec))
			defer cancel()
			pctx := sdkspray.NewContext().WithContext(sctx).WithFinger(finger).WithThreads(50)
			if p := scannerEgressProxyURL(); p != "" {
				pctx = pctx.WithProxy(p)
			}
			results, err := eng.Check(pctx, urls)
			if err != nil {
				return actool.Errorf("探测失败: " + err.Error()), nil
			}
			sites := make([]map[string]any, 0, len(results))
			for _, r := range results {
				if r == nil {
					continue
				}
				if len(sites) >= maxScannerResults {
					break
				}
				m := map[string]any{
					"url":    r.UrlString,
					"status": r.Status,
					"valid":  r.IsValid,
				}
				if r.Title != "" {
					m["title"] = r.Title
				}
				if r.BodyLength > 0 {
					m["bytes"] = r.BodyLength
				}
				if r.ContentType != "" {
					m["content_type"] = r.ContentType
				}
				if r.RedirectURL != "" {
					m["redirect"] = r.RedirectURL
				}
				if r.IsFuzzy {
					m["fuzzy"] = true
				}
				if len(r.Frameworks) > 0 {
					m["frameworks"] = frameworkSummary(r.Frameworks)
				}
				sites = append(sites, m)
			}
			res := map[string]any{
				"count":   len(sites),
				"finger":  finger,
				"results": sites,
			}
			if len(sites) == 0 {
				res["note"] = "没有可判读的响应（目标不可达或全部被拒）。用 http_probe 或手工 curl 复核连通性。"
			}
			return jsonResult(res)
		},
	)
}
