package agent

// 侦察领域工具（AGENTS.md §5.5 P4）：katana_scan / passive_search / web_search。
//
// 三个工具都是【只读发现类】：Web 爬虫、网空测绘引擎（FOFA/Hunter）、通用联网搜索。
// 用 readTool 包装（ReadOnly+Concurrent），避免 writeTool 丢标记被调度串行化。
// 角色分配对齐 search_vulns/scan_with_nuclei：三个执行角色（planner/worker/mainagent）同款。
//
// 凭据纪律（AGENTS.md §4 / §1.5）：FOFA/Hunter/搜索服务凭据只落运行时配置——
// gitignored 的 config.json（internal/config PassiveSearch/WebSearch 段）或 ZRECO_*
// 环境变量；不硬编码、不写进任何入库文件，也不进 trace 明文回显。
//
// 出口代理：与 tools_scanners.go 同一语义——SetScannerEgressProxy 是预留注入点，
// 当前未接线（无调用方），katana 爬虫、uncover 查询与搜索服务调用默认直连；
// 未来接线时同一段代理同时作用于三者。
//
// 新文件独立于 tools_scanners.go 的理由：该文件是 gogo/spray 进程内扫描引擎的单例
// 管理 + 目标归一逻辑，与「SDK 单例 + 指纹摘要」强耦合；本文件三个工具没有共享状态
// （katana 每次调用即建即毁、passive/web_search 是无状态 HTTP 查询），混进去只会让
// 两个主题互相稀释——按现有 tools_vulnintel.go / tools_zombie_proton.go 的按域分文件
// 惯例单独成篇。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/navigation"
	koutput "github.com/projectdiscovery/katana/pkg/output"
	ktypes "github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/uncover/sources"

	ufofa "github.com/projectdiscovery/uncover/sources/agent/fofa"
	uhunter "github.com/projectdiscovery/uncover/sources/agent/hunter"

	"github.com/c1ayooo/4zreco/internal/config"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// ---------- katana_scan ----------

// katanaCollector 是 katana 的紧凑结果收集器：实现 output.Writer 接口，
// 只留端点级摘要、超过 max 即取消 crawl（端点数量到了就不值得继续烧预算）。
type katanaCollector struct {
	mu     sync.Mutex
	count  int64 // 引擎实际产出的事件总数（含被截断丢弃的）
	out    []map[string]any
	max    int
	cancel context.CancelFunc
}

func (c *katanaCollector) Close() error { return nil }

func (c *katanaCollector) Write(r *koutput.Result) error {
	if r == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if len(c.out) >= c.max {
		if c.cancel != nil {
			c.cancel() // 幂等：后续事件不再追加，提前收尾
		}
		return nil
	}
	m := map[string]any{}
	if r.Request != nil {
		m["url"] = r.Request.URL
		if r.Request.Method != "" && r.Request.Method != http.MethodGet {
			m["method"] = r.Request.Method
		}
		if src := katanaSource(r.Request); src != "" {
			m["source"] = src
		}
	}
	if r.Response != nil {
		if r.Response.StatusCode != 0 {
			m["status"] = r.Response.StatusCode
		}
		// 表单是「参数」最密集的载体：action + 字段名列表。
		for _, f := range r.Response.Forms {
			fp := map[string]any{"action": f.Action}
			if f.Method != "" {
				fp["method"] = f.Method
			}
			if len(f.Parameters) > 0 {
				fp["parameters"] = f.Parameters
			}
			m["form"] = fp
			break // 一个响应只取第一个表单，保持紧凑
		}
	}
	// URL 查询参数：端点+参数摘要的核心（去重、按名排序保证确定性）。
	if raw, ok := m["url"].(string); ok {
		if params := queryParams(raw); len(params) > 0 {
			m["params"] = params
		}
	}
	if len(m) > 0 {
		c.out = append(c.out, m)
	}
	return nil
}

func (c *katanaCollector) WriteErr(*koutput.Error) error { return nil }

func (c *katanaCollector) GetResultCount() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// katanaSource 把请求来源压成短串（如 a[href]、form[action]、js）。
func katanaSource(r *navigation.Request) string {
	parts := make([]string, 0, 3)
	for _, v := range []string{r.Tag, r.Attribute, r.Source} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ".")
}

// queryParams 解析 URL 的查询串成有序的 name=value 短列表（紧凑、确定性排序）。
func queryParams(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, k := range names {
		vs := q[k]
		if len(vs) > 0 && vs[0] != "" {
			out = append(out, k+"="+vs[0])
		} else {
			out = append(out, k)
		}
	}
	return out
}

// katanaScan Web 端点爬虫（只读发现，katana standard 引擎进程内直跑，无 headless）。
func (t *ToolSet) katanaScan() actool.CoreTool {
	return readTool(
		"katana_scan",
		"对单个 http(s) URL 做【Web 爬虫端点发现】（只读，katana standard 引擎进程内执行，"+
			"不需要 Bash，也不启动浏览器）。返回紧凑 JSON 摘要：每条端点 = url/method/status/"+
			"params(查询参数)/form(表单 action+字段)/source(发现来源如 a[href]、js)。"+
			"参数：url 必填（绝对地址）；depth 可选（爬取深度，默认 3，上限 10）；"+
			"max_results 可选（回显端点上限，默认 100，达到即提前停止爬取）；"+
			"timeout_sec 可选（总超时秒数，默认 300，上限 900）。"+
			"发现的新端点/参数用 insert_assets 登记进资产图，可疑入口接续 "+
			"spray_finger（指纹）/ scan_with_nuclei（漏洞验证）。动态渲染页面（SPA）"+
			"本引擎爬不全——需要浏览器渲染的入口考虑手工 curl/JS 分析。",
		obj(map[string]any{
			"url":         str("爬取起点：http(s) 绝对地址"),
			"depth":       intp("爬取深度(可选，默认 3，上限 10)"),
			"max_results": intp("端点回显上限(可选，默认 100，达到即停)"),
			"timeout_sec": intp("总超时秒数(可选，默认 300，上限 900)"),
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL        string `json:"url"`
				Depth      int    `json:"depth"`
				MaxResults int    `json:"max_results"`
				TimeoutSec int    `json:"timeout_sec"`
			}
			_ = json.Unmarshal(in, &a)
			raw := strings.TrimSpace(a.URL)
			if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
				return actool.Errorf("url 必须是 http(s) 绝对地址"), nil
			}
			depth := clampInt(a.Depth, 1, 10, 3)
			maxResults := clampInt(a.MaxResults, 1, maxScannerResults, 100)
			wall := scannerTimeout(a.TimeoutSec)

			// crawl ctx：工具 ctx + 墙钟预算 + 达到 max_results 提前取消。
			cctx, cancel := context.WithTimeout(ctx, wall)
			defer cancel()
			collector := &katanaCollector{max: maxResults, cancel: cancel}

			// 以 katana 自身 DefaultOptions 为基线（含 Strategy/BodyReadSize 等
			// 引擎必需项——零值 Strategy 会让队列直接报 unsupported strategy），
			// 只覆盖模型可控项与运行环境项。
			opts := ktypes.DefaultOptions
			opts.MaxDepth = depth
			// JS 里常埋着真实端点与参数——打开相对端点抓取（standard 引擎支持，无需浏览器）。
			opts.ScrapeJSResponses = true
			opts.NoColors = true
			opts.Silent = true // 压掉 gologger 的 banner/info 输出，别污染进程 stderr
			opts.Proxy = scannerEgressProxyURL()
			opts.Context = cctx
			co, err := ktypes.NewCrawlerOptions(&opts)
			if err != nil {
				return actool.Errorf("katana 配置失败: " + err.Error()), nil
			}
			// NewCrawlerOptions 装的是文件/stdout writer；换成收集器拿结构化结果。
			co.OutputWriter = collector
			crawler, err := standard.New(co)
			if err != nil {
				return actool.Errorf("katana 引擎初始化失败: " + err.Error()), nil
			}
			defer crawler.Close()
			if err := crawler.Crawl(raw); err != nil && len(collector.out) == 0 {
				// 有端点产出时取消类错误不算失败（max_results 触发的提前停止）。
				return actool.Errorf("爬取失败: " + err.Error()), nil
			}
			res := map[string]any{
				"url":       raw,
				"depth":     depth,
				"count":     len(collector.out),
				"endpoints": collector.out,
			}
			if total := collector.GetResultCount(); total > int64(maxResults) {
				res["truncated"] = true
				res["note"] = fmt.Sprintf("共 %d 条端点事件、只回显前 %d 条——提高 max_results 或收窄 depth 拿更多", total, maxResults)
			}
			if len(collector.out) == 0 {
				res["note"] = "没有发现端点（目标不可达、无链接或全被过滤）。先用 http_probe/gogo_scan 确认目标存活。"
			}
			return jsonResult(res)
		},
	)
}

// clampInt 返回 v 夹逼在 [lo,hi] 的值；v<=0 时取 def（"未传/传 0 即默认"）。
func clampInt(v, lo, hi, def int) int {
	if v <= 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------- passive_search ----------

// passiveSearch 是 uncover 的一次查询结果（紧凑、去凭据）。
type passiveSearch struct {
	Engine string `json:"engine"`
	Host   string `json:"host,omitempty"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	URL    string `json:"url,omitempty"`
}

// passiveSearchTool FOFA/Hunter 网空测绘查询（只读，uncover SDK 直连两家 REST API）。
func (t *ToolSet) passiveSearchTool() actool.CoreTool {
	return readTool(
		"passive_search",
		"用【网空测绘引擎】（FOFA / Hunter 奇安信）按语法查互联网资产（只读外部情报查询，"+
			"不触碰目标本身）。返回紧凑 JSON：每条 = engine/host/ip/port/url。"+
			"参数：query 必填（测绘语法）；engine 可选（fofa/hunter/all，默认 all——"+
			"两家语法不同：FOFA 用 app=\"nginx\"、ip=\"1.2.3.0/24\" 这类；Hunter 用 "+
			"web.title=\"x\"、ip=\"1.2.3.4\" 这类，同一串未必两边都命中，定向查询单传 engine）；"+
			"limit 可选（每家引擎结果上限，默认 100，上限 300）。"+
			"凭据从运行时配置读取（config.json 的 passive_search 段或 ZRECO_FOFA_EMAIL/"+
			"ZRECO_FOFA_KEY/ZRECO_HUNTER_KEY 环境变量）；未配置对应引擎会明确报错而非失败重试。"+
			"查到的主机/端口是【情报侧历史数据】，与本任务实测结果可能有出入——"+"核对后用 "+
			"insert_assets 入资产图，归属明确的事实用 record_fact。",
		obj(map[string]any{
			"query":  str("测绘查询语法串（FOFA/Hunter 各自语法，见 engine 说明）"),
			"engine": str("引擎(可选)：fofa / hunter / all，默认 all"),
			"limit":  intp("每家引擎结果上限(可选，默认 100，上限 300)"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query  string `json:"query"`
				Engine string `json:"engine"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Query)
			if q == "" {
				return actool.Errorf("query 不能为空"), nil
			}
			limit := clampInt(a.Limit, 1, 300, 100)
			creds := config.LoadPassiveSearch()
			engine := strings.ToLower(strings.TrimSpace(a.Engine))
			if engine == "" {
				engine = "all"
			}
			if engine != "fofa" && engine != "hunter" && engine != "all" {
				return actool.Errorf("engine 只支持 fofa / hunter / all"), nil
			}

			// 引擎装配：只装「已配置凭据」的引擎；全没配 → 明确中文提示，不崩溃。
			type runner struct {
				name    string
				agent   sources.Agent
				engines []string
			}
			var runners []runner
			if engine == "fofa" || engine == "all" {
				if creds.FofaKey == "" || creds.FofaEmail == "" {
					if engine == "fofa" {
						return actool.Errorf(passiveUnconfigured("fofa")), nil
					}
				} else {
					runners = append(runners, runner{name: "fofa", agent: &ufofa.Agent{}, engines: []string{"fofa"}})
				}
			}
			if engine == "hunter" || engine == "all" {
				if creds.HunterKey == "" {
					if engine == "hunter" {
						return actool.Errorf(passiveUnconfigured("hunter")), nil
					}
				} else {
					runners = append(runners, runner{name: "hunter", agent: &uhunter.Agent{}, engines: []string{"hunter"}})
				}
			}
			if len(runners) == 0 {
				return actool.Errorf(passiveUnconfigured("fofa/hunter")), nil
			}

			keys := &sources.Keys{
				FofaEmail:   creds.FofaEmail,
				FofaKey:     creds.FofaKey,
				HunterToken: creds.HunterKey,
			}
			results := make([]passiveSearch, 0, limit*len(runners))
			errs := make([]string, 0, len(runners))
			for _, r := range runners {
				// 每个引擎一个 session（ratelimit 按引擎装）；超时沿用工具 ctx。
				session, err := sources.NewSession(keys, 2, 30, 0, r.engines, time.Second, scannerEgressProxyURL())
				if err != nil {
					errs = append(errs, r.name+": "+err.Error())
					continue
				}
				ch, err := r.agent.Query(ctx, session, &sources.Query{Query: q, Limit: limit})
				if err != nil {
					errs = append(errs, r.name+": "+err.Error())
					continue
				}
				n := 0
				for res := range ch {
					if res.Error != nil {
						errs = append(errs, r.name+": "+res.Error.Error())
						continue
					}
					if n >= limit || len(results) >= maxPassiveResults {
						break
					}
					n++
					results = append(results, passiveSearch{
						Engine: res.Source,
						Host:   res.Host,
						IP:     res.IP,
						Port:   res.Port,
						URL:    res.Url,
					})
				}
			}
			res := map[string]any{
				"query":   q,
				"engines": engine,
				"count":   len(results),
				"results": results,
			}
			if len(errs) > 0 {
				res["errors"] = errs
			}
			if len(results) == 0 && len(errs) > 0 {
				return actool.Errorf("passive_search 全部引擎查询失败: " + strings.Join(errs, "; ")), nil
			}
			if len(results) == 0 {
				res["note"] = "两家引擎都没有返回结果（语法不匹配、凭据权限不足或确实无资产）。检查 errors 字段与查询语法。"
			}
			return jsonResult(res)
		},
	)
}

// maxPassiveResults 是单次 passive_search 的总回显上限（两家引擎合计）。
const maxPassiveResults = 600

// passiveUnconfigured 是未配置凭据时的明确中文提示（对齐 ask：不崩溃、可操作）。
func passiveUnconfigured(which string) string {
	return fmt.Sprintf("未配置 %s 凭据：请在运行时配置文件 config.json 的 passive_search 段"+
		"填写 fofa_email/fofa_key（FOFA）或 hunter_key（Hunter，奇安信），或设置环境变量 "+
		"ZRECO_FOFA_EMAIL / ZRECO_FOFA_KEY / ZRECO_HUNTER_KEY 后重试。凭据只在本地运行时配置中，"+
		"不会被写入任何入库文件。", which)
}

// ---------- web_search ----------

// webSearchTool 通用联网搜索（只读，Tavily 兼容 API，配置驱动）。
func (t *ToolSet) webSearchTool() actool.CoreTool {
	return readTool(
		"web_search",
		"通用联网搜索：按关键词查公开网页，返回标题/链接/摘要（最多 10 条）。"+
			"用途：查漏洞背景、找公开 PoC/补丁公告、核实组件信息。"+
			"参数：query 必填；limit 可选（1-10，默认 5）。"+
			"搜索服务未配置时返回明确提示——请在运行时配置 config.json 的 web_search 段"+
			"（endpoint+key，Tavily 兼容 API）或设 ZRECO_WEBSEARCH_ENDPOINT / ZRECO_WEBSEARCH_KEY。"+
			"查到的情报属外部参考：结合目标实测验证后再用 record_fact / insert_assets 落图。",
		obj(map[string]any{
			"query": str("搜索关键词"),
			"limit": intp("结果条数(可选，1-10，默认 5)"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Query)
			if q == "" {
				return actool.Errorf("query 不能为空"), nil
			}
			limit := clampInt(a.Limit, 1, 10, 5)
			cfg := config.LoadWebSearch()
			if strings.TrimSpace(cfg.Key) == "" {
				return actool.Errorf("未配置搜索服务：请在运行时配置文件 config.json 的 web_search 段" +
					"填写 endpoint（Tavily 兼容 API，缺省 " + config.DefaultWebSearchEndpoint + "）与 key，" +
					"或设置环境变量 ZRECO_WEBSEARCH_ENDPOINT / ZRECO_WEBSEARCH_KEY。" +
					"凭据只在本地运行时配置中，不会被写入任何入库文件。"), nil
			}
			results, err := tavilySearch(ctx, cfg.Endpoint, cfg.Key, q, limit)
			if err != nil {
				return actool.Errorf("搜索失败: " + err.Error()), nil
			}
			res := map[string]any{
				"query":   q,
				"count":   len(results),
				"results": results,
			}
			if len(results) == 0 {
				res["note"] = "搜索服务没有返回结果（换个更具体的关键词或英文术语重试）。"
			}
			return jsonResult(res)
		},
	)
}

// tavilySearch 调 Tavily 兼容搜索端点：POST {api_key, query, max_results}，
// 解析 results[].{title,url,content}。出口走 scannerEgressProxyURL()（同扫描工具语义）。
func tavilySearch(ctx context.Context, endpoint, key, query string, limit int) ([]map[string]any, error) {
	transport := &http.Transport{}
	if p := scannerEgressProxyURL(); p != "" {
		if pu, err := url.Parse(p); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	body, err := json.Marshal(map[string]any{
		"api_key":     key,
		"query":       query,
		"max_results": limit,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("搜索服务返回 HTTP %d: %s", resp.StatusCode, truncateStr(strings.TrimSpace(string(raw)), 300))
	}
	var payload struct {
		Results []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Content string `json:"content"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("搜索响应解析失败: %v", err)
	}
	out := make([]map[string]any, 0, len(payload.Results))
	for i, r := range payload.Results {
		if i >= limit {
			break
		}
		m := map[string]any{"title": r.Title, "url": r.URL}
		if r.Content != "" {
			m["snippet"] = truncateStr(r.Content, 300)
		}
		out = append(out, m)
	}
	return out, nil
}

// truncateStr rune 安全截断，超长以「…」收尾（agent 包此前没有通用截断助手，
// 本文件的 snippet/错误体摘要有此需求）。
func truncateStr(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
