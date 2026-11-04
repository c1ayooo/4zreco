package traffic

// 代理池:多上游出口的按请求轮换。接入点就是 go-mitmproxy 的 per-request
// upstream 钩子( SetUpstreamProxy 的函数签名天然支持),selector 在钩子里
// 按策略挑一个可用代理;请求失败(RequestError)按上游计失败数,连败熔断。
//
// 与 global_proxy 的关系:池非空时池优先(全局代理被忽略),池空回退全局
// 单代理/直连——老用户零迁移成本。
// 熔断语义与 llmpool 一致思路:连败 N 次进入冷却,冷却期满自动恢复尝试。

import (
	"fmt"
	"hash/fnv"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PoolEntry 是池中的一个上游代理。
type PoolEntry struct {
	URL      string `json:"url"`      // http/https/socks5,可含 user:pass(输出时掩码)
	Name     string `json:"name"`     // 展示名
	Enabled  bool   `json:"enabled"`  // 手动开关
	Weight   int    `json:"weight"`   // 轮询权重(round_robin 有效,≥1)
	Failures int    `json:"failures"` // 连败计数(熔断窗口)
	LastOK   string `json:"last_ok,omitempty"`
	LastFail string `json:"last_fail,omitempty"`
	// BreakRemaining 是该上游当前熔断的剩余秒数(0=未熔断)。主动健康检查与
	// 手动验证都会读写 last_ok/last_fail/break,页面据此筛选失效代理。
	BreakRemaining int `json:"break_remaining,omitempty"`
}

// selector 持池的内存态与策略。持久化在 server 侧(settings+json),这里只管选。
type selector struct {
	mu       sync.Mutex
	entries  []*poolUpstream // enabled 项
	strategy string          // round_robin / sticky_host / sticky_host_random / random
	rr       atomic.Uint64   // 轮询游标(round_robin/random 共用)
	// hostPick 记录 sticky_host_random 的「目标 → 已选定上游」绑定,让同一目标在
	// 一段会话里稳定走同一出口(像真实用户),同时不用给每个 host 重新掷骰子。
	// 存 URL 字符串而不是指针:池整体重载时条目指针会换,字符串仍能对上。
	hostPick sync.Map
}

type poolUpstream struct {
	raw       *url.URL
	name      string
	weight    int
	failures  atomic.Int64
	lastFail  atomic.Int64 // unix
	lastOK    atomic.Int64 // unix
	breakOpen atomic.Int64 // 熔断到期时间(unix;0=未熔断)
}

const (
	breakAfterFails = 5              // 连败 N 次 → 熔断
	breakCooldown   = 10 * time.Minute // 冷却期
)

// SetPool 原子替换整池(server 每次 CRUD 后全量推送)。
func (s *selector) SetPool(items []PoolEntry, strategy string) error {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	switch strategy {
	case "", "round_robin", "sticky_host", "sticky_host_random", "random":
	default:
		return fmt.Errorf("未知策略 %q(round_robin/sticky_host/sticky_host_random/random)", strategy)
	}
	ups := make([]*poolUpstream, 0, len(items))
	for _, it := range items {
		if !it.Enabled {
			continue
		}
		u, err := ValidateProxyURL(it.URL)
		if err != nil {
			continue // server 侧已校验;双保险跳过坏条目
		}
		w := it.Weight
		if w < 1 {
			w = 1
		}
		nu := &poolUpstream{raw: u, name: it.Name, weight: w}
		// 重推整池时继承旧条目的熔断状态(按 URL 匹配),避免每次保存都重置熔断。
		for _, prev := range s.entries {
			if prev.raw.String() == nu.raw.String() {
				nu.failures.Store(prev.failures.Load())
				nu.breakOpen.Store(prev.breakOpen.Load())
			}
		}
		ups = append(ups, nu)
	}
	s.mu.Lock()
	s.entries = ups
	s.strategy = strategy
	s.mu.Unlock()
	return nil
}

// Pick 为一个目标请求挑上游。池空/全熔断返回 nil(直连,回退全局逻辑)。
// host 是目标 "host:port",sticky_host 策略按它稳定散列。
func (s *selector) Pick(host string) *url.URL {
	s.mu.Lock()
	entries := s.entries
	strategy := s.strategy
	s.mu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	now := time.Now().Unix()
	available := make([]*poolUpstream, 0, len(entries))
	for _, e := range entries {
		if bo := e.breakOpen.Load(); bo != 0 && now < bo {
			continue // 熔断中
		}
		available = append(available, e)
	}
	if len(available) == 0 {
		return nil
	}
	switch strategy {
	case "sticky_host":
		h := fnv.New32a()
		_, _ = h.Write([]byte(host))
		return available[h.Sum32()%uint32(len(available))].raw
	case "sticky_host_random":
		// 首次遇到该目标时随机钉住一个上游,之后固定 —— 兼得「同目标走同一出口」
		// 与「不同目标的出口分布随机」。钉住的那个被熔断时自动重钉。
		if raw, ok := s.hostPick.Load(host); ok {
			if u := findUpstream(available, raw.(string)); u != nil {
				return u.raw
			}
		}
		u := available[s.rr.Add(1)%uint64(len(available))]
		s.hostPick.Store(host, u.raw.String())
		return u.raw
	case "random":
		return available[s.rr.Add(1)%uint64(len(available))].raw
	default: // round_robin,按权重展开(权重大的出现更密)
		total := 0
		for _, e := range available {
			total += e.weight
		}
		n := s.rr.Add(1) - 1
		idx := n % uint64(total)
		for _, e := range available {
			if idx < uint64(e.weight) {
				return e.raw
			}
			idx -= uint64(e.weight)
		}
		return available[0].raw
	}
}

// findUpstream 从一段候选里按原始 URL 找回条目(钉住关系用 URL 串对账,池重载后仍有效)。
func findUpstream(list []*poolUpstream, raw string) *poolUpstream {
	for _, e := range list {
		if e.raw.String() == raw {
			return e
		}
	}
	return nil
}

// ReportFailure 上报某上游代理的一次失败(带目标 host 用于诊断,当前只计数)。
// 连败达阈值 → 熔断 10 分钟;成功一次即清零。
func (s *selector) ReportResult(proxyRaw string, ok bool) {
	if proxyRaw == "" {
		return
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		now := time.Now().Unix()
		if ok {
			e.failures.Store(0)
			e.lastOK.Store(now)
			return
		}
		e.lastFail.Store(now)
		if n := e.failures.Add(1); n >= breakAfterFails {
			e.breakOpen.Store(time.Now().Add(breakCooldown).Unix())
			e.failures.Store(0)
		}
		return
	}
}

// MarkBad 把某个上游立即熔断 cooldown(主动健康检查 / Agent 上报用)。
// 被动熔断要等连败 5 次,而「已知不通」的代理再试 5 次只是白白拖慢请求——
// 主动判定成立就立刻冷却。返回被熔断上游的掩码 URL,空串表示没找到。
func (s *selector) MarkBad(proxyRaw string, cooldown time.Duration) string {
	if proxyRaw == "" {
		return ""
	}
	if cooldown <= 0 {
		cooldown = breakCooldown
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		e.breakOpen.Store(time.Now().Add(cooldown).Unix())
		e.lastFail.Store(time.Now().Unix())
		e.failures.Store(0)
		// 钉住关系一并作废,sticky_host_random 下次 Pick 会换一个出口。
		s.hostPick.Range(func(k, v any) bool {
			if raw, _ := v.(string); raw == proxyRaw {
				s.hostPick.Delete(k)
			}
			return true
		})
		return maskURL(e.raw)
	}
	return ""
}

// BreakRemaining 返回该上游当前熔断的剩余秒数(0 = 未熔断 / 不在池里)。
func (s *selector) BreakRemaining(proxyRaw string) int {
	if proxyRaw == "" {
		return 0
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		rest := int(e.breakOpen.Load() - time.Now().Unix())
		if rest < 0 {
			return 0
		}
		return rest
	}
	return 0
}

// Status 导出池状态(UI 展示;URL 掩码凭据)。
func (s *selector) Status() []PoolEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	out := make([]PoolEntry, 0, len(s.entries))
	for _, e := range s.entries {
		item := PoolEntry{
			URL:      maskURL(e.raw),
			Name:     e.name,
			Enabled:  true,
			Weight:   e.weight,
			Failures: int(e.failures.Load()),
		}
		if bo := e.breakOpen.Load(); bo > now {
			item.BreakRemaining = int(bo - now)
		}
		if t := e.lastOK.Load(); t > 0 {
			item.LastOK = time.Unix(t, 0).Format(time.RFC3339)
		}
		if t := e.lastFail.Load(); t > 0 {
			item.LastFail = time.Unix(t, 0).Format(time.RFC3339)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// maskURL 隐藏 user:pass(user 保留,pass → ****)。
func maskURL(u *url.URL) string {
	c := *u
	if c.User != nil {
		if _, hasPass := c.User.Password(); hasPass {
			c.User = url.UserPassword(c.User.Username(), "****")
		}
	}
	return c.String()
}

// SetProxyPool 原子替换代理池(Traffic 门面)。
func (t *Traffic) SetProxyPool(items []PoolEntry, strategy string) error {
	sel := &selector{}
	if err := sel.SetPool(items, strategy); err != nil {
		return err
	}
	if len(items) == 0 {
		t.pool.Store(nil) // 池清空 = 回退全局代理/直连
		return nil
	}
	t.pool.Store(sel)
	return nil
}

// ProxyPoolStatus 导出池内条目(掩码 URL + 熔断计数),供 UI 展示。
func (t *Traffic) ProxyPoolStatus() []PoolEntry {
	if pool := t.pool.Load(); pool != nil {
		return pool.Status()
	}
	return []PoolEntry{}
}

// ProxyPoolReportOK 上报一次成功(清零连败,记录时间)。
func (t *Traffic) ProxyPoolReportOK(proxyRaw string) {
	pool := t.pool.Load()
	if pool == nil {
		return
	}
	pool.ReportResult(proxyRaw, true)
}

// ProxyPoolReportFail 上报一次失败(只累计连败,不立刻熔断——被动路径的阈值是 5 次)。
func (t *Traffic) ProxyPoolReportFail(proxyRaw string) {
	pool := t.pool.Load()
	if pool == nil {
		return
	}
	pool.ReportResult(proxyRaw, false)
}

// ProxyPoolMarkBad 把某个上游立即熔断 cooldown(主动健康检查 / 手动验证失败时用)。
// 返回被熔断的掩码 URL,空串表示不在池里。
func (t *Traffic) ProxyPoolMarkBad(proxyRaw string, cooldown time.Duration) string {
	pool := t.pool.Load()
	if pool == nil {
		return ""
	}
	return pool.MarkBad(proxyRaw, cooldown)
}

// ProxyPoolReportBad 让调用方(Agent)把某个目标「当前正在用的出口」立即熔断。
// target 可以是完整 host:port —— MITM 侧按 host 记录了最近一次选中的上游,
// 所以不需要请求方知道它到底走了哪个代理。返回被熔断的掩码 URL,空串表示
// 池为空 / 该目标没走过池上游(例如直连或全局单代理)。
func (t *Traffic) ProxyPoolReportBad(target string, cooldown time.Duration) string {
	pool := t.pool.Load()
	if pool == nil {
		return ""
	}
	raw, ok := t.lastPick.Load(hostOnly(target))
	if !ok {
		return ""
	}
	u, _ := raw.(string)
	return pool.MarkBad(u, cooldown)
}
