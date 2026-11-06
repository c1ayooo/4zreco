package agent

// 漏洞情报工具（vulnintel）：worker/planner/mainagent 在识别出目标组件后，
// 用 search_vulns 查公开已知漏洞（CISA KEV 优先排序），get_vuln 取单条详情
// （完整描述 + CPE criteria 版本区间 + 参考链接）决定利用路径。
// 情报库全库共享且对 agent 只读，因此走包级注入（同 ToolResolve 钩子的模式），
// server 启动时 Set 一次；nil = 工具可用但提示未启用（与 asset 工具的 guard 一致）。

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"time"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"

	"github.com/c1ayooo/4zreco/internal/selfupdate"
	"github.com/c1ayooo/4zreco/internal/vulnintel"
)

// vulnintelStore is process-wide (set once at server startup); safe for
// concurrent ToolSets because the store is read-only from the agent's side.
var vulnintelStore *vulnintel.Store

// SetVulnIntelStore wires the shared intel store; nil disables the tools.
func SetVulnIntelStore(s *vulnintel.Store) { vulnintelStore = s }

// nucleiTemplatesDir is the local nuclei-templates checkout (empty = scan tool
// unavailable). Set alongside the store at startup.
var nucleiTemplatesDir string

// SetNucleiTemplatesDir wires the template tree path; empty disables scan tool.
func SetNucleiTemplatesDir(dir string) { nucleiTemplatesDir = dir }

// cweSkillIndex 把 CWE 编号映射到按 tags.cwe 打标的方法论 skill（目录名）。
// server 启动时从 skills 目录的 SKILL.md frontmatter 构建（server.BuildCweSkillIndex）；
// 未注入（nil/空）时工具输出里不出现 related_skills 字段——联动是纯增量。
// 这是能力对比 M1 的最后一环：「查到 CVE → 自动提示对应方法论 skill」。
var cweSkillIndex atomic.Value // map[string][]string

// SetCweSkillIndex wires the CWE→skills mapping.
func SetCweSkillIndex(idx map[string][]string) { cweSkillIndex.Store(idx) }

// relatedSkillsFor 返回覆盖任一给定 CWE 的去重 skill 名单。
func relatedSkillsFor(cwes []string) []string {
	raw, _ := cweSkillIndex.Load().(map[string][]string)
	if len(raw) == 0 || len(cwes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range cwes {
		for _, s := range raw[strings.ToUpper(strings.TrimSpace(c))] {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// vulnDetailWithSkills 在 VulnDetail 之上附带 skill 联动字段
// （内嵌扁平序列化，无联动时字段缺失、形状与原来完全一致）。
type vulnDetailWithSkills struct {
	*vulnintel.VulnDetail
	RelatedSkills []string `json:"related_skills,omitempty"`
	SkillNote     string   `json:"skill_note,omitempty"`
}

// searchVulns exposes product-keyed CVE retrieval. Version matching against
// NVD criteria is intentionally returned as raw material (criteria text + a
// coarse "version seen" flag) — the LLM judges applicability, structured CPE
// range math is a later batch.
func (t *ToolSet) searchVulns() actool.CoreTool {
	return readTool(
		"search_vulns",
		"按组件名检索【公开已知漏洞】库（NVD + GitHub Advisory Database + CISA KEV 在野利用清单）。"+
			"识别出目标组件（Web 中间件/框架/服务/固件等）后先查这里：有 KEV 标记=已在野利用、优先考虑；"+
			"结果里的 cvss_score 与 severity 用于排优先级。\n"+
			"给 version 参数可做版本判定：\n"+
			"  - version_in_range=true → 目标版本**落在受影响区间内**（该打）\n"+
			"  - version_in_range=false → 目标版本**不在**受影响区间（通常不用打）\n"+
			"  - 该字段缺失 → 无结构化区间，版本是否受影响需自行判断（用 get_vuln 看 cpe_criteria 的版本区间语法）\n"+
			"**version_in_range=false 不等于安全**——有些库的版本区间本身就填错或缺失，"+
			"拿不准时用 get_vuln 看原始区间与参考链接。\n"+
			"source 字段标明这条来自 nvd 还是 ghsa：GHSA 的版本区间是必填的（可信度更高），"+
			"NVD 对新披露的 CVE 常留空。\n"+
			"返回条数有限，命中多时提高 limit 或加 vendor 收窄。",
		obj(map[string]any{
			"product": str("组件名，如 httpd / nginx / thinkphp / tomcat / weblogic；支持 % 通配"),
			"vendor":  str("厂商名过滤(可选)，如 apache / oracle，用于区分同名组件"),
			"version": str("目标版本号(可选，如 2.4.49)：命中过 CPE 版本段的结果会标记 version_seen_in_criteria"),
			// limit 是整数参数。之前误写成 obj(...)（嵌套对象），校验器于是要求
			// 模型传 `limit: {}` —— 实测 41 次调用全部报
			// "invalid tool input: limit: expected object"，这个工具等于废了一半。
			"limit": intp("返回条数上限(默认 20，最大 50)"),
		}, "product"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("search_vulns 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				Product string `json:"product"`
				Vendor  string `json:"vendor"`
				Version string `json:"version"`
				Limit   int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Product) == "" {
				return actool.Errorf("product 不能为空"), nil
			}
			hits, err := vulnintelStore.SearchVulns(context.Background(), a.Vendor, a.Product, a.Version, a.Limit)
			if err != nil {
				return actool.Errorf("检索漏洞失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return jsonResult(map[string]any{
					"count": 0,
					"note":  "该组件名在情报库无命中（可能拼写与 CPE 命名不符，试换常见缩写如 httpd/IIS；或该组件近期无已知漏洞）",
				})
			}
			kev := 0
			for _, h := range hits {
				if h.KEV {
					kev++
				}
			}
			res := map[string]any{
				"count":           len(hits),
				"kev_count":       kev,
				"vulnerabilities": hits,
				"note":            "kev=true 表示 CISA 已确认在野利用，价值最高；下一步用 get_vuln 看单条详情（影响版本区间/参考链接）",
			}
			// CWE→skill 联动：命中条目带 CWE 时提示对应方法论 skill。
			var allCWEs []string
			for _, h := range hits {
				allCWEs = append(allCWEs, h.Cwes...)
			}
			if skills := relatedSkillsFor(allCWEs); len(skills) > 0 {
				res["related_skills"] = skills
			}
			return jsonResult(res)
		},
	)
}

// getVuln exposes the full record for one CVE.
func (t *ToolSet) getVuln() actool.CoreTool {
	return readTool(
		"get_vuln",
		"取单条已知漏洞的完整详情：英文原始描述、CVSS 评分与向量、是否 KEV、"+
			"cpe_criteria（NVD 的影响范围原文，cpe:2.3:a:厂商:组件:版本:... 字符串，"+
			"配套 versionEndExcluding / versionStartIncluding 等区间字段表达影响范围）、"+
			"references（利用/公告/补丁链接）。用它判断目标版本是否命中、以及去哪找现成利用。",
		obj(map[string]any{
			"cve_id": str("CVE 编号，如 CVE-2021-41773"),
		}, "cve_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("get_vuln 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.CVEID) == "" {
				return actool.Errorf("cve_id 不能为空"), nil
			}
			d, err := vulnintelStore.GetVuln(context.Background(), a.CVEID)
			if err != nil {
				return actool.Errorf("查询漏洞失败: " + err.Error()), nil
			}
			if d == nil {
				return actool.Errorf(a.CVEID + " 不在情报库中（库只收录公开同步的数据源）"), nil
			}
			if skills := relatedSkillsFor(d.Cwes); len(skills) > 0 {
				return jsonResult(vulnDetailWithSkills{
					VulnDetail:    d,
					RelatedSkills: skills,
					SkillNote:     "这些方法论 skill 打标了该漏洞的 CWE 编号——深挖验证前可用 Skill 工具加载对应维度（越权/注入/竞态等的验证步骤与证据要求）",
				})
			}
			return jsonResult(d)
		},
	)
}

// searchRecentCritical exposes "what critical CVEs came out recently".
//
// 与 search_vulns 的分工：
//   - search_vulns 按**组件**查（已知「这是 nginx」，问 nginx 有哪些漏洞）；
//   - 本工具按**时间**查（问「最近 7 天出了哪些高危」），不需要事先知道
//     组件名或 CVE 号。
//
// 为什么需要它（2026-10-22 调研）：worker 扫到一个资产后，资产指纹往往是
// 「PHP/8.1.2」这种形式，它知道该查 PHP，但**不知道刚出了什么**——而高危
// 漏洞的价值窗口就是刚披露的那几天。有了这条工具，扫到组件就能直接问
// 「最近 PHP 出了什么高危」。
//
// version_undetermined=true 表示 NVD 还没填受影响版本区间——这**不代表目标
// 版本不受影响**，反而值得优先看（刚披露的高危通常还没补版本区间）。
func (t *ToolSet) searchRecentCritical() actool.CoreTool {
	return readTool(
		"search_recent_critical",
		"查【最近披露的高危漏洞】（CVSS≥9.0 或 CISA KEV 已在野利用）。"+
			"用法：扫到某个组件/资产后（指纹形如 PHP/8.1.2、Apache httpd 2.4.49），"+
			"用它问「最近这个方向出了什么高危」——不需要事先知道 CVE 号。"+
			"结果里的 products 字段是受影响产品（vendor/product），用它和你的目标"+
			"指纹比对；version_undetermined=true 表示 NVD 还没填受影响版本区间，"+
			"【不代表你的版本不受影响】——这类刚披露的漏洞通常还没补版本信息，值得优先"+
			"查厂商 advisory（用 get_vuln 看 refs 里的 GHSA/安全公告）确认受影响版本，"+
			"再用 scan_with_nuclei 或手工构造验证。",
		obj(map[string]any{
			"days":  intp("回看天数(默认 7,最大 90)。刚披露的漏洞用小值(3~14)即可"),
			"limit": intp("返回条数上限(默认 20,最大 100)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("search_recent_critical 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				Days  int `json:"days"`
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Days < 0 {
				return actool.Errorf("days 不能为负"), nil
			}
			if a.Days > 90 {
				a.Days = 90
			}
			hits, err := vulnintelStore.SearchRecentCritical(context.Background(), a.Days, a.Limit)
			if err != nil {
				return actool.Errorf("查询近期高危漏洞失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return jsonResult(map[string]any{
					"count": 0,
					"note":  "最近窗口内情报库没有新的高危漏洞（快通道按 CVSS≥9.0 或 KEV 收录；库只收录公开同步的数据源）",
				})
			}
			undet := 0
			for _, h := range hits {
				if h.VersionUndetermined {
					undet++
				}
			}
			return jsonResult(map[string]any{
				"count":                len(hits),
				"version_undetermined": undet,
				"vulnerabilities":      hits,
				"note":                 "version_undetermined=true 的条目表示 NVD 未填受影响版本区间——不等于不受影响，优先查厂商 advisory 确认",
			})
		},
	)
}

// getPoc exposes aggregated PoC/EXP entries for one CVE.
func (t *ToolSet) getPoc() actool.CoreTool {
	return readTool(
		"get_poc",
		"取单条已知漏洞的【现成 PoC/利用】聚合：GitHub 上引用该 CVE 的公开仓库，"+
			"按星数排序。先 search_vulns 确认漏洞存在，再 get_poc 找现成弹药；返回的是"+
			"仓库地址与描述，不替你执行——用 Bash clone/分析仓库内容、按其说明构造利用。"+
			"没有命中只代表公开仓库没有现成代码，不代表漏洞不可利用。",
		obj(map[string]any{
			"cve_id": str("CVE 编号，如 CVE-2021-41773"),
		}, "cve_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("get_poc 未启用: 漏洞情报库未初始化"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.CVEID) == "" {
				return actool.Errorf("cve_id 不能为空"), nil
			}
			hits, err := vulnintelStore.GetPoCs(context.Background(), a.CVEID)
			if err != nil {
				return actool.Errorf("查询 PoC 失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count": len(hits),
				"pocs":  hits,
			})
		},
	)
}

// scanWithNuclei assembles a nuclei command for the worker's Bash tool. The
// tool deliberately does NOT execute nuclei itself: Bash runs it through the
// recording proxy + approval gates like every other command, keeping audit
// semantics uniform. What this tool adds is template selection (CVE-keyed)
// and a correct, version-pinned command line.
func (t *ToolSet) scanWithNuclei() actool.CoreTool {
	return readTool(
		"scan_with_nuclei",
		"组装一条【nuclei 模板扫描】命令交给 Bash 执行(本工具只组命令不执行)。"+
			"适合已确认目标可达、且 search_vulns 找到对应 CVE 后做批量模板验证。"+
			"give cve_id 时只跑命中该 CVE 的模板(推荐,快且聚焦);不给则跑全模板树"+
			"(慢,慎用,建议配合 severity 收窄)。模板库随情报同步自动更新。"+
			"命令输出为 JSONL 结果,每行一个发现;没有输出=没有模板命中。",
		obj(map[string]any{
			"target":   str("扫描目标 URL,如 https://example.com"),
			"cve_id":   str("CVE 编号(可选,推荐):只跑命中该 CVE 的模板,如 CVE-2021-41773"),
			"severity": str("严重度过滤(可选):critical,high,medium,low 逗号组合"),
		}, "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if nucleiTemplatesDir == "" {
				return actool.Errorf("scan_with_nuclei 未启用: 模板库路径未配置"), nil
			}
			if !vulnintel.NucleiInstalled() {
				return actool.Errorf("nuclei 未安装(当前运行环境不含该二进制;Docker 镜像已内置)"), nil
			}
			var a struct {
				Target   string `json:"target"`
				CVEID    string `json:"cve_id"`
				Severity string `json:"severity"`
			}
			_ = json.Unmarshal(in, &a)
			cmd, cancel, err := vulnintel.BuildNucleiCmd(context.Background(), nucleiTemplatesDir, vulnintel.ScanArgs{
				Target:       a.Target,
				CVEID:        a.CVEID,
				Severity:     a.Severity,
				TimeoutTotal: 10 * time.Minute,
			})
			if err != nil {
				return actool.Errorf("组装扫描命令失败: " + err.Error()), nil
			}
			defer cancel()
			return jsonResult(map[string]any{
				"run_with_bash": strings.Join(cmd.Args, " "),
				"note": "用 Bash 工具执行上面这条命令(默认 10 分钟超时,超时会截断输出);" +
					"输出为 JSONL,每行一个模板命中;空输出=无命中。发现真实漏洞后走 report_finding 走正常上报。",
			})
		},
	)
}

// netContext 输出当前运行环境的网络上下文(网卡/路由/用户配置的回连信息),
// 供 reverse shell / bind shell / MSF 的 LHOST/LPORT 决策。
// 刻意不 exec ip 命令(镜像里 iproute2 不保证有),用 Go 原生枚举。
//
// 说明按部署形态分两套：二进制部署时本机网卡就是可用地址，内网渗透直接用；
// 容器部署时本机 IP 是容器内网地址，目标大概率连不进来，必须用宿主/公网可达地址。
func (t *ToolSet) netContext() actool.CoreTool {
	inDocker := selfupdate.InDocker()
	desc := "获取本机网络上下文：全部网卡 IP、以及平台配置的【回连可达地址】。"
	if inDocker {
		desc += "当前运行在容器里：本机 IP 是容器内网地址，目标大概率连不进来——起 reverse shell / " +
			"MSF handler 前【必须】先看本工具，用配置的宿主/公网可达地址做 LHOST，端口用已映射的端口段。"
	} else {
		desc += "当前是二进制(宿主)部署：interfaces 就是本机真实网卡，内网渗透直接用本机在该网段的 IP 做 LHOST 即可，" +
			"bind/reverse shell 都不需要额外的端口映射配置。"
	}
	return readTool(
		"net_context",
		desc,
		obj(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			type iface struct {
				Name string   `json:"name"`
				IPs  []string `json:"ips"`
			}
			var ifaces []iface
			addrs, err := net.Interfaces()
			if err == nil {
				for _, a := range addrs {
					if a.Flags&net.FlagUp == 0 {
						continue
					}
					addrs2, err := a.Addrs()
					if err != nil || len(addrs2) == 0 {
						continue
					}
					it := iface{Name: a.Name, IPs: []string{}}
					for _, ad := range addrs2 {
						it.IPs = append(it.IPs, ad.String())
					}
					ifaces = append(ifaces, it)
				}
			}
			var hint, portMap string
			if vulnintelStore != nil {
				hint = vulnintelStore.EgressHint(ctx)
				portMap = vulnintelStore.EgressPortMap(ctx)
			}
			note := ""
			if inDocker {
				note = "interfaces 是【容器内视角】，对外大概率不可达——reverse shell 的 LHOST 要用宿主/对外可达地址" +
					"（egress_hint 若有），监听端口必须在 port_map 声明过的映射范围内。" +
					"两者都为空说明平台未配置：用 add_hint 请求人工提供，不要拿容器 IP 盲目回连。"
			} else {
				note = "这是宿主二进制部署：interfaces 就是本机真实网卡，内网渗透可直接拿本机在该网段的 IP 当 LHOST，" +
					"端口随意绑、无需映射。目标是公网或跨网段时，挑其中一个对目标可达的地址即可。" +
					"egress_hint / port_map 为空不影响本机直连；若不确定哪个地址对目标可达，可用 add_hint 问一句。"
			}
			return jsonResult(map[string]any{
				"interfaces":      ifaces,
				"egress_hint":     hint,
				"egress_port_map": portMap,
				"deploy_mode":     map[bool]string{true: "docker", false: "host"}[inDocker],
				"note":            note,
			})
		},
	)
}
