package agent

// 强动作扫描器领域工具（AGENTS.md §5.5 P3）：zombie_weakpass / proton_secrets。
//
// 进程内接 chainreactors 官方 Go SDK（sdk/zombie 子包、sdk/proton 子包，
// pseudo-version 锁死在 go.mod，与 P2 的 gogo/spray 同一 sdk 提交），不拉外部进程。
//
// 与 P2 只读发现类（tools_scanners.go 的 readTool）不同，这两个都是【强动作】：
//   - zombie_weakpass 对目标发起真实认证尝试（失败日志、账户锁定风险）；
//   - proton_secrets 从数据/文件里提取凭据明文。
// 所以照 tools_listener.go 的 listener_start 审批接线：工具本体用 writeTool 包装，
// ask 审批门在拦截规则层（seed 批次 v6，「[内置] 弱口令爆破 zombie_weakpass」/
// 「[内置] 敏感信息扫描 proton_secrets」两条 tool_name ask 规则），审批通过才执行。
//
// 证据纪律（§5.5）：凭据类输出不得进 trace 明文——
//   - zombie 命中（含密码明文）整体写 evidence 附件（save_evidence 的内部实现
//     路径 ArtifactRecorder.RecordArtifact），工具返回只给 ip:port/service/用户名，
//     密码一律打码；
//   - proton 命中明细（提取到的 secret 原文）写 evidence，返回只给规则类型统计 +
//     条数 + evidence artifact id。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
	sdkproton "github.com/chainreactors/sdk/proton"
	sdkzombie "github.com/chainreactors/sdk/zombie"
	zombiepkg "github.com/chainreactors/zombie/pkg"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// ---------- 引擎单例（懒初始化，对齐 tools_scanners.go） ----------

var (
	zombieEngine  *sdkzombie.Engine
	zombieInitErr error
	protonEng     *sdkproton.Engine
	protonInitErr error
)

func zombieWeakpassEngine() (*sdkzombie.Engine, error) {
	scannerMu.Lock()
	defer scannerMu.Unlock()
	if zombieEngine != nil || zombieInitErr != nil {
		return zombieEngine, zombieInitErr
	}
	// zombiepkg.Load（经引擎 init）加载内嵌端口表/服务关键词/内置弱口令字典，
	// 开销不小且进程级共享——懒初始化单例，失败缓存不重试。
	zombieEngine, zombieInitErr = sdkzombie.NewEngine(sdkzombie.NewConfig())
	return zombieEngine, zombieInitErr
}

func protonSecretsEngine() (*sdkproton.Engine, error) {
	scannerMu.Lock()
	defer scannerMu.Unlock()
	if protonEng != nil || protonInitErr != nil {
		return protonEng, protonInitErr
	}
	// proton 模块本身不带内嵌规则（sdk 的 WithCategories 需要 ResourceProvider 提供
	// found_* 数据，上游没有）——内置敏感信息规则集由本项目以 YAML 模板数据
	// （protonBuiltinTemplateYAML）随二进制分发，见文件底部。
	protonEng, protonInitErr = sdkproton.NewEngine(
		sdkproton.NewConfig().WithTemplateData([]byte(protonBuiltinTemplateYAML)))
	return protonEng, protonInitErr
}

// ---------- 证据附件（复用 save_evidence 的内部实现路径） ----------

// recordScanEvidence 把扫描原始命中（含凭据/secret 明文）写成工作目录里的 JSON
// 文件并经 ArtifactRecorder 登记为任务附件——与 save_evidence 工具同一条内部
// 落盘路径（server.RecordArtifact：路径边界校验 → sha256 去重 → 复制 → 落库）。
// 返回 artifact id；0 = 已写盘但登记失败/不可用（err 说明原因）。
func (t *ToolSet) recordScanEvidence(prefix, note string, payload any) (int64, error) {
	if t.artifactRecorder == nil {
		return 0, fmt.Errorf("证据附件存储不可用（当前运行环境未启用）")
	}
	if t.taskID <= 0 {
		return 0, fmt.Errorf("证据登记需要任务上下文")
	}
	if t.runDir == "" {
		return 0, fmt.Errorf("证据登记需要当前运行目录（内部未注入）")
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("证据序列化失败: %w", err)
	}
	rel := fmt.Sprintf("%s-%d.json", prefix, time.Now().UnixNano())
	path := filepath.Join(t.runDir, rel)
	// 0600：凭据类原始命中只落任务目录，不放开组/其他读。
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return 0, fmt.Errorf("证据写盘失败: %w", err)
	}
	rec, err := t.artifactRecorder.RecordArtifact(t.taskID, 0, t.runDir, rel, "", "data", "", note)
	if err != nil {
		return 0, fmt.Errorf("证据登记失败（文件已落工作目录 %s）: %w", rel, err)
	}
	return rec.ID, nil
}

// ---------- zombie_weakpass ----------

// zombie 内置弱口令字典的兜底规模上限：防止模型传超大列表把一次调用变成
// 数百万次真实认证尝试。users×passwords×targets 的笛卡尔积超限直接拒绝。
const (
	maxZombieUsers     = 64
	maxZombiePasswords = 256
	maxZombieAttempts  = 50000
)

// zombieTargetSpec 是一条 service://[user:pass@]host:port 的解析结果。
type zombieTargetSpec struct {
	Service  string
	IP       string
	Port     string
	Username string
	Password string
	HasCreds bool
}

// parseZombieTarget 解析 service://[user:pass@]host:port。
// host 支持域名（内部解析成 IP——zombie 的 Target.IP 要求是可拨号地址）。
func parseZombieTarget(ctx context.Context, raw string) (zombieTargetSpec, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return zombieTargetSpec{}, fmt.Errorf("target 不能为空")
	}
	u, err := url.Parse(t)
	if err != nil {
		return zombieTargetSpec{}, fmt.Errorf("target %q 解析失败: %v", raw, err)
	}
	if u.Scheme == "" {
		return zombieTargetSpec{}, fmt.Errorf("target %q 缺少服务前缀（应为 service://host:port，如 ssh://1.2.3.4）", raw)
	}
	spec := zombieTargetSpec{Service: strings.ToLower(u.Scheme)}
	// 服务合法性前置校验（引擎 normalizeTarget 对未知服务静默放行，运行期才炸——
	// 这里给出带支持清单的明确报错）。
	if _, ok := zombiepkg.Services.Get(spec.Service); !ok {
		return zombieTargetSpec{}, fmt.Errorf("target %q 的服务 %q 不受支持（支持: %s）",
			raw, spec.Service, strings.Join(supportedZombieServices(), "/"))
	}
	if u.User != nil {
		spec.Username = u.User.Username()
		spec.Password, _ = u.User.Password()
		spec.HasCreds = spec.Username != ""
	}
	host := u.Hostname()
	if host == "" {
		return zombieTargetSpec{}, fmt.Errorf("target %q 缺少主机地址", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		spec.IP = ip.String()
	} else {
		// 域名：在调用 ctx 上解析（超时由 ctx 控制），优先 IPv4。
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(rctx, host)
		if err != nil || len(addrs) == 0 {
			return zombieTargetSpec{}, fmt.Errorf("target %q 的域名 %s 解析失败（%v）——请直接给 IP", raw, host, err)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				spec.IP = a
				break
			}
		}
		if spec.IP == "" {
			spec.IP = addrs[0]
		}
	}
	spec.Port = u.Port()
	if spec.Port == "" {
		if s, ok := zombiepkg.Services.Get(spec.Service); ok {
			spec.Port = s.DefaultPort
		}
	}
	if spec.Port == "" {
		return zombieTargetSpec{}, fmt.Errorf("target %q 缺少端口且服务 %q 无默认端口", raw, spec.Service)
	}
	return spec, nil
}

// supportedZombieServices 返回已注册服务名列表（排序，报错信息用）。
func supportedZombieServices() []string {
	out := make([]string, 0, len(zombiepkg.Services.Plugins))
	for name := range zombiepkg.Services.Plugins {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// builtinWeakLists 取服务内置弱口令字典：优先 <service>_user / <service>_pwd
// （zombie 内嵌配置按服务带的定向字典），缺省回退 top100_user / top100_pwd。
// 仅在调用方既没给 userlist/passlist、target 也没带凭据时使用——即 zombie CLI
// 「--weakpass 内置常见弱口令规则」的 SDK 等价物。
func builtinWeakLists(service string) (users, pwds []string) {
	users = zombiepkg.Keywords[service+"_user"]
	pwds = zombiepkg.Keywords[service+"_pwd"]
	if len(users) == 0 {
		users = zombiepkg.Keywords["top100_user"]
	}
	if len(pwds) == 0 {
		pwds = zombiepkg.Keywords["top100_pwd"]
	}
	if len(users) > maxZombieUsers {
		users = users[:maxZombieUsers]
	}
	if len(pwds) > maxZombiePasswords {
		pwds = pwds[:maxZombiePasswords]
	}
	return users, pwds
}

// zombieWeakpass 授权弱口令检测（强动作，ask 审批门在拦截规则 seed v6）。
func (t *ToolSet) zombieWeakpass() actool.CoreTool {
	return writeTool(
		"zombie_weakpass",
		"对已发现的服务做【弱口令检测】（zombie 内核进程内执行，需要 ask 审批）。"+
			"支持 ssh/smb/mysql/mssql/postgresql/redis/mongo/ftp/telnet/vnc/rdp/ldap/rsync 等服务。"+
			"参数：target 必填（列表，每条形如 service://[user:pass@]host:port，如 ssh://admin@10.0.0.1、mysql://root:root@10.0.0.2:3306）；"+
			"userlist/passlist 可选（用户名/密码列表，笛卡尔积尝试）；都不给且 target 未带凭据时用内置常见弱口令字典。"+
			"命中只回显服务/地址/用户名（密码打码），完整命中（含凭据）自动落证据附件。"+
			"注意：会产生真实认证失败日志、可能触发账户锁定——只对授权目标使用，先小字典再扩大。",
		obj(map[string]any{
			"target": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "目标列表，每条 service://[user:pass@]host:port（如 ssh://10.0.0.1、mysql://root:root@10.0.0.2:3306）",
			},
			"userlist": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "可选：用户名列表（≤64 个）；与 passlist 搭配做笛卡尔积爆破",
			},
			"passlist": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "可选：密码列表（≤256 个）",
			},
			"timeout_sec": intp("总超时秒数(可选，默认 300，上限 900)"),
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			eng, err := zombieWeakpassEngine()
			if err != nil {
				return actool.Errorf("zombie_weakpass 未启用: 引擎初始化失败: " + err.Error()), nil
			}
			var a struct {
				Target     json.RawMessage `json:"target"`
				Userlist   []string        `json:"userlist"`
				Passlist   []string        `json:"passlist"`
				TimeoutSec int             `json:"timeout_sec"`
			}
			_ = json.Unmarshal(in, &a)
			targets, err := parseZombieTargets(ctx, a.Target)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			users, pwds := dedupeStrings(a.Userlist), dedupeStrings(a.Passlist)
			if len(users) > maxZombieUsers || len(pwds) > maxZombiePasswords {
				return actool.Errorf(fmt.Sprintf("userlist/passlist 过大（上限 %d/%d）——先小字典试探，命中面出来再定向扩大", maxZombieUsers, maxZombiePasswords)), nil
			}
			// 三种模式可并存：target 自带凭据走 Sniper（只验这一对），
			// 其余按 userlist/passlist 或内置字典走 Brute。
			var sniperTargets, bruteTargets []sdkzombie.Target
			for _, spec := range targets {
				z := sdkzombie.Target{IP: spec.IP, Port: spec.Port, Service: spec.Service}
				if spec.HasCreds {
					z.Username, z.Password = spec.Username, spec.Password
					sniperTargets = append(sniperTargets, z)
				} else {
					bruteTargets = append(bruteTargets, z)
				}
			}
			if len(bruteTargets) > 0 && len(users) == 0 && len(pwds) == 0 {
				// 未指定字典：用该服务的内置弱口令列表（首个 brute 目标的服务定向，
				// 混合服务时回退 top100——各服务定向字典只在单一服务时生效）。
				svc := bruteTargets[0].Service
				for _, bt := range bruteTargets {
					if bt.Service != svc {
						svc = ""
						break
					}
				}
				users, pwds = builtinWeakLists(svc)
			}
			attempts := len(users) * len(pwds) * len(bruteTargets)
			if attempts > maxZombieAttempts {
				return actool.Errorf(fmt.Sprintf("尝试组合过大（%d 用户 × %d 密码 × %d 目标 = %d，上限 %d）——收窄字典或分批",
					len(users), len(pwds), len(bruteTargets), attempts, maxZombieAttempts)), nil
			}
			sctx, cancel := context.WithTimeout(ctx, scannerTimeout(a.TimeoutSec))
			defer cancel()
			zctx := sdkzombie.NewContext().WithContext(sctx).WithThreads(16)
			if p := scannerEgressProxyURL(); p != "" {
				zctx = zctx.WithProxy(p)
			}
			var hits []*sdktypes.ZombieResult
			if len(sniperTargets) > 0 {
				res, err := eng.Sniper(zctx, sniperTargets)
				if err != nil {
					return actool.Errorf("zombie 执行失败: " + err.Error()), nil
				}
				hits = append(hits, res...)
			}
			if len(bruteTargets) > 0 && len(users) > 0 && len(pwds) > 0 {
				res, err := eng.Brute(zctx, bruteTargets, users, pwds)
				if err != nil {
					return actool.Errorf("zombie 执行失败: " + err.Error()), nil
				}
				hits = append(hits, res...)
			}
			// 证据纪律：完整命中（含密码明文）落 evidence；返回值只给地址/服务/用户名。
			res := map[string]any{
				"mode":     zombieModeLabel(len(sniperTargets), len(bruteTargets), len(users), len(pwds)),
				"count":    len(hits),
				"services": zombieHitAddrs(hits),
			}
			if len(hits) > 0 {
				full := make([]map[string]any, 0, len(hits))
				for _, h := range hits {
					full = append(full, map[string]any{
						"service": h.Service, "ip": h.IP, "port": h.Port,
						"username": h.Username, "password": h.Password,
					})
				}
				aid, evErr := t.recordScanEvidence("zombie_weakpass",
					fmt.Sprintf("zombie_weakpass 命中 %d 条（含凭据明文，勿外传）", len(hits)),
					map[string]any{"tool": "zombie_weakpass", "at": time.Now().UTC(), "hits": full})
				if evErr != nil {
					// fail-closed：命中明细（含凭据明文）落不了证据时，宁可不产出——
					// 回显绝不降级为「无证据的命中清单」。
					return actool.Errorf(fmt.Sprintf("zombie_weakpass 命中 %d 条，但证据附件存储不可用（%v）——为守住「凭据不进 trace」纪律，本次不回显命中明细；请修复证据存储后重跑", len(hits), evErr)), nil
				}
				res["hits"] = zombieHitSummary(hits)
				res["evidence_artifact_id"] = aid
				res["note"] = "完整命中（含凭据明文）已落证据附件 artifact " + fmt.Sprint(aid) +
					"；本回显不含密码。凭据入资产图请走 insert_assets，不要把密码写进 fact/finding 明文"
			} else {
				res["note"] = "没有命中。先确认服务真实可达（gogo_scan 摸面），再考虑扩大字典"
			}
			return jsonResult(res)
		},
	)
}

func parseZombieTargets(ctx context.Context, raw json.RawMessage) ([]zombieTargetSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("target 不能为空")
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var one string
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			return nil, fmt.Errorf("target 应为字符串或字符串列表")
		}
		list = []string{one}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("target 至少要有一个")
	}
	if len(list) > 64 {
		return nil, fmt.Errorf("target 一次最多 64 个——分批跑")
	}
	out := make([]zombieTargetSpec, 0, len(list))
	seen := map[string]bool{}
	for _, r := range list {
		spec, err := parseZombieTarget(ctx, r)
		if err != nil {
			return nil, err
		}
		key := spec.Service + "://" + spec.IP + ":" + spec.Port + "@" + spec.Username + ":" + spec.Password
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, spec)
	}
	return out, nil
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func zombieModeLabel(sniperN, bruteN, usersN, pwdsN int) string {
	parts := make([]string, 0, 2)
	if sniperN > 0 {
		parts = append(parts, fmt.Sprintf("sniper(显式凭据)×%d", sniperN))
	}
	if bruteN > 0 {
		parts = append(parts, fmt.Sprintf("brute(%d 用户 × %d 密码)×%d 目标", usersN, pwdsN, bruteN))
	}
	return strings.Join(parts, " + ")
}

// zombieHitAddrs 命中的去重地址清单（不含凭据，粗粒度概览用）。
func zombieHitAddrs(hits []*sdktypes.ZombieResult) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if h == nil {
			continue
		}
		a := h.Service + "://" + h.IP + ":" + h.Port
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// zombieHitSummary 命中明细（密码打码——凭据明文只进 evidence，不进 trace）。
func zombieHitSummary(hits []*sdktypes.ZombieResult) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		if h == nil {
			continue
		}
		m := map[string]any{
			"service": h.Service, "ip": h.IP, "port": h.Port,
			"password": "***（见证据附件）",
		}
		if h.Username != "" {
			m["username"] = h.Username
		}
		out = append(out, m)
	}
	return out
}

// ---------- proton_secrets ----------

// protonBuiltinTemplateYAML 是 proton_secrets 的内置敏感信息规则集（nuclei 风格
// file 模板，SDK WithTemplateData 直接吃）。只内置高频高置信规则：云 AK、私钥、
// JWT、通用 key/secret/token 赋值形态。命中明细（提取值即凭据原文）只落 evidence。
const protonBuiltinTemplateYAML = `
- id: aws-access-key
  info:
    name: AWS Access Key
    severity: critical
    tags: cloud,aws,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: aws-akid
          regex:
            - "\\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\\b"

- id: private-key-block
  info:
    name: Private Key Block
    severity: critical
    tags: keys,tls
  file:
    - extensions:
        - all
      matchers:
        - type: word
          words:
            - "-----BEGIN RSA PRIVATE KEY"
            - "-----BEGIN EC PRIVATE KEY"
            - "-----BEGIN OPENSSH PRIVATE KEY"
            - "-----BEGIN PRIVATE KEY"
          condition: or

- id: jwt-token
  info:
    name: JWT Token
    severity: high
    tags: token,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: jwt
          regex:
            - "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"

- id: credential-assignment
  info:
    name: Credential Assignment (password/secret/api_key/token)
    severity: high
    tags: credential,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: cred-assign
          regex:
            - "(?i)\\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\\b['\\\"]?\\s*[:=]\\s*['\\\"]?[A-Za-z0-9+/_@#%^&*!?.~-]{6,}"

- id: bearer-token
  info:
    name: Bearer / Authorization Token
    severity: high
    tags: token,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: bearer
          regex:
            - "(?i)\\b(?:authorization|set-cookie)\\b['\\\"]?\\s*[:=]\\s*['\\\"]?(?:bearer|basic)\\s+[A-Za-z0-9+/_=.-]{16,}"

- id: google-api-key
  info:
    name: Google API Key
    severity: critical
    tags: cloud,google,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: google-key
          regex:
            - "\\bAIza[A-Za-z0-9_-]{35}\\b"

- id: slack-token
  info:
    name: Slack Token
    severity: critical
    tags: cloud,slack,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: slack-token
          regex:
            - "\\bxo[xbap]-[A-Za-z0-9-]{10,}\\b"

- id: generic-hex-secret
  info:
    name: Generic Hex Secret Assignment
    severity: medium
    tags: credential,keys
  file:
    - extensions:
        - all
      extractors:
        - type: regex
          name: hex-secret
          regex:
            - "(?i)\\b(?:secret|token|key)\\b['\\\"]?\\s*[:=]\\s*['\\\"]?[a-f0-9]{32,64}\\b"
`

// maxProtonInputBytes 是单次扫描输入上限（与证据附件单文件 20MB 上限一致）。
const maxProtonInputBytes = 20 << 20

// protonSecrets 敏感信息扫描（强动作 per §5.5，ask 审批门在拦截规则 seed v6）。
func (t *ToolSet) protonSecrets() actool.CoreTool {
	return writeTool(
		"proton_secrets",
		"扫描文本或文件中的【敏感信息】（API key / token / 凭据 / 私钥，proton 内核进程内执行，需要 ask 审批）。"+
			"参数：data（待检文本）或 file（文件路径）二选一必填。"+
			"返回只有规则类型统计 + 命中条数 + 证据附件 id——命中明细（含 secret 原文）自动落证据附件，不进对话；"+
			"需要查看明细时用工作目录里的证据文件或 list_artifacts 定位。"+
			"适合：拿到源码/配置/备份文件后快速定位硬编码凭据；响应内容里找泄漏的 token。",
		obj(map[string]any{
			"data": str("待检文本（与 file 二选一）"),
			"file": str("待检文件路径（与 data 二选一；只支持单个普通文件）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			eng, err := protonSecretsEngine()
			if err != nil {
				return actool.Errorf("proton_secrets 未启用: 引擎初始化失败: " + err.Error()), nil
			}
			var a struct {
				Data string `json:"data"`
				File string `json:"file"`
			}
			_ = json.Unmarshal(in, &a)
			var payload []byte
			var label string
			switch {
			case strings.TrimSpace(a.File) != "":
				f := strings.TrimSpace(a.File)
				info, statErr := os.Stat(f)
				if statErr != nil {
					return actool.Errorf("file 不可读: " + statErr.Error()), nil
				}
				if !info.Mode().IsRegular() {
					return actool.Errorf("file 只支持单个普通文件（目录请先在 Bash 里筛选/打包）"), nil
				}
				if info.Size() > maxProtonInputBytes {
					return actool.Errorf(fmt.Sprintf("file 超过单次扫描上限（%d MB）——先在 Bash 里切分", maxProtonInputBytes>>20)), nil
				}
				payload, err = os.ReadFile(f)
				if err != nil {
					return actool.Errorf("file 读取失败: " + err.Error()), nil
				}
				label = filepath.Base(f)
			case strings.TrimSpace(a.Data) != "":
				payload = []byte(a.Data)
				label = "input-text"
			default:
				return actool.Errorf("data 与 file 必须二选一"), nil
			}
			findings := eng.ScanData(payload, label)
			// 类型统计（命中明细不回显——secret 原文只进证据附件）。
			byType := map[string]int{}
			order := make([]string, 0, 8)
			for _, f := range findings {
				if _, ok := byType[f.TemplateID]; !ok {
					order = append(order, f.TemplateID)
				}
				byType[f.TemplateID]++
			}
			sort.Strings(order)
			summary := make([]map[string]any, 0, len(order))
			names, severities := protonRuleMeta(eng, order)
			for _, id := range order {
				summary = append(summary, map[string]any{
					"template_id": id,
					"name":        names[id],
					"severity":    severities[id],
					"count":       byType[id],
				})
			}
			res := map[string]any{
				"label":   label,
				"count":   len(findings),
				"by_type": summary,
			}
			if len(findings) == 0 {
				res["note"] = "没有命中内置规则（云 AK/私钥/JWT/凭据赋值等）。规则集是高置信子集，不排除人工翻查仍有发现"
				return jsonResult(res)
			}
			// 完整命中（events.value 即提取到的 secret 原文）落证据附件。
			aid, evErr := t.recordScanEvidence("proton_secrets",
				fmt.Sprintf("proton_secrets 命中 %d 条（含凭据原文，勿外传）", len(findings)),
				map[string]any{"tool": "proton_secrets", "at": time.Now().UTC(), "label": label, "findings": findings})
			if evErr != nil {
				// fail-closed：命中明细（含 secret 原文）落不了证据时，宁可不产出。
				return actool.Errorf(fmt.Sprintf("proton_secrets 命中 %d 条，但证据附件存储不可用（%v）——为守住「凭据不进 trace」纪律，本次不回显命中明细；请修复证据存储后重跑", len(findings), evErr)), nil
			}
			res["evidence_artifact_id"] = aid
			res["note"] = "命中明细（含 secret 原文）已落证据附件 artifact " + fmt.Sprint(aid) +
				"；确认的凭据用 insert_assets 登记为资产、不要把明文写进 fact/finding"
			return jsonResult(res)
		},
	)
}

// protonRuleMeta 从引擎已加载规则里取 id → 名称/严重级（统计展示用）。
func protonRuleMeta(eng *sdkproton.Engine, ids []string) (names, severities map[string]string) {
	names = map[string]string{}
	severities = map[string]string{}
	if eng == nil || eng.Scanner() == nil {
		return names, severities
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for _, g := range eng.Scanner().Groups {
		for _, ref := range g.Templates() {
			if want[ref.ID] {
				names[ref.ID] = ref.Name
				severities[ref.ID] = ref.Severity
			}
		}
	}
	return names, severities
}
