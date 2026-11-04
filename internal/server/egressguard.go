package server

// 出口敏感信息审查的指纹装配（引擎在 guard/egressguard.go）。EgressGuard 是进程级
// 单例（Manager.egress），每个任务的 Guard 在 taskFromPG 里通过 SetEgress 引用同一份
// ——所以这里只需在「启动」与「LLM profile 变更」（reapplyActiveProfile 是唯一漏斗）
// 时向这一份注册/替换指纹，所有任务（含已存在的）即时生效，无需逐任务注入。
// 注册只存哈希（见 guard/egressguard.go），本文件是原文唯一出现的地方，不日志、不落盘。

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/c1ayooo/4zreco/internal/config"
)

// registerEgressFingerprints 把当前平台敏感信息注册进共享 EgressGuard：
// 全部 LLM profile 的 API key（变更时整体替换）、jwt.key（原文/hex/base64 三种
// 文本形态）、PG DSN 中的密码、settings 里的第三方服务 key。幂等：重复调用不
// 产生重复指纹（guard.AddFingerprint 内部去重）。
func (s *Server) registerEgressFingerprints() {
	if s.m == nil || s.m.egress == nil {
		return
	}
	eg := s.m.egress
	// 全部 LLM profile 的 API key：profile 可能换 key/增删，先整类摘掉再注册当前值
	// （不只有激活那个——任务链可绑定任意 profile，谁的 key 都不能外发）。
	eg.RemoveKind("llm_api_key")
	if s.m.pg != nil {
		rows, err := s.m.pg.Query(`SELECT COALESCE(api_key,'') FROM llm_profiles WHERE COALESCE(api_key,'') <> ''`)
		if err == nil {
			for rows.Next() {
				var key string
				if rows.Scan(&key) == nil {
					eg.AddFingerprint("llm_api_key", key)
				}
			}
			rows.Close()
		}
	}
	// jwt.key：32 字节签名密钥，出现在命令文本里通常是原文/hex/base64 之一。
	if key, ok := s.jwtKey.Load().([]byte); ok && len(key) > 0 {
		eg.AddFingerprint("jwt_key", string(key))
		eg.AddFingerprint("jwt_key", hex.EncodeToString(key))
		eg.AddFingerprint("jwt_key", base64.StdEncoding.EncodeToString(key))
	}
	// PG DSN 中的密码（env ZRECO_PG_DSN 或 config.json，与启动解析同一来源）。
	if dsn, _, err := config.PostgresDSN(); err == nil {
		eg.AddFingerprint("pg_password", dsnPassword(dsn))
	}
	// settings 里的第三方服务 key：泄漏同样可被消耗/溯源。
	if s.m.pg != nil {
		for _, key := range []string{settingNvdApiKey, settingBraveKey, settingTavilyKey} {
			if v, _, err := s.m.pg.GetSetting(key); err == nil && strings.TrimSpace(v) != "" {
				eg.AddFingerprint(key, strings.TrimSpace(v))
			}
		}
	}
}

// dsnPassword 从 DSN 里取密码：兼容 URL 形态（postgres://user:pass@host/db）
// 与 keyword 形态（host=... password=...）。取不到返回空串（注册方会跳过）。
func dsnPassword(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			return pw
		}
	}
	if m := reKeywordPassword.FindStringSubmatch(dsn); m != nil {
		return strings.Trim(m[1], "'")
	}
	return ""
}

// reKeywordPassword 匹配 keyword 形态 DSN 的 password 段（值可单引号包裹）。
var reKeywordPassword = regexp.MustCompile(`(?:^|\s)password=('[^']*'|[^\s]+)`)
