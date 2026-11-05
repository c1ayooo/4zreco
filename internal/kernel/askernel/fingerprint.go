package askernel

// fingerprint.go — the runner assembly fingerprint (方案 §4-P1 第 8 条):
//
//	sha256(agentKey, promptVersion, toolset_snapshot_hash, unlock_seed,
//	       mcp_connection_digest, model_profile)
//
// 工具面是 DB 实时解析的（ToolAugment/ToolResolve + agent_visibility），skill 会
// 中途解锁，MCP 会重连——只按 (task, agentKey) 重建 runner 会得到与中断时不同的
// 工具面，checkpoint 里记录的 tool_call 在恢复的 ToolsNode 里找不到。P2 的恢复
// 校验按指纹拒绝不匹配的 resume（P2-6 回退）。
//
// 覆盖口径（定案）：只覆盖「工具名集合 + schema hash + 解锁集种子」；
// MCP 连接的临时状态（连接句柄、存活探针）不进指纹——MCP 断连由工具级错误表达，
// 不让指纹漂移吞掉恢复。promptVersion 随 SeedPromptVersioned 下发，装配即快照。
//
// 本刀建表落库（runner_checkpoints），P2 消费；驱动侧每个主 run 装配时写一行。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// Fingerprint computes the runner assembly fingerprint over its six canonical
// components. The join is length-prefixed per component so no delimiter
// ambiguity can merge two fields into one.
func Fingerprint(agentKey, promptVersion, toolsetSnapshotHash, unlockSeed, mcpConnectionDigest, modelProfile string) string {
	h := sha256.New()
	for _, part := range []string{agentKey, promptVersion, toolsetSnapshotHash, unlockSeed, mcpConnectionDigest, modelProfile} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ToolsetSnapshotHash hashes the tool NAME SET + input-schema hash over the
// tool list in registration order (the same order ToEinoTools binds and
// ToolGate.Managed returns — the order is the snapshot's spine).
func ToolsetSnapshotHash(tools []actool.CoreTool) string {
	h := sha256.New()
	for _, t := range tools {
		name := t.Name()
		fmt.Fprintf(h, "%d:%s\n", len(name), name)
		schemaJSON := canonicalSchemaJSON(t.InputSchema())
		fmt.Fprintf(h, "%d:%s\n", len(schemaJSON), schemaJSON)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// UnlockSeed renders the unlock set's seed as a stable string: sorted names
// joined with "," (empty set = ""). The host supplies the seed it built the
// set from (actool.UnlockSet does not enumerate), keeping the fingerprint a
// pure function of assembly inputs.
func UnlockSeed(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// canonicalSchemaJSON serializes an input schema map deterministically
// (encoding/json sorts map keys, so the hash is stable across runs).
func canonicalSchemaJSON(schema map[string]any) string {
	if len(schema) == 0 {
		return ""
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		// A tool schema that cannot marshal cannot hash — surface it as a
		// distinct marker rather than silently dropping the tool from the
		// fingerprint (defensive; actool specs marshal in practice).
		return "!unmarshalable"
	}
	return string(raw)
}

// FingerprintOnSession computes the assembly fingerprint over this session's
// LIVE toolset (the registry order — kernel-added access tools, background-task
// tools and webfetch/websearch included — is the toolset a P2 resume must
// reconstruct). The remaining four components are assembly inputs the host
// knows; promptVersion/mcpDigest/modelProfile default "" until P2 wires their
// sources (SeedPromptVersioned / MCP 连接摘要 / 模型 profile 名).
func (s *Session) FingerprintOnSession(agentKey, promptVersion, unlockSeed, mcpDigest, modelProfile string) string {
	return Fingerprint(agentKey, promptVersion, ToolsetSnapshotHash(s.registry.List()), unlockSeed, mcpDigest, modelProfile)
}
