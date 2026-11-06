package askernel

// fingerprint 单测（方案 §4-P1 第 8 条）：六元组 sha256 的确定性与分量敏感性；
// 工具集快照只覆盖「工具名集合 + schema hash」且按注册序；解锁集种子排序稳定；
// 覆盖口径不含 MCP 临时状态（六元组里根本没有该入参的临时形态）。

import (
	"context"
	"encoding/json"
	"testing"

	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

func fpTool(t *testing.T, name, schemaRaw string) actool.CoreTool {
	t.Helper()
	var schema map[string]any
	if schemaRaw != "" {
		if err := json.Unmarshal([]byte(schemaRaw), &schema); err != nil {
			t.Fatalf("schema %s: %v", name, err)
		}
	}
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "fp " + name,
		Schema:      schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text(name + " ran"), nil
		},
	})
}

func TestFingerprintDeterministicAndComponentSensitive(t *testing.T) {
	base := Fingerprint("worker", "v1", "toolhash", "a,b", "mcpdigest", "profile-x")

	if again := Fingerprint("worker", "v1", "toolhash", "a,b", "mcpdigest", "profile-x"); again != base {
		t.Fatal("fingerprint must be deterministic")
	}
	// 表驱动：六个分量逐个扰动，指纹必须变；不加扰动必须不变。
	sens := []struct {
		name string
		mut  func() string
	}{
		{"agentKey", func() string { return Fingerprint("planner", "v1", "toolhash", "a,b", "mcpdigest", "profile-x") }},
		{"promptVersion", func() string { return Fingerprint("worker", "v2", "toolhash", "a,b", "mcpdigest", "profile-x") }},
		{"toolsetHash", func() string { return Fingerprint("worker", "v1", "toolhash2", "a,b", "mcpdigest", "profile-x") }},
		{"unlockSeed", func() string { return Fingerprint("worker", "v1", "toolhash", "a,c", "mcpdigest", "profile-x") }},
		{"mcpDigest", func() string { return Fingerprint("worker", "v1", "toolhash", "a,b", "mcpdigest2", "profile-x") }},
		{"modelProfile", func() string { return Fingerprint("worker", "v1", "toolhash", "a,b", "mcpdigest", "profile-y") }},
	}
	for _, c := range sens {
		t.Run(c.name+"_sensitive", func(t *testing.T) {
			if c.mut() == base {
				t.Fatalf("fingerprint insensitive to %s", c.name)
			}
		})
	}
}

// TestFingerprintDelimiterSafety: 分量以长度前缀拼接——分量里出现分隔符形态的
// 内容不会把两个字段折叠成一个。
func TestFingerprintDelimiterSafety(t *testing.T) {
	a := Fingerprint("worker", "v1:x", "", "", "", "")
	b := Fingerprint("worker:v1", "x", "", "", "", "")
	if a == b {
		t.Fatal("length-prefixed join must not merge components across fields")
	}
}

func TestToolsetSnapshotHashCoversNamesAndSchemasInOrder(t *testing.T) {
	ta := fpTool(t, "probe_a", `{"type":"object","properties":{"q":{"type":"string"}}}`)
	tb := fpTool(t, "probe_b", `{"type":"object"}`)

	h := ToolsetSnapshotHash([]actool.CoreTool{ta, tb})
	if again := ToolsetSnapshotHash([]actool.CoreTool{ta, tb}); again != h {
		t.Fatal("toolset hash must be deterministic")
	}
	// 顺序敏感（注册序 = ToEinoTools 绑定序 = 指纹的脊柱）。
	if swapped := ToolsetSnapshotHash([]actool.CoreTool{tb, ta}); swapped == h {
		t.Fatal("toolset hash must be order-sensitive")
	}
	// schema 敏感：同名工具、不同 schema → 指纹变（P2 恢复时工具面漂移要被拒）。
	taAlt := fpTool(t, "probe_a", `{"type":"object","properties":{"q":{"type":"integer"}}}`)
	if alt := ToolsetSnapshotHash([]actool.CoreTool{taAlt, tb}); alt == h {
		t.Fatal("toolset hash must be schema-sensitive")
	}
	// 名字敏感。
	if renamed := ToolsetSnapshotHash([]actool.CoreTool{fpTool(t, "probe_z", `{"type":"object","properties":{"q":{"type":"string"}}}`), tb}); renamed == h {
		t.Fatal("toolset hash must be name-sensitive")
	}
	// 空集合法且稳定。
	if ToolsetSnapshotHash(nil) != ToolsetSnapshotHash([]actool.CoreTool{}) {
		t.Fatal("empty toolset hash must be stable")
	}
}

func TestUnlockSeedSortedAndStable(t *testing.T) {
	if got := UnlockSeed([]string{"mcp__b__t", "mcp__a__t"}); got != "mcp__a__t,mcp__b__t" {
		t.Fatalf("UnlockSeed = %q, want sorted join", got)
	}
	if UnlockSeed(nil) != "" {
		t.Fatal("empty seed must render as empty string")
	}
}

// TestFingerprintOnSessionUsesLiveRegistry: 会话级指纹覆盖内核加进注册表的
// 访问工具/后台任务工具/延迟工具（P2 恢复必须重建出同一个工具面）。
func TestFingerprintOnSessionUsesLiveRegistry(t *testing.T) {
	mk := func() *Session {
		return NewSession(Options{
			SystemPrompt:  []string{"fp session"},
			DeferredTools: []string{"mcp__s__locked"},
			Todos:         actool.NewTodoStore(),
		})
	}
	s1, s2 := mk(), mk()
	defer func() { _ = s1.Close(); _ = s2.Close() }()

	f1 := s1.FingerprintOnSession("worker", "v1", "seed", "mcp", "profile")
	f2 := s2.FingerprintOnSession("worker", "v1", "seed", "mcp", "profile")
	if f1 == "" || f1 != f2 {
		t.Fatalf("session fingerprint must be deterministic across assemblies: %q vs %q", f1, f2)
	}
	// 与手算一致：注册表（含延迟访问工具 + 后台任务工具 + TodoWrite）参与快照。
	if manual := Fingerprint("worker", "v1", ToolsetSnapshotHash(s1.registry.List()), "seed", "mcp", "profile"); manual != f1 {
		t.Fatal("FingerprintOnSession must hash the live registry")
	}
}
