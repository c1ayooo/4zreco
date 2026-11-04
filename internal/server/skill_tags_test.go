package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// 标签解析：标准 frontmatter 形态。
func TestParseSkillTags(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "SKILL.md")
	content := `---
name: demo
description: 测试用
tags:
  cwe: [cwe-269, CWE-862, " cwe-639 "]
  attack: [t1190, T1210]
  class: [Authz, IDOR]
---
# body
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tags := ParseSkillTags(p)
	if len(tags.CWE) != 3 {
		t.Fatalf("应解析出 3 个 CWE，实际 %v", tags.CWE)
	}
	// 大小写规范化：CWE 用大写习惯。
	for _, want := range []string{"CWE-269", "CWE-862", "CWE-639"} {
		found := false
		for _, c := range tags.CWE {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("应含规范化后的 %s，实际 %v", want, tags.CWE)
		}
	}
	// ATT&CK 也大写。
	if tags.Attack[0] != "T1190" || tags.Attack[1] != "T1210" {
		t.Errorf("ATT&CK 应大写规范化，实际 %v", tags.Attack)
	}
	// class 小写习惯。
	if tags.Class[0] != "authz" || tags.Class[1] != "idor" {
		t.Errorf("class 应小写规范化，实际 %v", tags.Class)
	}
	if tags.Empty() {
		t.Error("有标签不该判空")
	}
	// 按号匹配（大小写不敏感）。
	if !tags.MatchesCWE("cwe-269") {
		t.Error("MatchesCWE 应大小写不敏感")
	}
	if tags.MatchesCWE("CWE-0000") {
		t.Error("不存在的 CWE 不该匹配")
	}
}

// 没有标签 / frontmatter 损坏 → 空标签（不是错误）。
//
// 第三方上传的 skill 常没有标签——标签是可选元数据。
func TestParseSkillTagsOptional(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"无标签": "---\nname: a\ndescription: x\n---\nbody",
		"无 frontmatter":  "# just a body",
		"损坏的 YAML":     "---\nname: [broken\n---\nbody",
		"文件不存在":         "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "SKILL.md")
			if content != "" {
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = os.Remove(p)
			}
			tags := ParseSkillTags(p)
			if !tags.Empty() {
				t.Errorf("应返回空标签，实际 %+v", tags)
			}
		})
	}
}

// LoadSkillTags 解析整个目录，键是**目录名**（与 agent_skill_visibility
// 的绑定键一致——不是 frontmatter 的 name）。
func TestLoadSkillTagsKeysByDirName(t *testing.T) {
	dir := t.TempDir()
	// 故意让 frontmatter name 与目录名不同——绑定键必须是目录名。
	if err := os.MkdirAll(filepath.Join(dir, "my-skill"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "my-skill", "SKILL.md"), []byte(
		"---\nname: totally-different-name\ntags:\n  class: [demo]\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 没 SKILL.md 的目录不产生条目。
	if err := os.MkdirAll(filepath.Join(dir, "no-skill-md"), 0o755); err != nil {
		t.Fatal(err)
	}
	tags := LoadSkillTags(dir)
	if _, ok := tags["my-skill"]; !ok {
		t.Fatalf("键应为目录名 my-skill，实际 %v", tags)
	}
	if _, ok := tags["totally-different-name"]; ok {
		t.Error("不该用 frontmatter name 做键")
	}
	if _, ok := tags["no-skill-md"]; ok {
		t.Error("没 SKILL.md 的目录不该有条目")
	}
}

// **守门测试**：打了标签的 skill 必须仍被 norma 正常加载。
//
// 这是标签机制的安全前提：norma 的 frontmatter 解析忽略未知字段，所以
// tags 不会破坏 skill 加载。但「不会破坏」是靠这条测试守着的——
// 升级 norma 或改 SKILL.md 格式时，这里先红。
func TestTaggedSkillsStillLoadWithNorma(t *testing.T) {
	// 找仓库里的 skills 目录（与本测试文件同级的 ../skills）。
	skillDir := filepath.Join("..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skip("找不到 skills 目录（可能不是从仓库根跑的测试）")
	}
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]bool{}
	for _, s := range reg.List() {
		loaded[s.Name] = true
		if s.Description == "" {
			t.Errorf("skill %s 加载后 description 为空——frontmatter 可能被 tags 破坏", s.Name)
		}
	}
	// 四个内置 skill 都要加载成功。
	for _, name := range []string{"vuln-hunting", "api-recon", "scopesentry-mcp"} {
		if !loaded[name] {
			t.Errorf("打了标签的 skill %s 未被 norma 加载", name)
		}
	}
}

// 内置 skill 的标签内容要有实质覆盖（能力矩阵的起点）。
//
// 这条测试同时守住「标签真的写进去了」——SKILL.md 手工编辑时漏掉
// tags 块，这里会红。
func TestShippedSkillsHaveSubstantiveTags(t *testing.T) {
	skillDir := filepath.Join("..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skip("找不到 skills 目录")
	}
	tags := LoadSkillTags(skillDir)
	vh, ok := tags["vuln-hunting"]
	if !ok {
		t.Fatal("vuln-hunting 应有标签")
	}
	// 越权/IDOR/竞态是七维度方法论的核心，CWE 标签必须覆盖。
	for _, want := range []string{"CWE-269", "CWE-862", "CWE-639", "CWE-362"} {
		if !vh.MatchesCWE(want) {
			t.Errorf("vuln-hunting 应覆盖 %s（越权/鉴权/IDOR/竞态的核心 CWE），实际 %v", want, vh.CWE)
		}
	}
	if len(vh.Class) < 4 {
		t.Errorf("vuln-hunting 的 class 标签应覆盖至少 4 个维度，实际 %v", vh.Class)
	}
	if ar, ok := tags["api-recon"]; !ok || len(ar.Class) == 0 {
		t.Error("api-recon 应有 class 标签")
	}
}

// BuildCweSkillIndex 的倒排形态：同一个 skill 的多个 CWE 各自成键；
// 无标签目录不进索引；空目录返回空 map 而不是 nil 的行为差异不重要，
// 重要的是「读失败不该 panic」（联动缺失只是没有提示）。
func TestBuildCweSkillIndex(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, cwes string) {
		t.Helper()
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + name + "\ndescription: test\n"
		if cwes != "" {
			body += "tags:\n  cwe: [" + cwes + "]\n"
		}
		body += "---\n\nbody\n"
		if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("authz-skill", "CWE-862, CWE-639")
	mk("inj-skill", "CWE-89")
	mk("untagged", "")

	idx := BuildCweSkillIndex(dir)
	if got := idx["CWE-862"]; len(got) != 1 || got[0] != "authz-skill" {
		t.Fatalf("CWE-862 → %v，应为 [authz-skill]", got)
	}
	if got := idx["CWE-89"]; len(got) != 1 || got[0] != "inj-skill" {
		t.Fatalf("CWE-89 → %v，应为 [inj-skill]", got)
	}
	if _, ok := idx["CWE-999"]; ok {
		t.Fatal("无命中的 CWE 不应出现在索引里")
	}
}
