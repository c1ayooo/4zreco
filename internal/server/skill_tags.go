package server

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// skill 的标准化标签（CWE / ATT&CK / 类别）。
//
// ## 为什么需要标签
//
// 没有标签的 skill 是「孤岛」：不能按 CWE 检索「这类漏洞我们有没有方法论」、
// 不能统计覆盖度（能力矩阵）、任务来了也不能按标签匹配 skill——只能靠模型
// 记住每个 skill 的描述。这是与开源同类对比（docs/漏洞挖掘能力对比.md）里
// 从 Anthropic-Cybersecurity-Skills（818 个 skill 全部带框架标签）学来的机制。
//
// ## 标签格式（SKILL.md frontmatter）
//
//	---
//	name: vuln-hunting
//	description: ...
//	tags:
//	  cwe: [CWE-269, CWE-862]        # MITRE CWE 编号
//	  attack: [T1190]                 # MITRE ATT&CK 技术编号
//	  class: [authz, idor, race]      # 自定义类别（小写连字符）
//	---
//
// norma 的 skill.LoadDir 不认识 tags 字段——但 yaml.Unmarshal 默认忽略未知
// 字段，所以加了标签的 SKILL.md 对 norma 完全透明（db 的
// TestShippedSkillsLoadWithNormaLoader 守着这一点）。
// 4ZRECO 自己解析标签：本文件的 ParseSkillTags。
//
// ## 三类标签各自的用途
//
//   - cwe：与漏洞情报联动——CVE/GHSA 条目带 CWE 编号，按号匹配方法论。
//     （GHSA 的 cwes 字段已在 vulnintel/ghsa.go 解析。）
//   - attack：与杀伤链阶段对齐——T1190（利用面向公众的应用）这类编号
//     是跨工具通用的语言。
//   - class：平台内部类别——按「越权/可枚举/竞态」这种平台自己的概念
//     组织，比 CWE 更贴近 vuln-hunting 七维度的语言。

// SkillTags 是一个 skill 的标准化标签。
type SkillTags struct {
	// CWE 是 MITRE CWE 编号列表（大写规范化：CWE-269）。
	CWE []string `json:"cwe,omitempty"`
	// Attack 是 MITRE ATT&CK 技术编号列表（大写规范化：T1190）。
	Attack []string `json:"attack,omitempty"`
	// Class 是平台内部类别列表（小写规范化：authz / idor / race）。
	Class []string `json:"class,omitempty"`
}

// Empty 报告是否一个标签都没有。
func (t SkillTags) Empty() bool {
	return len(t.CWE) == 0 && len(t.Attack) == 0 && len(t.Class) == 0
}

// MatchesCWE 报告该 skill 是否覆盖给定的 CWE 编号（大小写不敏感）。
func (t SkillTags) MatchesCWE(cwe string) bool {
	want := strings.ToUpper(strings.TrimSpace(cwe))
	if want == "" {
		return false
	}
	for _, c := range t.CWE {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

// skillTagFrontmatter 只声明 tags 相关字段；yaml.Unmarshal 忽略其余字段，
// frontmatter 里其它键（name/description/allowed-tools…）不会被这里碰。
type skillTagFrontmatter struct {
	Tags struct {
		CWE    []string `yaml:"cwe"`
		Attack []string `yaml:"attack"`
		Class  []string `yaml:"class"`
	} `yaml:"tags"`
}

// ParseSkillTags 从一个 SKILL.md 里解析标签。
//
// 没有标签 / frontmatter 损坏 → 返回空 SkillTags（不是错误）：
// 标签是可选元数据，缺标签的 skill 照样合法（第三方上传的 skill 就常没有）。
func ParseSkillTags(path string) SkillTags {
	var out SkillTags
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	head, ok := frontmatterHead(string(data))
	if !ok {
		return out
	}
	var fm skillTagFrontmatter
	if err := yaml.Unmarshal([]byte(head), &fm); err != nil {
		return out // frontmatter 不是合法 YAML → 没标签
	}
	out.CWE = normalizeUpper(fm.Tags.CWE)
	out.Attack = normalizeUpper(fm.Tags.Attack)
	out.Class = normalizeLower(fm.Tags.Class)
	return out
}

// LoadSkillTags 解析整个 skills 目录下所有 skill 的标签。
//
// 返回 dirName → tags（与 agent_skill_visibility 的绑定键一致——按目录名，
// 不是 frontmatter 的 name）。读目录失败返回空 map：标签装饰不该让
// skill 列表整体失败。
func LoadSkillTags(dir string) map[string]SkillTags {
	out := map[string]SkillTags{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "SKILL.md")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if tags := ParseSkillTags(p); !tags.Empty() {
			out[e.Name()] = tags
		}
	}
	return out
}

// BuildCweSkillIndex 构建 CWE 编号 → skill 目录名 的倒排索引。
//
// 用途：server 启动时注入 agent 的漏洞情报工具（agent.SetCweSkillIndex），
// search_vulns / get_vuln 命中带 CWE 的条目时提示对应的方法论 skill——
// 「查到 CVE → 自动提示对应方法论 skill」联动（能力对比 M1）的最后一环。
// 读目录失败返回空 map：联动缺失只是没有提示，不该让启动失败。
func BuildCweSkillIndex(dir string) map[string][]string {
	out := map[string][]string{}
	for name, t := range LoadSkillTags(dir) {
		for _, c := range t.CWE {
			out[c] = append(out[c], name)
		}
	}
	return out
}

// frontmatterHead 提取 SKILL.md 开头的 YAML frontmatter（--- 与 --- 之间）。
//
// 与 norma skill.parse 的边界判定一致（找 "\n---"），保证两边对同一文件的
// 理解不会漂移。
func frontmatterHead(s string) (string, bool) {
	if !strings.HasPrefix(s, "---") {
		return "", false
	}
	rest := strings.TrimLeft(strings.TrimPrefix(s, "---"), "\r\n")
	i := strings.Index(rest, "\n---")
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// normalizeUpper 规范化为大写并去空白（CWE-269 / T1190 都是大写习惯）。
func normalizeUpper(in []string) []string {
	return normalizeTags(in, strings.ToUpper)
}

// normalizeLower 规范化为小写并去空白（class 用小写连字符习惯）。
func normalizeLower(in []string) []string {
	return normalizeTags(in, strings.ToLower)
}

func normalizeTags(in []string, conv func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(conv(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
