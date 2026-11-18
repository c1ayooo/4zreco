package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/c1ayooo/4zreco/internal/pocparse"
)

// pocTemplateMaxBytes 是模板读取上限：nuclei 模板正常 <10KB，2MB 足够覆盖
// 体积较大的 workflow 模板，同时把「误传大文件」挡在解析之前。
const pocTemplateMaxBytes = 2 << 20

// parsePocTemplate 把一份 nuclei YAML 模板解析成结构化字段（第三批 J1，
// 移植自 Jingwei v1.6.5 `pocparse`）。
//
// 为什么要它：scan_with_nuclei 只给「跑模板」的能力，worker 拿到一个模板路径时
// 无法快速判断它针对哪个 CVE/CWE、severity 是否值得跑、有哪些 tag——只能整段
// 读 YAML 再自己数。这里一次调用回紧凑结构化结论（含 sha256 digest 便于去重）。
//
// 安全边界：路径模式必须落在 `<Base>/nuclei-templates` 树内（解析真实路径后做
// 前缀校验，翻不出去也绕不过符号链接），只允许 .yaml/.yml 普通文件，读上限 2MB。
// 输出只回结构化字段，不回显模板正文以外的内容。
func (t *ToolSet) parsePocTemplate() actool.CoreTool {
	return readTool(
		"parse_poc_template",
		"解析一份 nuclei YAML 模板，返回结构化字段：id、name、severity（归一化 info/low/medium/high/critical）、"+
			"protocol（http/network/dns/headless/workflow…）、CVE/CWE、CVSS、tags、author、references 与 sha256 digest。"+
			"用来在 scan_with_nuclei 之前判断模板对应哪个漏洞、严重性是否值得跑、是否与已跑模板重复（按 digest）。"+
			"入参给 path（必须位于 nuclei-templates 树内，.yaml/.yml）或直接给 content，二选一。",
		obj(map[string]any{
			"path":        str("模板路径：相对 nuclei-templates 根的相对路径，或树内的绝对路径（须为 .yaml/.yml）"),
			"content":     str("直接给模板 YAML 原文（与 path 二选一；内容模式不做路径校验）"),
			"fallback_id": str("模板缺 id 时使用的标识（可选；缺省按 name 生成稳定 slug）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path       string `json:"path"`
				Content    string `json:"content"`
				FallbackID string `json:"fallback_id"`
			}
			_ = json.Unmarshal(in, &a)
			content, src, err := pocTemplateContent(a.Path, a.Content)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tpl, err := pocparse.Parse(content, a.FallbackID)
			if err != nil {
				return actool.Errorf("解析模板失败: " + err.Error()), nil
			}
			res := map[string]any{
				"source":      src,
				"template_id": tpl.TemplateID,
				"name":        tpl.Name,
				"severity":    tpl.Severity,
				"protocol":    tpl.Protocol,
				"cve_id":      tpl.CVEID,
				"cwe_id":      tpl.CWEID,
				"tags":        tpl.Tags,
				"author":      tpl.Author,
				"description": tpl.Description,
				"references":  tpl.References,
				"digest":      tpl.Digest,
				"bytes":       len(content),
			}
			if tpl.CVSSScore != nil {
				res["cvss_score"] = *tpl.CVSSScore
			} else {
				res["cvss_score"] = nil
			}
			return jsonResult(res)
		},
	)
}

// pocTemplateContent 决定取原文还是读文件，并落实路径边界。
func pocTemplateContent(path, content string) ([]byte, string, error) {
	path = strings.TrimSpace(path)
	content = strings.TrimSpace(content)
	if content != "" && path != "" {
		return nil, "", fmt.Errorf("path 与 content 只能给一个")
	}
	if content != "" {
		return []byte(content), "content", nil
	}
	if path == "" {
		return nil, "", fmt.Errorf("path 与 content 至少给一个")
	}
	root := strings.TrimSpace(nucleiTemplatesDir)
	if root == "" {
		return nil, "", fmt.Errorf("nuclei 模板树未就绪（与 scan_with_nuclei 同一前置：等待模板同步完成或改用 content 模式）")
	}
	// 相对路径按模板树根解析；绝对路径原样参与校验（越界即拒）。
	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	rel, err := pocTemplateRelPath(root, target)
	if err != nil {
		return nil, "", err
	}
	ext := strings.ToLower(filepath.Ext(rel))
	if ext != ".yaml" && ext != ".yml" {
		return nil, "", fmt.Errorf("只接受 .yaml/.yml 模板文件，得到 %q", rel)
	}
	abs, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, "", fmt.Errorf("模板文件不可读: %v", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, "", fmt.Errorf("模板文件不可读: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("模板路径不是普通文件: %s", rel)
	}
	if info.Size() > pocTemplateMaxBytes {
		return nil, "", fmt.Errorf("模板文件 %d 字节超过上限 %d（改用 content 模式分段处理）", info.Size(), pocTemplateMaxBytes)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, "", fmt.Errorf("读取模板失败: %v", err)
	}
	return data, rel, nil
}

// pocTemplateRelPath 校验 target 是否落在 root 树内，返回相对路径。
// 两侧都先 EvalSymlinks：词法前缀挡不住「树内符号链接指向树外」。
func pocTemplateRelPath(root, target string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("模板树路径非法: %v", err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("模板路径非法: %v", err)
	}
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("模板树不可用: %v", err)
	}
	// 目标文件可能尚不存在（报「不可读」比报「越界」更准确），先解析父目录再拼回。
	realTarget, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		parent, perr := filepath.EvalSymlinks(filepath.Dir(targetAbs))
		if perr != nil {
			return "", fmt.Errorf("模板路径不可用: %v", err)
		}
		realTarget = filepath.Join(parent, filepath.Base(targetAbs))
	}
	rel, err := filepath.Rel(realRoot, realTarget)
	if err != nil {
		return "", fmt.Errorf("模板路径越界: %s 不在 nuclei-templates 树内", target)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("模板路径越界: %s 不在 nuclei-templates 树内", target)
	}
	return rel, nil
}
