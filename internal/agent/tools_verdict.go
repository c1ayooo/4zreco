package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
	"github.com/c1ayooo/4zreco/internal/pocparse"
	"github.com/c1ayooo/4zreco/internal/verdict"
)

// assessNucleiHit 用确定性规则判定一条扫描命中「证据够不够独立成立」（第三批 J2，
// 移植自 Jingwei v1.6.5 `verdict`）。
//
// 为什么要它：模板命中 ≠ 漏洞。只匹配状态码的模板、5xx、没有响应正文的命中，
// 单独拿出来都可能被误报成 finding——而"误报一条 critical"对交付质量的伤害远大于
// 漏报一条 needs_review。本工具把上游的判定口径搬进对话：给出 confirmed /
// needs_review 与按类的复核清单，让 worker 在 report_finding 前先过一道统一标准。
//
// 语义边界：**只判证据强度，不替你上报**；判定 never downgrades（无证据 ≠ 无漏洞），
// 弱证据一律 needs_review 并把缺什么写清楚。不写库、不改 finding。
func (t *ToolSet) assessNucleiHit() actool.CoreTool {
	return readTool(
		"assess_nuclei_hit",
		"判定一条 nuclei 扫描命中的证据强度，返回 confirmed / needs_review + 类别 + 理由 + 复核清单。"+
			"在 report_finding 之前用：模板命中不等于漏洞——只匹配状态码、5xx、没有响应正文、"+
			"XSS 没给反射位置、信息泄露响应过短，都会被判 needs_review 并列出还缺什么证据。"+
			"模板信息给 path（nuclei-templates 树内）或 content，或直接给 template_id+name+tags；"+
			"命中的 status_code/response/extracted 从 parse_nuclei_output 的结果里取。",
		obj(map[string]any{
			"path":        str("模板路径（相对 nuclei-templates 根的相对路径或树内绝对路径，.yaml/.yml）"),
			"content":     str("模板 YAML 原文（与 path 二选一；两者都不给则按 template_id/name/tags 判定）"),
			"template_id": str("模板 ID（信息或模板都给时以模板解析结果为准）"),
			"name":        str("模板名称"),
			"tags":        str("模板 tags，逗号分隔（用于漏洞类目识别）"),
			"type":        str("命中类型：http / network / dns 等（缺省按 http 处理）"),
			"status_code": intp("命中的 HTTP 状态码（0 = 未知）"),
			"response":    str("命中的响应正文片段（网页类命中必须给，否则判 needs_review）"),
			"extracted":   str("模板提取到的证据，逗号分隔（XSS/仅状态码模板需要）"),
			"matched_at":  str("命中地址（可选，仅回显）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path       string `json:"path"`
				Content    string `json:"content"`
				TemplateID string `json:"template_id"`
				Name       string `json:"name"`
				Tags       string `json:"tags"`
				Type       string `json:"type"`
				StatusCode int    `json:"status_code"`
				Response   string `json:"response"`
				Extracted  string `json:"extracted"`
				MatchedAt  string `json:"matched_at"`
			}
			_ = json.Unmarshal(in, &a)

			obs := verdict.Observation{
				TemplateID: strings.TrimSpace(a.TemplateID),
				Name:       strings.TrimSpace(a.Name),
				Tags:       splitCommaList(a.Tags),
				Type:       strings.TrimSpace(a.Type),
				StatusCode: a.StatusCode,
				Response:   a.Response,
				Extracted:  splitCommaList(a.Extracted),
				MatchedAt:  strings.TrimSpace(a.MatchedAt),
			}

			// 模板来源：path/content 优先——模板里的 id/name/tags 与 matcher 画像
			// 都比模型口述更权威；模板只用来补空字段，不覆盖显式给的值。
			if strings.TrimSpace(a.Path) != "" || strings.TrimSpace(a.Content) != "" {
				raw, _, err := pocTemplateContent(a.Path, a.Content)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				tpl, err := pocparse.Parse(raw, "")
				if err != nil {
					return actool.Errorf("解析模板失败: " + err.Error()), nil
				}
				if obs.TemplateID == "" {
					obs.TemplateID = tpl.TemplateID
				}
				if obs.Name == "" {
					obs.Name = tpl.Name
				}
				if len(obs.Tags) == 0 {
					obs.Tags = tpl.Tags
				}
				obs.Matcher = verdict.ParseMatcherProfile(tpl.Content)
			} else if obs.TemplateID == "" && obs.Name == "" {
				return actool.Errorf("至少给模板 path/content，或 template_id/name 之一"), nil
			}

			d := verdict.Assess(obs)
			res := map[string]any{
				"verdict":             d.Verdict,
				"needs_manual_review": d.NeedsManualReview(),
				"class":               d.Class,
				"reasons":             d.Reasons,
				"checks":              d.Checks,
				"template_id":         obs.TemplateID,
				"matched_at":          obs.MatchedAt,
				"note":                "本工具只判证据强度，不替你上报：needs_review 时按 checks 补齐证据再决定是否 report_finding；confirmed 也只代表「证据自身成立」，上报时仍要写清复现方式。",
			}
			if obs.Matcher != nil {
				res["matcher_profile"] = map[string]any{
					"status_only": obs.Matcher.StatusOnly,
					"has_status":  obs.Matcher.HasStatus,
					"has_word":    obs.Matcher.HasWord,
					"has_regex":   obs.Matcher.HasRegex,
					"has_dsl":     obs.Matcher.HasDSL,
					"has_other":   obs.Matcher.HasOther,
				}
			}
			return jsonResult(res)
		},
	)
}

// splitCommaList 把 "a,b , c" 拆成去空去重的列表（tags/extracted 共用）。
func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
