package agent

import (
	"fmt"
	"strings"
)

// ═══ 上游 0.4.63：fact/intelligence/finding 写回的 asset_ids 锚定校验 ═══
//
// 写回锚定只允许「自有范围」资产：
//
//	own    ：匹配本任务自己的 scope，或本任务发现/登记（task_ids 含本任务）→ 放行；
//	source ：只匹配来源/继承任务的 scope → 拒绝（继承范围只读；确属授权时
//	         用 add_task_scope 显式纳入本任务范围）；
//	foreign：完全越界 → 一律拒绝。
//
// 返回空串表示放行；非空是给模型的中文纠正提示（含资产标签，便于它自己纠正）。
// 分类查询失败 fail-open（返回空串）——校验故障不能把正常任务全部卡死，由调用方
// 打日志兜底。与上游差异：上游经 scope_write_guard / scope_inherit_writes 两个
// settings 开关灰度；4zreco 直接常开（fail-open 已兜底故障面），不留继承写开关。
func (t *ToolSet) scopeGuardError(taskID int64, ids []int64) string {
	if t.as == nil || taskID <= 0 || len(ids) == 0 {
		return ""
	}
	own, source, foreign, err := t.as.ClassifyAssetsForTask(taskID, ids)
	if err != nil {
		return "" // fail-open：分类查询故障不阻断正常任务
	}
	_ = own
	if len(source) == 0 && len(foreign) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("范围守卫：以下资产不属于本任务自有范围，禁止锚定/写回：")
	if len(source) > 0 {
		b.WriteString(fmt.Sprintf("\n· 来源/继承任务范围（只读，不可锚定）：%s", t.scopeAssetLabels(source)))
	}
	if len(foreign) > 0 {
		b.WriteString(fmt.Sprintf("\n· 完全越界：%s", t.scopeAssetLabels(foreign)))
	}
	b.WriteString("\n处理方式（二选一）：① 把本条结论的 asset_ids 改成自有范围资产，或删掉 asset_ids 让系统只记结论本身；" +
		"② 若该资产确在本任务授权内，先用 add_task_scope 显式纳入本任务范围后重试。" +
		"跨域名归属类结论必须先在两个域各自取证复核（本域复验 200/内容一致），未复核一律按 inferred 写，不得标 observed。")
	return b.String()
}

// scopeAssetLabels renders up to 6 assets as "#id 名称" for the guard message.
func (t *ToolSet) scopeAssetLabels(ids []int64) string {
	assets, err := t.as.GetByIDs(ids)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(assets))
	for i, a := range assets {
		if a == nil {
			continue
		}
		name := a.Domain
		if name == "" {
			name = a.URL
		}
		if name == "" {
			name = a.IP
		}
		if name == "" {
			name = a.AppName
		}
		if name == "" {
			name = a.RootDomain
		}
		if i >= 6 {
			parts = append(parts, fmt.Sprintf("…等 %d 个", len(assets)))
			break
		}
		parts = append(parts, fmt.Sprintf("#%d %s", a.ID, name))
	}
	return strings.Join(parts, "、")
}
