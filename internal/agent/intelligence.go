package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c1ayooo/4zreco/internal/db"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// 任务情报（移植自 ARTEX 0.3.29 C2）：record_intelligence 写库工具 + record_fact
// 随附 intelligence[] 写回。宿主未注入开关/落库函数（或 settings 关闭）＝整体缺席，
// 不给模型任何 token 开销。每次写回前重读开关，运行中会话也能即时生效。
var IntelligenceEnabled func() bool
var IntelligenceRecord func(context.Context, int64, int64, string, db.IntelligenceInput) (int64, error)
// CredentialRecorded 由宿主在 credential 情报落库后调用（凭据整理 agent 子阶段）：
// 只为降低延迟，持久化的数据库行才是事实源；漏掉的通知由处理循环的慢 tick 兜底。
var CredentialRecorded func()

func intelligenceEnabled() bool { return IntelligenceEnabled != nil && IntelligenceEnabled() }

func intelligenceSchema() map[string]any {
	return obj(map[string]any{
		"kind":       map[string]any{"type": "string", "enum": []string{"credential", "lead", "sensitive_data"}},
		"title":      str("简短标题，禁止包含密码、Token 或敏感数据原文"),
		"content":    str("实际获取的信息。凭据用 JSON 字符串保存账号/密码/Token 等；敏感数据仅少量样例、数量和文件位置，禁止整库粘贴"),
		"evidence":   str("真实来源：命令/请求/响应/文件位置及关键观察，禁止编造"),
		"confidence": map[string]any{"type": "string", "enum": []string{"observed", "inferred"}},
		"status":     str("凭据 unverified/verified/invalid；线索 pending/in_progress/dismissed/converted；敏感数据 suspected/confirmed/dismissed。省略时保守默认，verified 需要真实认证成功证据"),
		"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
	}, "kind", "title", "content", "evidence", "confidence")
}

// saveIntelligence 落一条情报。任务/来源节点由系统绑定：ToolSet 自带的 taskID/
// ownerNode 优先，缺了再从 RunInfo（engine 注入的运行上下文）取，两者皆无则拒绝。
func (t *ToolSet) saveIntelligence(ctx context.Context, nodeID int64, in db.IntelligenceInput) (int64, error) {
	if !intelligenceEnabled() || IntelligenceRecord == nil {
		return 0, fmt.Errorf("任务情报自动记录已关闭")
	}
	taskID := t.taskID
	if taskID <= 0 {
		taskID = RunInfoFrom(ctx).TaskID
	}
	if taskID <= 0 {
		return 0, fmt.Errorf("任务情报需要当前任务上下文")
	}
	if nodeID <= 0 {
		nodeID = t.ownerNode
	}
	if nodeID <= 0 {
		nodeID = RunInfoFrom(ctx).IntentID
	}
	id, err := IntelligenceRecord(ctx, taskID, nodeID, t.worker, in)
	if err == nil {
		t.writes.Intelligence++
	}
	return id, err
}

func (t *ToolSet) recordIntelligence() actool.CoreTool {
	return writeTool("record_intelligence", "记录当前任务实际获取的凭据、重要线索或敏感数据。任务和执行来源由系统绑定；凭据发现不等于验证成功。重复记录会去重。已有 insert_assets.auth 自动登记凭据，无需重复调用。", intelligenceSchema(), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in db.IntelligenceInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return actool.Errorf("无效情报参数"), nil
		}
		id, err := t.saveIntelligence(ctx, 0, in)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text(fmt.Sprintf("intelligence recorded: %d", id)), nil
	})
}

// intelligenceWorkflow 在工具装配完成后按开关动态增删情报面：
//   - 关闭：从工具列表剔除 record_intelligence，并从 record_fact 的 schema 里删掉
//     intelligence 属性——关闭时对提示词零 token 开销（工具 gate 回归的核心断言）；
//   - 开启且有任务上下文：注入 intelligence 属性（≤20 条/次）并追加一段行为指引。
func intelligenceWorkflow(ctx context.Context, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	enabled := intelligenceEnabled() && RunInfoFrom(ctx).TaskID > 0
	out := make([]actool.CoreTool, 0, len(tools))
	hasRecord := false
	hasFact := false
	for _, tool := range tools {
		if tool.Name() == "record_intelligence" {
			if !enabled {
				continue
			}
			hasRecord = true
		}
		if tool.Name() == "record_fact" {
			raw, _ := json.Marshal(tool.InputSchema())
			var schema map[string]any
			if json.Unmarshal(raw, &schema) == nil {
				props, _ := schema["properties"].(map[string]any)
				if props != nil {
					delete(props, "intelligence")
					if enabled {
						props["intelligence"] = map[string]any{"type": "array", "maxItems": 20, "description": "随事实一次写回情报，字段与 record_intelligence 相同；无需再单独调用该工具", "items": intelligenceSchema()}
						hasFact = true
					}
				}
				tool = DecorateTool(tool, tool.Description(), schema)
			}
		}
		out = append(out, tool)
	}
	guide := ""
	if enabled && (hasRecord || hasFact) {
		guide = "\n\n**任务情报记录已开启**：发现凭据、值得跟进的线索或真实敏感数据时立即结构化写回，不等用户追问；结束前检查遗漏。record_fact 可附 intelligence 数组一起写回，每条事实/批量 facts 的元素均支持；单独记录用 record_intelligence（若可用）。insert_assets.auth 已由后端自动登记，勿重复调用。只记录新增、有价值的信息，普通指纹/端口状态仍仅作 fact。title 禁止包含秘密原文；正文带实际内容和来源。凭据默认未验证，只有真实认证成功才标 verified；推断必须 inferred；敏感数据写类型、数量、少量样例、文件位置，勿粘整库。"
	}
	return out, guide
}
