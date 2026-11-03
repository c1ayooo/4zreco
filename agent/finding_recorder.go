package agent

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/db"
)

// validateFindingEvidence 高严重度证据门槛（v0.4.5，借鉴 Shannon 的 L3 门槛）：
// critical/high 必须有达到最低篇幅的可核验证据，挡住"一句话上报严重漏洞"。
// medium/low 不设门槛——低危经常只有一句说明，过度校验会阻碍正常上报。
// 返回空串表示通过，否则是回灌给模型的中文纠正提示（模型可在同会话补证据或降级）。
func validateFindingEvidence(severity, evidence string) string {
	n := utf8.RuneCountInString(strings.TrimSpace(evidence))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		if n < 200 {
			return "证据不足以支撑 critical 级别：evidence 至少需要 200 字的可核验原始证据（请求/响应原文、命令输出、回显片段）。请补全证据后重新调用 report_finding；若实际只达到 L2（证明输入影响了后端逻辑但未拿到真实影响），请把 severity 降为 medium 并写明利用条件。"
		}
	case "high":
		if n < 120 {
			return "证据不足以支撑 high 级别：evidence 至少需要 120 字的可核验原始证据（请求/响应原文、命令输出或回显片段）。请补全后重新调用 report_finding；若只是间接推断，请把 severity 降为 medium 并注明。"
		}
	}
	return ""
}

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**漏洞流量证据（可选）**：调用 report_finding 上报漏洞时，如有已查看并确认支持漏洞结论的 HTTP 请求/响应，可用 traffic_refs 按复现顺序绑定真实 ID；域名和时间只作候选筛选，不推定关联。TCP 等非 HTTP 漏洞、未采集或无确切匹配时省略或传 []，在 evidence 保留命令输出、日志等其他可验证证据，建议说明未绑定原因。不要猜测 ID，也不要仅为补包重复探测。"

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
