package db

import (
	"encoding/json"
	"strings"
)

// ═══ 上游 0.4.80 #20：prove_goal 能力型目标证据等级 ═══
//
// 目标要求拿到实际能力/高危结果（RCE、命令执行、控制权、敏感数据）时，只接受
// high/critical 的 finding 作为证据——fact（包括「未发现入口」这类否定结论）与
// low/medium finding 会拒绝；「是否存在/排查」类存在性目标不受影响。
// 否则 planner 可以借 prove_goal 把所有目标标 met，绕过 goal_met 的收官闸门，
// 让任务以 done 结束而实际没有拿到要求的能力。
//
// 判定是纯函数，落在 db 层（节点 payload 形状的唯一知情者）；agent 层的
// prove_goal 工具只留一行调用。

// capabilityGoalTerms 是「目标要求拿到实际能力/高危结果」的关键词。命中这些
// 词的目标不能用否定性事实或 low/medium 信息发现来证明。
// 只列结果性词，不列「管理员」这种会出现在侦察目标里的宽泛词。
var capabilityGoalTerms = []string{
	"rce", "远程代码执行", "命令执行", "代码执行",
	"getshell", "webshell", "反弹shell", "反弹 shell", "reverse shell",
	"控制权", "管理员权限", "管理员控制权", "管理员凭据", "domain admin",
	"root权限", "root 权限", "提权", "privilege escalation",
	"立足点", "foothold", "敏感数据", "数据泄露", "高危数据", "越权访问", "越权泄露", "敏感信息泄露",
}

// capabilityGoalNegativePhrases 表示目标是「确认是否存在/排查」，不是「拿到」。
// 这类目标用否定性 fact 证明是合法的，不能套用能力型门槛。
var capabilityGoalNegativePhrases = []string{
	"是否存在", "是否可", "确认是否", "排查", "探测", "评估是否存在",
	"有无", "whether", "check if", "test if", "probe for",
}

// GoalRequiresCapabilityEvidence 报告目标文本是否要求能力型/高危结果，
// 而非存在性（yes/no）核查。
func GoalRequiresCapabilityEvidence(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return false
	}
	for _, neg := range capabilityGoalNegativePhrases {
		if strings.Contains(t, neg) {
			return false
		}
	}
	for _, term := range capabilityGoalTerms {
		if strings.Contains(t, term) {
			return true
		}
	}
	return false
}

// goalNodeText extracts the human-readable text from a goal node payload.
func goalNodeText(n *Node) string {
	if n == nil {
		return ""
	}
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Text
}

// findingNodeSeverity extracts a finding node's severity from its payload.
// Finding 节点在 RecordFindingTx 创建时携带 {"severity": ...}。
func findingNodeSeverity(n *Node) string {
	if n == nil || n.Kind != KindFinding {
		return ""
	}
	var p struct {
		Severity string `json:"severity"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return strings.ToLower(strings.TrimSpace(p.Severity))
}

// CapabilityEvidenceError 在能力型目标被无法证明该能力的证据关联时返回非空
// 中文纠正提示（给模型看的），否则返回空串。goal 是目标节点，evidence 是
// prove_goal 传入的证据节点（fact 或 finding）。
func CapabilityEvidenceError(goal, evidence *Node) string {
	if !GoalRequiresCapabilityEvidence(goalNodeText(goal)) {
		return ""
	}
	if evidence == nil || evidence.Kind != KindFinding {
		return "该目标要求拿到实际能力/高危结果（如 RCE、命令执行、控制权、敏感数据），evidence_id 必须是 high/critical 的漏洞节点；普通 fact（包括「未发现入口」这类否定结论）不能证明此类目标。请先用 report_finding 记录可验证的 high/critical 漏洞，再用 prove_goal 关联。"
	}
	sev := findingNodeSeverity(evidence)
	if sev != "high" && sev != "critical" {
		return "该目标要求拿到实际能力/高危结果，当前关联漏洞的 severity 是「" + sev + "」；必须用 high/critical 的漏洞节点证明，low/medium 信息发现不足以证明能力型目标。"
	}
	return ""
}
