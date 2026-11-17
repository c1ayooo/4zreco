package agent

// 攻击链自动续跳（v0.4.64 批次，移植自上游 0.4.63）：report_finding 成功登记
// high/critical 后，按漏洞类别自动派一条「继续打穿」的继任意图，把「漏洞存在」
// 推进到「拿到影响」。
//
// ## 为什么需要它
//
// 现场事实：worker 能确认漏洞（report_finding），但确认之后**没有下一步**——
// planner 下一轮看到的是「已有漏洞」，容易转去补覆盖面，而不是利用它。这里做
// 确定性续跳：高危漏洞入库后立刻生成一条继任意图（维度=下一跳，dimension.go），
// 锚在该 finding 节点上。规划者仍然掌握全局（可 kill/steer/改编排），但
// 「从存在到影响」这一步不再取决于模型是否想起来。
//
// ## 4zreco 侧差异
//
//   - 继任意图经 addOneIntent 下发，因此受同一套约束：意图锚点校验、派发去重
//     （FindSimilarOpenIntent）、接续代数——续跳不是特权通道。
//   - 与 finding_cases 归并联动：登记的漏洞若已归入某个 case，继任意图 summary
//     注明「关联 case #N」，后续归并/复盘时能顺着 case 追到这条续跳意图。
//   - 上游的 SRC 证据缺口参数（missing）未移植：4zreco 没有 SRC 审查环节，
//     证据门槛由 validateFindingEvidence 承担。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// chainNext 返回某维度对应的下一跳维度与目标描述（空=不续跳）。
func chainNext(dim string) (string, string) {
	switch dim {
	case dimInjection:
		return dimDataExport, "用已确认的注入点导出数据/凭据（只读取证）：拿到可交付的库表、账号或配置证据，并评估影响范围"
	case dimUpload, dimRCE:
		return dimCredReuse, "利用已确认的命令执行/上传点在目标主机收集凭据与配置（只读），确认权限级别与内网可达面"
	case dimAuthz:
		return dimDataExport, "用已确认的越权点回读他人数据（限证明所需），并验证改状态/改价的业务影响"
	case dimSSRF:
		return dimRecon, "用 SSRF 探测内网服务与云元数据，找出下一跳可打的服务"
	case dimCredReuse:
		return dimLateral, "用已拿到的凭据尝试横向下一个系统（先确认授权边界内的目标）"
	case dimPayment:
		return dimDataExport, "验证支付/订单状态机被篡改后能产生多少实际影响（测试订单、金额、回调），取证后停止"
	case dimPrivesc:
		return dimDataExport, "提权后只读取证：确认可访问的敏感数据与持久化位置，不做破坏性操作"
	default:
		return "", ""
	}
}

// dispatchChainIntent 生成继任意图。返回 (intentID, note)。intentID<=0 时 note
// 为空串表示不续跳（非 high/critical、维度不在续跳表且无兜底理由）；>0 时 note
// 是给调用方（report_finding 返回值）的说明文字。续跳失败（去重命中/校验拒绝）
// 时 intentID=0、note 说明原因——不静默，让模型/人知道续跳被什么挡了。
func (t *ToolSet) dispatchChainIntent(vulnclass, name, summary, severity string, assetIDs []int64, findingNodeID, findingID, intentID int64) (int64, string) {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "critical" && sev != "high" {
		return 0, ""
	}
	dim := inferDimension(vulnclass + " " + name + " " + summary)
	nextDim, goal := chainNext(dim)
	if nextDim == "" {
		// 维度不在续跳表里（如信息泄露/未知类）：仍派一条取数/影响证明意图，
		// 避免高危 finding 停在「存在性」。
		nextDim = dimDataExport
		goal = "补齐该漏洞的完整危害证据（原始请求/响应、真实数据条数与敏感字段、权限影响），不做破坏性操作"
	}
	// 摘要必须具体：带上漏洞名与下一跳，避免和别的意图撞车被 FindSimilarOpenIntent 去重掉。
	// name 可能为空（模型只给了 summary），回落到 summary 前 40 字。
	label := strings.TrimSpace(name)
	if label == "" {
		label = trimForSummary(strings.TrimSpace(summary), 40)
	}
	sum := fmt.Sprintf("利用「%s」继续打穿：%s", trimForSummary(label, 40), goal)
	// finding_cases 归并联动：该漏洞已归入 case 时在摘要里注明，归并复盘可循迹。
	if cid := t.findingCaseIDFor(findingID); cid > 0 {
		sum += fmt.Sprintf("（关联 case #%d）", cid)
	}
	it := intentItem{Summary: sum, Dimension: nextDim, Priority: 8}
	for _, id := range assetIDs {
		if raw, err := json.Marshal(id); err == nil {
			it.AssetIDs = append(it.AssetIDs, raw)
		}
	}
	if findingNodeID > 0 {
		if raw, err := json.Marshal(findingNodeID); err == nil {
			it.ParentIDs = append(it.ParentIDs, raw)
		}
	}
	id, err := t.addOneIntent(it)
	if err != nil {
		return 0, "攻击链续跳未派：" + err.Error()
	}
	return id, fmt.Sprintf("已自动派继任意图 #%d（维度=%s）：从「漏洞存在」推进到「拿到影响」。", id, nextDim)
}

// findingCaseIDFor 查 finding 已归入的 case id。归并存储未接线（FindingCaseDB 为
// nil）或查询失败时返回 0——续跳不依赖归并，失败只是少一句注记。
func (t *ToolSet) findingCaseIDFor(findingID int64) int64 {
	if findingID <= 0 || FindingCaseDB == nil {
		return 0
	}
	pg := FindingCaseDB()
	if pg == nil {
		return 0
	}
	cid, err := pg.FindingCaseID(findingID)
	if err != nil {
		return 0
	}
	return cid
}

func trimForSummary(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
