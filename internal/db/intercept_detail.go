package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// InterceptContextEntry is a bounded, recorded session event, not model reasoning.
type InterceptContextEntry struct {
	Kind      string `json:"kind"`
	Tool      string `json:"tool,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Text      string `json:"text"`
	IsError   bool   `json:"is_error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// InterceptAudit is captured at review time. It is deliberately excluded from
// polling/list responses; old rows have no audit instead of reconstructed data.
//
// P0 三表拆分后：RunID/ToolUseID/Correlation/InputDigest/模型输入/Context 等
// 审查时快照字段冻结在 intercept_pending.audit（只 INSERT 一次）；而
// EffectiveAction/DecisionReason（来自 intercept_decisions）与 ExecutionStatus/
// Output/OutputTruncated/ExecutionEndedAt（来自 intercept_executions 最后一行）
// 由 GetInterceptDetail 从三表拼装回同形 JSON——前端消费面不变。
type InterceptAudit struct {
	RunID            string                  `json:"run_id,omitempty"`
	ToolUseID        string                  `json:"tool_use_id,omitempty"`
	Correlation      string                  `json:"correlation"` // exact | ambiguous | unavailable
	InputDigest      string                  `json:"input_digest"`
	UserMessage      string                  `json:"user_message"`
	UserTruncated    bool                    `json:"user_truncated,omitempty"`
	Context          []InterceptContextEntry `json:"context"`
	ContextTruncated bool                    `json:"context_truncated,omitempty"`
	CapturedAt       time.Time               `json:"captured_at"`
	ModelFallback    bool                    `json:"model_fallback,omitempty"`
	ModelInput       json.RawMessage         `json:"model_input,omitempty"`
	ModelInputDigest string                  `json:"model_input_digest,omitempty"`
	InitialAction    string                  `json:"initial_action"`
	InitialReason    string                  `json:"initial_reason"`
	// Ask 审批等待的固化策略（P2 reaper 依据；ask 创建时写死，永不更新）：
	// TimeoutEnabled/Seconds/Action 与规则或 judge 配置在 ask 时刻的取值。
	AskTimeoutEnabled bool       `json:"ask_timeout_enabled,omitempty"`
	AskTimeoutSeconds int        `json:"ask_timeout_seconds,omitempty"`
	AskTimeoutAction  string     `json:"ask_timeout_action,omitempty"`
	EffectiveAction   string     `json:"effective_action,omitempty"`
	DecisionReason    string     `json:"decision_reason,omitempty"`
	RuleName          string     `json:"rule_name,omitempty"`
	ConfigDigest      string     `json:"config_digest,omitempty"`
	ProfileID         int64      `json:"profile_id,omitempty"`
	ExecutionStatus   string     `json:"execution_status"`
	Output            string     `json:"output,omitempty"`
	OutputTruncated   bool       `json:"output_truncated,omitempty"`
	ExecutionEndedAt  *time.Time `json:"execution_ended_at,omitempty"`
}

type InterceptDetail struct {
	InterceptApprovalRow
	Audit *InterceptAudit `json:"audit"`
}

// 详情列集：审批行 + 冻结的审查快照 + 视图里的决定/执行字段（拼装用）。
const approvalDetailColumns = approvalRowColumns + `,
       v.audit, COALESCE(v.effective_action,'') AS effective_action,
       COALESCE(v.decision_reason,'') AS effective_reason,
       COALESCE(v.execution_status,'') AS execution_status,
       COALESCE(v.output,'') AS execution_output,
       COALESCE(v.output_truncated,false) AS execution_output_truncated,
       v.execution_ended_at`

const approvalRowSelectWithAudit = `SELECT ` + approvalDetailColumns + approvalRowJoins

func (d *DB) GetInterceptDetail(id int64) (*InterceptDetail, error) {
	var out InterceptDetail
	var raw []byte
	var effectiveAction, decisionReason, executionStatus, output string
	var outputTruncated bool
	var executionEndedAt sql.NullTime
	err := d.QueryRow(approvalRowSelectWithAudit+` WHERE v.id=$1`, id).Scan(
		&out.ID, &out.RuleID, &out.ConversationID, &out.TaskID, &out.AgentName,
		&out.ToolName, &out.ToolInput, &out.Kind, &out.AskSource, &out.Reason, &out.Status,
		&out.DecidedAt, &out.DecidedBy, &out.DecisionSource, &out.CreatedAt,
		&out.ConvTitle, &out.ConvAgentKey, &out.RuleName,
		&raw, &effectiveAction, &decisionReason, &executionStatus, &output, &outputTruncated, &executionEndedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.Audit); err != nil {
			return nil, err
		}
	}
	// 拼装层：视图给出的决定/执行字段是当前事实，非空时覆盖快照残留；
	// 旧行（历史区，无 decisions/executions 行）视图列为空 → 保留 audit 内嵌
	// 的旧值，前端显示与拆表前一致。
	if a := out.Audit; a != nil {
		if effectiveAction != "" {
			a.EffectiveAction = effectiveAction
			a.DecisionReason = decisionReason
		}
		if executionStatus != "" {
			a.ExecutionStatus = executionStatus
			a.Output = output
			a.OutputTruncated = outputTruncated
		}
		if executionEndedAt.Valid {
			t := executionEndedAt.Time
			a.ExecutionEndedAt = &t
		}
	}
	return &out, nil
}

// ResolveIntercept settles a pending request by appending a decision row to the
// HMAC hash chain inside a serialized transaction. A timeout cannot overwrite a
// human decision and repeat decisions cannot rewrite history: the decision
// table's UNIQUE(pending_id) makes the first decision win (存储层的 decide-once，
// 取代旧的 UPDATE ... WHERE status='pending' CAS)。decidedBy is the caller's
// credential identity (empty for automatic paths); decisionSource classifies
// the decision (human/auto/timeout/auto_cancel/legacy/archive).
func (d *DB) ResolveIntercept(id int64, decision, action, reason, decidedBy, decisionSource string) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	// Serialize concurrent decides so two chains never fork and seq has no gaps.
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('intercept_chain'))`); err != nil {
		return false, err
	}
	if err := d.ensureAuditAnchorTx(tx); err != nil {
		return false, err
	}
	var claimed int
	if err := tx.QueryRow(`SELECT 1 FROM intercept_decisions WHERE pending_id=$1`, id).Scan(&claimed); err == nil {
		return false, nil // already decided — first decision wins
	} else if err != sql.ErrNoRows {
		return false, err
	}
	// 不存在的 pending id 同样按「已处理或不存在」收口（409）：否则 INSERT 会
	// 以 decisions.pending_id FK 违规透出 500 + PG 原始错误文本。
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM intercept_pending WHERE id=$1`, id).Scan(&exists); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if _, err := d.appendChainDecisionTx(tx, id, decision, action, reason, decidedBy, decisionSource); err != nil {
		return false, err
	}
	if err := d.appendExecutionTx(tx, id, action); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// CompleteIntercept appends the tool execution result as a NEW row in
// intercept_executions (append-only; 视图取最后一行，等价原「audit JSONB 追加」
// 语义)。It only lands for the exact recorded call after it was allowed: a
// blocked or uncorrelated call must never present a fabricated execution.
func (d *DB) CompleteIntercept(id int64, runID, toolUseID, status, output string, truncated bool) error {
	_, err := d.Exec(`INSERT INTO intercept_executions(pending_id, run_id, tool_use_id, execution_status, output, output_truncated, ended_at)
SELECT $1, $2, $3, $4, $5, $6, now()
FROM intercept_pending ip
WHERE ip.id=$1 AND ip.audit->>'run_id'=$2 AND ip.audit->>'tool_use_id'=$3
  AND EXISTS (SELECT 1 FROM v_intercept v WHERE v.id=$1 AND v.effective_action='allow' AND v.execution_status='awaiting_result')`,
		id, runID, toolUseID, status, output, truncated)
	return err
}
