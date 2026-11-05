package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// InterceptRule is one row of intercept_rules.
type InterceptRule struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Priority       int       `json:"priority"`
	MatchTarget    string    `json:"match_target"`
	MatchType      string    `json:"match_type"`
	Pattern        string    `json:"pattern"`
	Action         string    `json:"action"`
	Message        string    `json:"message"`
	TimeoutEnabled bool      `json:"timeout_enabled"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	TimeoutAction  string    `json:"timeout_action"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// InterceptPending is one row of v_intercept (审批请求 + 视图计算的 status)。
// P0 三表拆分后 pending 表本身只 INSERT；Status/DecidedAt/DecisionSource 等
// 决定侧字段来自 intercept_decisions 的最后一条行。
type InterceptPending struct {
	ID             int64           `json:"id"`
	RuleID         *int64          `json:"rule_id"`
	ConversationID *int64          `json:"conversation_id"`
	TaskID         *string         `json:"task_id"`
	AgentName      string          `json:"agent_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Kind           string          `json:"kind"`       // 请求类型：rule | judge（旧行为空）
	AskSource      string          `json:"ask_source"` // ask 来源：rule | judge（旧行 model/unknown）
	Status         string          `json:"status"`     // 视图计算：pending 或最后一条决定
	Reason         string          `json:"reason"`     // 规则 message 或模型判定理由(前缀 [模型])
	DecidedAt      *time.Time      `json:"decided_at"`
	DecidedBy      string          `json:"decided_by"`      // 决定者凭据身份（人工路径非空）
	DecisionSource string          `json:"decision_source"` // 决定来源：human/auto/timeout/auto_cancel/legacy/archive
	CreatedAt      time.Time       `json:"created_at"`
}

const interceptRuleCols = `id, name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action, created_at, updated_at`

func scanInterceptRule(row interface{ Scan(...any) error }) (InterceptRule, error) {
	var r InterceptRule
	err := row.Scan(&r.ID, &r.Name, &r.Enabled, &r.Priority,
		&r.MatchTarget, &r.MatchType, &r.Pattern, &r.Action, &r.Message,
		&r.TimeoutEnabled, &r.TimeoutSeconds, &r.TimeoutAction,
		&r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// ListInterceptRules returns all rules ordered by priority DESC then id.
func (d *DB) ListInterceptRules() ([]InterceptRule, error) {
	rows, err := d.Query(`SELECT ` + interceptRuleCols + ` FROM intercept_rules ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InterceptRule
	for rows.Next() {
		r, err := scanInterceptRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateInterceptRule inserts a new rule.
func (d *DB) CreateInterceptRule(name, matchTarget, matchType, pattern, action, message string, priority int, enabled bool, timeoutEnabled bool, timeoutSeconds int, timeoutAction string) (InterceptRule, error) {
	row := d.QueryRow(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING `+interceptRuleCols,
		name, enabled, priority, matchTarget, matchType, pattern, action, message, timeoutEnabled, timeoutSeconds, timeoutAction)
	return scanInterceptRule(row)
}

// UpdateInterceptRule replaces all editable fields of an existing rule.
func (d *DB) UpdateInterceptRule(id int64, name, matchTarget, matchType, pattern, action, message string, priority int, enabled bool, timeoutEnabled bool, timeoutSeconds int, timeoutAction string) (InterceptRule, error) {
	row := d.QueryRow(`
UPDATE intercept_rules
   SET name=$2, enabled=$3, priority=$4, match_target=$5,
       match_type=$6, pattern=$7, action=$8, message=$9,
       timeout_enabled=$10, timeout_seconds=$11, timeout_action=$12
WHERE id=$1
RETURNING `+interceptRuleCols,
		id, name, enabled, priority, matchTarget, matchType, pattern, action, message, timeoutEnabled, timeoutSeconds, timeoutAction)
	return scanInterceptRule(row)
}

// DeleteInterceptRule removes a rule.
func (d *DB) DeleteInterceptRule(id int64) error {
	_, err := d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, id)
	return err
}

// ToggleInterceptRule flips the enabled state of a rule.
func (d *DB) ToggleInterceptRule(id int64, enabled bool) error {
	_, err := d.Exec(`UPDATE intercept_rules SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

// askSourceFor maps a request to its ask 来源 dimension. ruleID != 0 → the ask
// (or the observation row) belongs to an intercept rule; otherwise it came from
// the LLM fallback judge. Legacy rows keep rule/model/unknown values.
func askSourceFor(ruleID int64) string {
	if ruleID != 0 {
		return "rule"
	}
	return "judge"
}

// normalizeKind falls back to the rule/judge derivation when the caller did not
// classify the request (defensive: the column's CHECK allows '' but新行应当有值).
func normalizeKind(ruleID int64, kind string) string {
	if kind == "rule" || kind == "judge" {
		return kind
	}
	if ruleID != 0 {
		return "rule"
	}
	return "judge"
}

// CreateInterceptPending inserts a pending approval record and returns its ID.
// convID == 0 → conversation_id stored as NULL (background task).
// taskID == "" → task_id stored as NULL. kind ∈ {rule, judge} is the request
// taxonomy (P0-6); empty falls back to the ruleID derivation.
func (d *DB) CreateInterceptPending(ruleID, convID int64, taskID, agentName, toolName string, input []byte, reason, kind string, audits ...*InterceptAudit) (int64, error) {
	raw := json.RawMessage(input)
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	var convIDPtr *int64
	if convID != 0 {
		convIDPtr = &convID
	}
	var taskIDPtr *string
	if taskID != "" {
		taskIDPtr = &taskID
	}
	// ruleID == 0 → NULL: the LLM fallback judge has no owning rule.
	var ruleIDPtr *int64
	if ruleID != 0 {
		ruleIDPtr = &ruleID
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO intercept_pending(rule_id, conversation_id, task_id, agent_name, tool_name, tool_input, reason, ask_source, kind, audit)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		ruleIDPtr, convIDPtr, taskIDPtr, agentName, toolName, raw, reason, askSourceFor(ruleID), normalizeKind(ruleID, kind), firstAudit(audits)).Scan(&id)
	return id, err
}

// CreateDecidedIntercept inserts an intercept_pending row ALREADY in a final
// state (status = 'allowed' | 'denied') together with its decision row (chained
// into the HMAC hash chain, decision_source='auto') and the pre-inserted
// execution row. Used to log allow/deny rule/model verdicts for observability —
// they don't block and need no user action, so unlike CreateInterceptPending
// (which starts 'pending') this records the outcome directly. P0 三表拆分后
// 观测行也必须带决定行，否则视图会把它显示成永久 pending。
func (d *DB) CreateDecidedIntercept(ruleID, convID int64, taskID, agentName, toolName string, input []byte, status, reason, kind string, audits ...*InterceptAudit) (int64, error) {
	raw := json.RawMessage(input)
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	var convIDPtr *int64
	if convID != 0 {
		convIDPtr = &convID
	}
	var taskIDPtr *string
	if taskID != "" {
		taskIDPtr = &taskID
	}
	// ruleID == 0 → NULL: the LLM fallback judge has no owning rule.
	var ruleIDPtr *int64
	if ruleID != 0 {
		ruleIDPtr = &ruleID
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	// 观测行接链：锚行缺失时先补（与 ResolveIntercept 同一串行化前提由
	// appendChainDecisionTx 的链头 FOR UPDATE + 本事务的 INSERT 顺序保证）。
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('intercept_chain'))`); err != nil {
		return 0, err
	}
	if err := d.ensureAuditAnchorTx(tx); err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(`
INSERT INTO intercept_pending(rule_id, conversation_id, task_id, agent_name, tool_name, tool_input, reason, ask_source, kind, audit)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		ruleIDPtr, convIDPtr, taskIDPtr, agentName, toolName, raw, reason, askSourceFor(ruleID), normalizeKind(ruleID, kind), firstAudit(audits)).Scan(&id)
	if err != nil {
		return 0, err
	}
	action := "deny"
	if status == "allowed" {
		action = "allow"
	}
	// Observation rows are auto verdicts: no human identity, source=auto.
	if _, err := d.appendChainDecisionTx(tx, id, status, action, reason, "", "auto"); err != nil {
		return 0, err
	}
	if err := d.appendExecutionTx(tx, id, action); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

const interceptPendingCols = `id, rule_id, conversation_id, task_id, agent_name, tool_name, tool_input, kind, ask_source, reason, status, decided_at, decided_by, decision_source, created_at`

func scanInterceptPending(s interface{ Scan(...any) error }, p *InterceptPending) error {
	return s.Scan(&p.ID, &p.RuleID, &p.ConversationID, &p.TaskID, &p.AgentName,
		&p.ToolName, &p.ToolInput, &p.Kind, &p.AskSource, &p.Reason, &p.Status,
		&p.DecidedAt, &p.DecidedBy, &p.DecisionSource, &p.CreatedAt)
}

// ListPendingIntercepts returns all unresolved approval requests, newest first.
// Reads v_intercept: status is computed from the absence of a decision row.
func (d *DB) ListPendingIntercepts() ([]InterceptPending, error) {
	rows, err := d.Query(`SELECT ` + interceptPendingCols + ` FROM v_intercept WHERE status='pending' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InterceptPending
	for rows.Next() {
		var p InterceptPending
		if err := scanInterceptPending(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetInterceptPending returns one pending record (nil if absent).
func (d *DB) GetInterceptPending(id int64) (*InterceptPending, error) {
	var p InterceptPending
	err := scanInterceptPending(
		d.QueryRow(`SELECT `+interceptPendingCols+` FROM v_intercept WHERE id=$1`, id),
		&p,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

// InterceptApprovalRow is v_intercept enriched with conversation and rule info.
type InterceptApprovalRow struct {
	InterceptPending
	ConvTitle    string `json:"conv_title"`
	ConvAgentKey string `json:"conv_agent_key"`
	RuleName     string `json:"rule_name"`
}

func scanInterceptApprovalRow(rows interface{ Scan(...any) error }, r *InterceptApprovalRow) error {
	return rows.Scan(
		&r.ID, &r.RuleID, &r.ConversationID, &r.TaskID, &r.AgentName,
		&r.ToolName, &r.ToolInput, &r.Kind, &r.AskSource, &r.Reason, &r.Status,
		&r.DecidedAt, &r.DecidedBy, &r.DecisionSource, &r.CreatedAt,
		&r.ConvTitle, &r.ConvAgentKey, &r.RuleName,
	)
}

const approvalRowColumns = `v.id, v.rule_id, v.conversation_id, v.task_id, v.agent_name,
       v.tool_name, v.tool_input, v.kind, v.ask_source, v.reason, v.status, v.decided_at,
       v.decided_by, v.decision_source, v.created_at,
       COALESCE(c.title,'') AS conv_title,
       COALESCE(c.agent_key,'') AS conv_agent_key,
       COALESCE(ir.name,'') AS rule_name`

const approvalRowJoins = `
FROM v_intercept v
LEFT JOIN conversations c ON c.id = v.conversation_id
LEFT JOIN intercept_rules ir ON ir.id = v.rule_id`

const approvalRowSelect = `SELECT ` + approvalRowColumns + approvalRowJoins

func firstAudit(audits []*InterceptAudit) any {
	if len(audits) == 0 || audits[0] == nil {
		return nil
	}
	raw, err := json.Marshal(audits[0])
	if err != nil {
		return nil
	}
	return raw
}

// ListAllIntercepts returns up to limit approval rows (newest first)
// joined with conversation and rule info.
func (d *DB) ListAllIntercepts(limit int) ([]InterceptApprovalRow, error) {
	rows, err := d.Query(approvalRowSelect+` ORDER BY v.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InterceptApprovalRow
	for rows.Next() {
		var r InterceptApprovalRow
		if err := scanInterceptApprovalRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InterceptApprovalFilter combines exact status, ask-source (rule/judge, 旧值
// model/unknown) and decide-source (human/auto/timeout/…) filters. The two
// source dimensions are orthogonal since P0-6. Empty fields include all values.
type InterceptApprovalFilter struct {
	Status         string
	AskSource      string
	DecisionSource string
}

// ListAllInterceptsPage returns one 1-based page and the total matching count.
func (d *DB) ListAllInterceptsPage(page, size int, filter InterceptApprovalFilter) ([]InterceptApprovalRow, int, error) {
	return d.listInterceptsPage("", page, size, filter)
}

// ListTaskIntercepts returns all approval rows for a specific task (newest first).
func (d *DB) ListTaskIntercepts(taskID string) ([]InterceptApprovalRow, error) {
	rows, err := d.Query(approvalRowSelect+` WHERE v.task_id=$1 ORDER BY v.created_at DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InterceptApprovalRow
	for rows.Next() {
		var r InterceptApprovalRow
		if err := scanInterceptApprovalRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListTaskInterceptsPage is the paginated variant of ListTaskIntercepts.
func (d *DB) ListTaskInterceptsPage(taskID string, page, size int, filter InterceptApprovalFilter) ([]InterceptApprovalRow, int, error) {
	return d.listInterceptsPage(taskID, page, size, filter)
}

func (d *DB) listInterceptsPage(taskID string, page, size int, filter InterceptApprovalFilter) ([]InterceptApprovalRow, int, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	offset := (page - 1) * size

	conditions := []string{}
	args := []any{}
	add := func(column, value string) {
		if value != "" {
			args = append(args, value)
			conditions = append(conditions, column+"=$"+fmt.Sprint(len(args)))
		}
	}
	add("v.task_id", taskID)
	add("v.status", filter.Status)
	add("v.ask_source", filter.AskSource)
	add("v.decision_source", filter.DecisionSource)
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM v_intercept v"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitArg := len(args) + 1
	offsetArg := limitArg + 1
	dataQ := approvalRowSelect + where +
		" ORDER BY v.created_at DESC, v.id DESC LIMIT $" + fmt.Sprint(limitArg) +
		" OFFSET $" + fmt.Sprint(offsetArg)
	args = append(args, size, offset)
	rows, err := d.Query(dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []InterceptApprovalRow{}
	for rows.Next() {
		var r InterceptApprovalRow
		if err := scanInterceptApprovalRow(rows, &r); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
