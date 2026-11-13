package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// 凭据验证 agent（移植自 ARTEX 0.3.29 C2 可选子阶段）：task_intelligence.credential_analysis
// 列的派生状态机。原始情报行始终是权威数据；本文件只维护「拆分展示 + 流量引用」这层
// 派生呈现的租约排队（queued/processing/ready），不改变情报本身的 status/语义。
const (
	// SettingCredentialAgent：凭据整理 agent 总开关（依赖 SettingTaskIntelligence 先开）。
	SettingCredentialAgent = "credential_agent_enabled"
	// SettingCredentialTraffic：整理时核对已抓取流量并保存引用（依赖上面两个开关）。
	SettingCredentialTraffic = "credential_traffic_binding"
	// CredentialAgentKey：内置「凭据整理」会话 agent 的注册 key。
	CredentialAgentKey = "credential_processor"
)

// CredentialAccount 是拆分出的一组凭据字段；全部字段必须是原文中已存在的精确值，
// 不允许模型猜测或拼接（校验在 internal/agent.ValidateCredentialAccounts）。
type CredentialAccount struct {
	Label    string `json:"label,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Cookie   string `json:"cookie,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// CredentialTraffic 是验证过的引用与有界片段，不是完整报文快照；原始流量在
// 流量存储存续期间仍可打开（引用在原始流量被清理后仍可展示片段）。
type CredentialTraffic struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Status   int    `json:"status"`
	Side     string `json:"side"`
	Excerpt  string `json:"excerpt"`
	Accounts []int  `json:"accounts"`
}
type CredentialAnalysis struct {
	ConversationID int64               `json:"conversation_id,omitempty"`
	ForceExtract   bool                `json:"force_extract,omitempty"`
	TrafficNote    string              `json:"traffic_note,omitempty"`
	State          string              `json:"state"`
	Lease          string              `json:"lease,omitempty"`
	LeaseUntil     time.Time           `json:"lease_until,omitempty"`
	SourceHash     string              `json:"source_hash,omitempty"`
	Method         string              `json:"method,omitempty"`
	Accounts       []CredentialAccount `json:"accounts"`
	Traffic        []CredentialTraffic `json:"traffic"`
	TrafficState   string              `json:"traffic_state"`
	Note           string              `json:"note,omitempty"`
	Error          string              `json:"error,omitempty"`
	Model          string              `json:"model,omitempty"`
	InputTokens    int                 `json:"input_tokens"`
	OutputTokens   int                 `json:"output_tokens"`
	ProcessedAt    *time.Time          `json:"processed_at,omitempty"`
}

// CredentialSourceHash 是 content 原文的 SHA256：整理结果绑定它，content 变化后
// 下一次认领会强制重跑提取。
func CredentialSourceHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// 三个开关（情报采集总开关 → agent 开关 → 流量绑定）的依赖提交在同一事务里完成：
// 关掉父开关会连动清掉子开关，重新开启父开关不会把旧的子开关静默带起来。
// advisory lock 7337741006 同时串行化 FinishCredentialJob 的完成写（见该函数）。
func (d *DB) SetCredentialAgentSettings(ctx context.Context, enabled, binding *bool) error {
	return d.SetIntelligenceSettings(ctx, nil, enabled, binding)
}
func (d *DB) SetIntelligenceSettings(ctx context.Context, recording, enabled, binding *bool) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7337741006)`); err != nil {
		return err
	}
	record, on, bind := false, false, false
	var value string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, SettingTaskIntelligence).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	record = value == "true" || value == "1"
	if recording != nil {
		record = *recording
	}
	value = ""
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, SettingCredentialAgent).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	on = value == "true" || value == "1"
	value = ""
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, SettingCredentialTraffic).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	bind = value == "true" || value == "1"
	if enabled != nil {
		on = *enabled
	}
	if binding != nil {
		bind = *binding
	}
	if !record {
		if enabled != nil && *enabled {
			return fmt.Errorf("%w: 请先开启 Agent 自动记录，再开启 Agent 开关", ErrIntelligenceInvalid)
		}
		if binding != nil && *binding {
			return fmt.Errorf("%w: 请依次开启 Agent 自动记录和 Agent 开关", ErrIntelligenceInvalid)
		}
		on = false
		bind = false
	}
	if !on {
		if binding != nil && *binding {
			return fmt.Errorf("%w: 请先开启 Agent 开关，再启用绑定流量", ErrIntelligenceInvalid)
		}
		bind = false
	}
	for key, val := range map[string]bool{SettingTaskIntelligence: record, SettingCredentialAgent: on, SettingCredentialTraffic: bind} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()`, key, strconv.FormatBool(val)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ClaimCredentialJob 认领一条待整理的凭据情报：每条记录一个持久租约，由全部应用
// 进程共享（FOR UPDATE SKIP LOCKED）。出错不会每个 tick 都重试——显式 retry 才重新
// 入队；过期租约让进程重启后的中断运行得以恢复；LLM I/O 期间不持有任务锁。
// bind=true 时 ready 且 traffic_state=off 的记录也重新入队（后补流量绑定，无需重跑提取）。
func (d *DB) ClaimCredentialJob(ctx context.Context, bind bool, taskID int64) (*Intelligence, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT i.id FROM task_intelligence i JOIN tasks t ON t.id=i.task_id
 WHERE i.kind='credential' AND EXISTS(SELECT 1 FROM settings WHERE key='credential_agent_enabled' AND value IN ('true','1')) AND EXISTS(SELECT 1 FROM settings WHERE key='task_intelligence_enabled' AND value IN ('true','1')) AND ($2::bigint=0 OR i.task_id=$2) AND t.deleted_at IS NULL AND t.archived_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM task_archives a WHERE a.task_id=t.id AND a.state IN ('archive_queued','archiving','restore_queued','restoring','delete_queued','deleting'))
 AND (i.credential_analysis IS NULL OR i.credential_analysis->>'state'='queued'
 OR (i.credential_analysis->>'state'='processing' AND (i.credential_analysis->>'lease_until')::timestamptz < now())
 OR ($1 AND i.credential_analysis->>'state'='ready' AND i.credential_analysis->>'traffic_state'='off'))
 ORDER BY i.id FOR UPDATE OF i SKIP LOCKED LIMIT 1`, bind, taskID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	patch, _ := json.Marshal(map[string]any{"state": "processing", "lease": hex.EncodeToString(token), "lease_until": time.Now().UTC().Add(3 * time.Minute)})
	if _, err = tx.ExecContext(ctx, `UPDATE task_intelligence SET credential_analysis=COALESCE(credential_analysis,'{}'::jsonb)||$2::jsonb WHERE id=$1`, id, string(patch)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetIntelligence(ctx, id)
}

// FinishCredentialJob 持租约写入整理结果。租约不匹配（已被重领）的写直接丢弃——
// 过期租约的迟到完成不能覆盖新一轮运行。与三个开关的切换经 advisory lock 串行化：
// 已关闭的功能不能在关闭之后又发布新的派生结果或新匹配的流量。
func (d *DB) FinishCredentialJob(ctx context.Context, item *Intelligence, result CredentialAnalysis) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7337741006)`); err != nil {
		return err
	}
	var enabled, binding bool
	if err = tx.QueryRowContext(ctx, `SELECT (EXISTS(SELECT 1 FROM settings WHERE key=$1 AND value IN ('true','1')) AND EXISTS(SELECT 1 FROM settings WHERE key='task_intelligence_enabled' AND value IN ('true','1'))),EXISTS(SELECT 1 FROM settings WHERE key=$2 AND value IN ('true','1'))`, SettingCredentialAgent, SettingCredentialTraffic).Scan(&enabled, &binding); err != nil {
		return err
	}
	if !enabled {
		// 关闭期间完成的运行退回队列：开关重开后自动接续，原文不受影响。
		_, err = tx.ExecContext(ctx, `UPDATE task_intelligence SET credential_analysis=credential_analysis||'{"state":"queued"}'::jsonb WHERE id=$1 AND credential_analysis->>'lease'=$2`, item.ID, item.Credentials.Lease)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if !binding {
		result.Traffic = item.Credentials.Traffic
		result.TrafficState = "off"
		result.TrafficNote = ""
	}
	result.Lease = ""
	result.LeaseUntil = time.Time{}
	now := time.Now().UTC()
	result.ProcessedAt = &now
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE task_intelligence i SET credential_analysis=$3::jsonb
 WHERE i.id=$1 AND i.credential_analysis->>'lease'=$2
 AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=i.task_id AND t.deleted_at IS NULL AND t.archived_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM task_archives a WHERE a.task_id=i.task_id AND a.state IN ('archive_queued','archiving','restore_queued','restoring','delete_queued','deleting'))`, item.ID, item.Credentials.Lease, string(raw))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// RetryCredentialJob 显式重排队（用户点「重新处理」）。processing 中的记录不重排队
// （租约还活着）；错误状态的记录可以。重排队置 force_extract 强制重跑提取。
func (d *DB) RetryCredentialJob(ctx context.Context, taskID, id int64) error {
	result, err := d.ExecContext(ctx, `UPDATE task_intelligence i SET credential_analysis=COALESCE(credential_analysis,'{}'::jsonb)||'{"state":"queued","error":"","force_extract":true}'::jsonb
 WHERE id=$1 AND task_id=$2 AND kind='credential'
 AND COALESCE(credential_analysis->>'state','')<>'processing'
 AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=i.task_id AND t.deleted_at IS NULL AND t.archived_at IS NULL)`, id, taskID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrIntelligenceNotFound
	}
	return nil
}
