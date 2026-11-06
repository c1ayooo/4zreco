package db

// hitl.go — P2 HITL（docs/Eino深度接入方案-2026-11-05.md §4-P2 第 1/3/4/6 条）的
// 宿主侧持久层。本包在红线 R1 下不得 import eino：adk.CheckPointStore 是结构化
// 接口（Get/Set/Delete 只用 ctx/string/[]byte），本文件的方法集按同签名实现，
// 由内核装配处直接当 CheckPointStore 用（Go 接口隐式满足，无需任何 eino 类型）。
//
//   - HitlAskInfo：工具审批中断的信息载荷（guard 产出 → gate 装进
//     StatefulInterrupt 的 state，随 checkpoint 的 gob 序列化——内核侧注册）；
//   - hitl_pending_checkpoint：审批↔checkpoint↔中断点的映射，人工决定后据此
//     精确 ResumeWithParams。进程重启后内存态全失，这张表是唯一的恢复钥匙；
//     决定投递/重领续跑消费后即删（一次性钥匙，防重放）；
//   - HitlResumeData + HMAC 签名：恢复数据必须能与库中决定行对上——伪造的
//     resume 无法放行任何工具调用（签名密钥 = 审批哈希链的 audit_key）；
//   - runner_checkpoints 兼任 eino checkpoint 载体（payload bytea，刀④ 只写
//     fingerprint 留痕的同一张表加列）：Set 用 INSERT … ON CONFLICT 支持同一
//     checkpoint id 的 re-interrupt 复写；payload 有字节上限（超限拒绝落库，
//     P2-6 劣化路径）。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ============================================================================
// 载荷类型（gob 序列化目标；导出字段 + 标量，注册在 acllm/hitl.go 的 init）
// ============================================================================

// HitlAskInfo 是一次审批挂起的完整描述：guard 的 ask 分支在 eino 模式下落库
// pending 后产出它，gate 把它装进 StatefulInterrupt 的 info 与 state。只带
// pending_id / 工具名 / 分类 / 输入摘要 / 裁决依据——工具入参明文既不能进
// checkpoint（体积不可控）也不能进中断信息（敏感度不可控）。
type HitlAskInfo struct {
	PendingID   int64  `json:"pending_id"`
	Tool        string `json:"tool"`
	Kind        string `json:"kind"` // rule | judge
	InputDigest string `json:"input_digest"`
	Reason      string `json:"reason"` // 裁决依据：规则名/模型理由（卡片已有，供中断侧核对）
}

// HitlResumeData 是人工决定后的恢复数据（决定行 + HMAC 签名）。
// ResumeWithParams 的 Targets 值原样投递；gate 在中断点取回后交 guard 核对。
type HitlResumeData struct {
	PendingID  int64  `json:"pending_id"`
	DecisionID int64  `json:"decision_id"` // 决定行 id（intercept_decisions）
	Allowed    bool   `json:"allowed"`
	Sig        string `json:"sig"` // HMAC-SHA256(audit_key, canonical(payload))
}

type hitlSigPayload struct {
	PendingID  int64 `json:"pending_id"`
	DecisionID int64 `json:"decision_id"`
	Allowed    bool  `json:"allowed"`
}

func (r *HitlResumeData) sign(key []byte) string {
	mac := hmac.New(sha256.New, key)
	raw, _ := json.Marshal(hitlSigPayload{r.PendingID, r.DecisionID, r.Allowed})
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignHitlResume 用审计密钥对一条决定行签名，产出可校验的恢复数据。
// 决定行必须已存在（ResolveIntercept 成功后调用）；找不到决定行返回 nil。
func (d *DB) SignHitlResume(pendingID, decisionID int64, allowed bool) *HitlResumeData {
	r := &HitlResumeData{PendingID: pendingID, DecisionID: decisionID, Allowed: allowed}
	r.Sig = r.sign(d.auditChainKey())
	return r
}

// VerifyHitlResume 校验恢复数据：签名一致，且库中决定行存在、pending 匹配、
// 决定方向与数据一致。timeout 决定按其 action（allow|deny）核对——超时放行
// 语义（TimeoutAction=allow）经同一条验签链落地。任何一项不满足都不可放行。
func (d *DB) VerifyHitlResume(r *HitlResumeData) bool {
	if r == nil || r.Sig == "" || r.DecisionID <= 0 || r.PendingID <= 0 {
		return false
	}
	var decision, action string
	err := d.QueryRow(`SELECT decision, action FROM intercept_decisions
		WHERE id=$1 AND pending_id=$2`, r.DecisionID, r.PendingID).Scan(&decision, &action)
	if err != nil {
		return false
	}
	switch decision {
	case "allowed":
		if !r.Allowed {
			return false
		}
	case "denied":
		if r.Allowed {
			return false
		}
	case "timeout":
		if r.Allowed != (action == "allow") {
			return false
		}
	default: // anchor 等：恢复数据只对真实决定行有意义
		return false
	}
	return hmac.Equal([]byte(r.sign(d.auditChainKey())), []byte(r.Sig))
}

// ============================================================================
// ctx seams（guard ↔ gate 的中断/恢复信号；类型全部 eino-free，R4 红线不动）
// ============================================================================

// hitlResumeKey 携带 *HitlResumeData（gate 在恢复重入时注入，guard 核对）。
type hitlResumeKey struct{}

// WithHitlResume 供内核在恢复重入时把决定注入工具调用上下文。
func WithHitlResume(ctx context.Context, r *HitlResumeData) context.Context {
	return context.WithValue(ctx, hitlResumeKey{}, r)
}

// HitlResumeFrom 由 guard 读取；nil = 非恢复流（正常首轮判定）。
func HitlResumeFrom(ctx context.Context) *HitlResumeData {
	r, _ := ctx.Value(hitlResumeKey{}).(*HitlResumeData)
	return r
}

// AskSignal 是 gate 注入 ctx 的可变信号持有者：guard 的 ask 分支（eino 模式）
// 落库 pending 后把 HitlAskInfo 写进来，PreToolUse 返回后 gate 读到即以
// StatefulInterrupt 中断本次调用。norma hook.Result 无法扩展（外部模块），且
// guard→gate 隔着多层旁路包装链（toollog/idlestop/steer），ctx 是唯一不破坏
// 任何包装层的信号通道。
type AskSignal struct {
	info *HitlAskInfo
}

func (s *AskSignal) set(info *HitlAskInfo) { s.info = info }

type askSignalKey struct{}

// WithAskSignal 由 gate 在 hitl 模式下、调用 PreToolUse 之前注入。
func WithAskSignal(ctx context.Context) context.Context {
	return context.WithValue(ctx, askSignalKey{}, &AskSignal{})
}

// RaiseAskInterrupt 由 guard 的 ask 分支调用：把审批挂起交给 gate（gate 未开
// hitl 时 sig 为 nil，调用方按 channel 模式继续阻塞等待）。调用前必须以
// HasAskSignal 核对持有者存在（fail-closed 闸，见其注释）。
func RaiseAskInterrupt(ctx context.Context, info *HitlAskInfo) {
	if sig, ok := ctx.Value(askSignalKey{}).(*AskSignal); ok && sig != nil {
		sig.set(info)
	}
}

// HasAskSignal reports whether the gate injected a signal holder. 三半装配
// （guard hitlMode / gate SetHitl / checkpoint store）的读取时点可以漂移——灰度期
// settings 把开关翻回 channel 后，常驻内存的任务 guard 仍 hitlOn 而新装配的 gate
// 不再注入持有者。guard 的 ask 分支必须先核对持有者存在才走中断路径，否则回退
// channel 阻塞语义：没有这个 fail-closed 闸，RaiseAskInterrupt 会在无持有者时
// 静默丢弃、工具无审批直跑（评审第 1 轮 #2）。
func HasAskSignal(ctx context.Context) bool {
	sig, _ := ctx.Value(askSignalKey{}).(*AskSignal)
	return sig != nil
}

// AskInterruptFrom 由 gate 在 PreToolUse 返回后读取；nil = 本次调用没有 ask
// 挂起（channel 模式或判定未到 ask）。
func AskInterruptFrom(ctx context.Context) *HitlAskInfo {
	sig, _ := ctx.Value(askSignalKey{}).(*AskSignal)
	if sig == nil {
		return nil
	}
	return sig.info
}

// ============================================================================
// CheckPointStore（eino adk 结构化接口的同签名实现）
// ============================================================================

// CheckpointPayloadLimit 是单个 checkpoint 载荷的字节上限（方案 §6「checkpoint
// 体积」风险的对冲；RunCtx 含工作集消息，依赖 compaction 边界，超限即拒绝落库
// 走 P2-6 劣化）。与 schema.sql 的 CHECK 约束同值，双保险。
const CheckpointPayloadLimit = 32 << 20 // 32 MiB

// CheckpointVersion 是 checkpoint 消费方（本仓库）的格式版本号。eino 升级改
// gob 形状时递增，恢复路径读到旧版本即走 P2-6 回退。
const CheckpointVersion = 1

// ErrCheckpointTooLarge：payload 超过上限，拒绝落库（Go 侧兜底，PG CHECK 同值）。
var ErrCheckpointTooLarge = errors.New("hitl: checkpoint 载荷超过上限")

// ErrCheckpointUnavailable：checkpoint 缺失/损坏/版本不兼容。恢复路径按 P2-6
// 回退——决定照常落库，运行侧按 denied/重跑收尾，审批操作不得被阻塞。
var ErrCheckpointUnavailable = errors.New("hitl: checkpoint 不可用")

// GetCheckpoint implements adk.CheckPointStore（结构化满足，本包无 eino import）。
func (d *DB) GetCheckpoint(_ context.Context, checkPointID string) ([]byte, bool, error) {
	var payload []byte
	err := d.QueryRow(`SELECT payload FROM runner_checkpoints WHERE checkpoint_id=$1 AND payload IS NOT NULL`, checkPointID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return payload, true, nil
}

// SetCheckpoint implements adk.CheckPointStore。INSERT … ON CONFLICT DO UPDATE：
// 同一 checkpoint id 的 re-interrupt（官方语义）复写 payload 到最新状态。
// fingerprint/session_id/agent_key 由装配点先行写入（RecordRunnerCheckpoint P2
// 起携带 checkpoint id），冲突时不覆盖——装配留痕是恢复校验的基准。
func (d *DB) SetCheckpoint(_ context.Context, checkPointID string, checkPoint []byte) error {
	if len(checkPoint) > CheckpointPayloadLimit {
		return ErrCheckpointTooLarge
	}
	_, err := d.Exec(`INSERT INTO runner_checkpoints
(session_id, agent_key, checkpoint_id, fingerprint, payload, kind, version, created_at, updated_at)
VALUES ('', '', $1, '', $2, 'hitl', $3, now(), now())
ON CONFLICT (checkpoint_id) WHERE checkpoint_id <> '' DO UPDATE
SET payload=EXCLUDED.payload, kind='hitl', version=EXCLUDED.version, updated_at=now()`,
		checkPointID, checkPoint, CheckpointVersion)
	return err
}

// DeleteCheckpoint implements adk.CheckPointDeleter（任务终态/孤儿清理）。
func (d *DB) DeleteCheckpoint(_ context.Context, checkPointID string) error {
	_, err := d.Exec(`DELETE FROM runner_checkpoints WHERE checkpoint_id=$1`, checkPointID)
	return err
}

// HitlCheckpointMeta returns the stored fingerprint + version for one checkpoint
// row（P2-3 恢复校验 / P2-6 回退判据）。ok=false = 无该 checkpoint。
func (d *DB) HitlCheckpointMeta(checkpointID string) (fingerprint string, version int, ok bool, err error) {
	var fp sql.NullString
	err = d.QueryRow(`SELECT fingerprint, version FROM runner_checkpoints
WHERE checkpoint_id=$1 AND payload IS NOT NULL`, checkpointID).Scan(&fp, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return fp.String, version, true, nil
}

// DeleteCheckpointsBySession removes every checkpoint payload recorded for one
// transcript session and their hitl mappings（任务终态清理：worker 侧意图收场
// 时调用；decide 后已消费的映射由投递方即时删除，这里兜底）。
func (d *DB) DeleteCheckpointsBySession(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if _, err := d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE checkpoint_id IN
(SELECT checkpoint_id FROM runner_checkpoints WHERE session_id=$1)`, sessionID); err != nil {
		return err
	}
	_, err := d.Exec(`DELETE FROM runner_checkpoints WHERE session_id=$1`, sessionID)
	return err
}

// ============================================================================
// 映射表：pending ↔ checkpoint ↔ interrupt（恢复钥匙，消费即删）
// ============================================================================

// SaveHitlMapping 记录审批↔checkpoint↔中断点映射（decide 侧恢复的钥匙）。
// 同一 pending 重挂（re-interrupt 换 checkpoint）复写。
func (d *DB) SaveHitlMapping(pendingID int64, checkpointID, interruptID, taskID string) error {
	_, err := d.Exec(`INSERT INTO hitl_pending_checkpoint(pending_id, checkpoint_id, interrupt_id, task_id, created_at)
VALUES ($1,$2,$3,NULLIF($4,''),now())
ON CONFLICT (pending_id) DO UPDATE SET checkpoint_id=EXCLUDED.checkpoint_id, interrupt_id=EXCLUDED.interrupt_id`,
		pendingID, checkpointID, interruptID, taskID)
	return err
}

// HitlMapping 恢复决定时取回映射（无映射 = channel 模式或已消费；两者都按
// 「无恢复路径」处理，调用方走 P2-6 劣化）。
func (d *DB) HitlMapping(pendingID int64) (checkpointID, interruptID, taskID string, err error) {
	var cp, ii, tid sql.NullString
	err = d.QueryRow(`SELECT checkpoint_id, interrupt_id, task_id FROM hitl_pending_checkpoint WHERE pending_id=$1`, pendingID).
		Scan(&cp, &ii, &tid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", err
	}
	return cp.String, ii.String, tid.String, nil
}

// ConsumeHitlMapping deletes the one-shot resume key（投递/重领消费后调用；
// 二次 resume 重放同一决定被钥匙删除挡住）。
func (d *DB) ConsumeHitlMapping(pendingID int64) error {
	_, err := d.Exec(`DELETE FROM hitl_pending_checkpoint WHERE pending_id=$1`, pendingID)
	return err
}

// HasHitlPendingCheckpoint reports whether a task has unconsumed hitl mappings
// （P2-5 暂停=park 的判定点：有钥匙的 run 在等决定，pause 不 cancel）。
func (d *DB) HasHitlPendingCheckpoint(taskID string) (bool, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(1) FROM hitl_pending_checkpoint WHERE task_id=$1`, taskID).Scan(&n)
	return n > 0, err
}

// PendingHitlApproval 是 reaper 扫描的一行：仍挂起的审批及其映射与固化超时。
type PendingHitlApproval struct {
	PendingID    int64     `json:"pending_id"`
	CreatedAt    time.Time `json:"created_at"`
	CheckpointID string    `json:"checkpoint_id"`
	InterruptID  string    `json:"interrupt_id"`
	TaskID       string    `json:"task_id"`
	// AskTimeoutSeconds/Action 是 ask 创建时固化进 audit 快照的超时策略
	//（0/空 = 无声明，用平台级兜底）。
	AskTimeoutSeconds int    `json:"ask_timeout_seconds"`
	AskTimeoutAction  string `json:"ask_timeout_action"`
}

// PendingHitlApprovals lists still-pending asks joined with their mappings
// （reaper 扫描器：goroutine per-ask timer 的替代，方案 §4-P2 第 4 条）。
func (d *DB) PendingHitlApprovals() ([]PendingHitlApproval, error) {
	rows, err := d.Query(`SELECT ip.id, ip.created_at,
	       COALESCE(h.checkpoint_id,''), COALESCE(h.interrupt_id,''), COALESCE(h.task_id,''),
	       COALESCE((ip.audit->>'ask_timeout_seconds')::int, 0),
	       COALESCE(ip.audit->>'ask_timeout_action','')
	FROM intercept_pending ip
	JOIN hitl_pending_checkpoint h ON h.pending_id = ip.id
	WHERE NOT EXISTS (SELECT 1 FROM intercept_decisions d WHERE d.pending_id = ip.id)
	ORDER BY ip.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingHitlApproval
	for rows.Next() {
		var p PendingHitlApproval
		if err := rows.Scan(&p.PendingID, &p.CreatedAt, &p.CheckpointID, &p.InterruptID, &p.TaskID,
			&p.AskTimeoutSeconds, &p.AskTimeoutAction); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DecidedHitlResume 是重领重建（跨进程恢复）的一行：已有决定、钥匙未消费、
// checkpoint 仍在的审批。
type DecidedHitlResume struct {
	PendingID    int64
	CheckpointID string
	InterruptID  string
	DecisionID   int64
	Decision     string // allowed | denied | timeout
	Action       string // allow | deny | ''
	Fingerprint  string // checkpoint 行上记录的装配指纹（恢复校验基准）
}

// DecidedHitlResumesForSession lists decided-but-unconsumed hitl mappings whose
// checkpoint belongs to one transcript session（进程重启后 worker 重领该意图时
// 的确定性重建输入；没有行 = 无待续跑）。
func (d *DB) DecidedHitlResumesForSession(sessionID string) ([]DecidedHitlResume, error) {
	rows, err := d.Query(`SELECT h.pending_id, h.checkpoint_id, h.interrupt_id,
	       dec.id, dec.decision, dec.action, COALESCE(rc.fingerprint,'')
	FROM hitl_pending_checkpoint h
	JOIN runner_checkpoints rc ON rc.checkpoint_id = h.checkpoint_id AND rc.payload IS NOT NULL
	JOIN intercept_decisions dec ON dec.pending_id = h.pending_id
	WHERE rc.session_id = $1
	ORDER BY h.pending_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DecidedHitlResume
	for rows.Next() {
		var r DecidedHitlResume
		var fp sql.NullString
		if err := rows.Scan(&r.PendingID, &r.CheckpointID, &r.InterruptID,
			&r.DecisionID, &r.Decision, &r.Action, &fp); err != nil {
			return nil, err
		}
		r.Fingerprint = fp.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastInterceptDecisionID returns the id of a pending's decision row
// （ResolveIntercept 不回传 id；签名需要它）。ok=false = 未决定。
func (d *DB) LastInterceptDecisionID(pendingID int64) (int64, bool, error) {
	var id int64
	err := d.QueryRow(`SELECT id FROM intercept_decisions WHERE pending_id=$1`, pendingID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// HitlDecision returns a pending's decision row in full（停靠自投递用）：
// 决定先于停靠注册到达时，park 钩子据此自查库中已有决定并签名续跑
// （decide 接口对已决行 409 不会再投递，reaper 又排除已决行——这条自查是
// 乱序决定/重启前落库的决定的唯一投递通道）。ok=false = 未决定。
func (d *DB) HitlDecision(pendingID int64) (decisionID int64, decision, action string, ok bool, err error) {
	err = d.QueryRow(`SELECT id, decision, action FROM intercept_decisions WHERE pending_id=$1`, pendingID).
		Scan(&decisionID, &decision, &action)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", false, nil
	}
	if err != nil {
		return 0, "", "", false, err
	}
	return decisionID, decision, action, true, nil
}

// HitlAllowedFromDecision 把决定行折算成恢复方向：allowed 直取；timeout 按
// 固化策略（action=allow 即放行，与 channel 模式 timer 收口同语义）；
// denied/auto_cancel 一律不放行。
func HitlAllowedFromDecision(decision, action string) bool {
	if decision == "allowed" {
		return true
	}
	return decision == "timeout" && action == "allow"
}

// ============================================================================
// CheckPointStore 适配（adk.CheckPointStore 的结构化满足；接口方法名 Get/Set
// 与 db 层语义命名冲突，故用薄适配器——装配处 e.m.pg.AsCheckpointStore()）
// ============================================================================

// CheckpointStore 是 adk.CheckPointStore 的 db 适配（方法签名只用 ctx/string/
// []byte，本包无 eino import——R1 红线不动）。
type CheckpointStore struct{ d *DB }

// AsCheckpointStore 返回 eino Runner 用的存储适配。
func (d *DB) AsCheckpointStore() CheckpointStore { return CheckpointStore{d} }

// Get implements adk.CheckPointStore.
func (s CheckpointStore) Get(ctx context.Context, checkPointID string) ([]byte, bool, error) {
	return s.d.GetCheckpoint(ctx, checkPointID)
}

// Set implements adk.CheckPointStore.
func (s CheckpointStore) Set(ctx context.Context, checkPointID string, checkPoint []byte) error {
	return s.d.SetCheckpoint(ctx, checkPointID, checkPoint)
}

// Delete implements adk.CheckPointDeleter.
func (s CheckpointStore) Delete(ctx context.Context, checkPointID string) error {
	return s.d.DeleteCheckpoint(ctx, checkPointID)
}
