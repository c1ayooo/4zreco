package db

import (
	"sort"
	"strconv"
	"time"
)

// LLMUsage is one lightweight LLM-call metering row — the always-on usage ledger,
// distinct from llm_records (which stores full request/response bodies and is a
// gated debug feature). One row per completion call, written on both success and
// error, so token accounting is complete even for interrupted/failed runs. Carries
// only the dimensions needed to slice token spend (model / profile / task / agent),
// never any prompt or response content.
type LLMUsage struct {
	TaskID        string `json:"task_id"`        // task registry id (matches llm_records.task_id)
	ExplorationID int64  `json:"exploration_id"` // exploration id parsed from the session (0 = unknown/non-task)
	// IntentID (B7) 是该调用归属的具体意图（worker session 后缀 i<n>），0 = 不挂意图的
	// 调用（planner/mainagent/compactor）。态势据此给意图节点标 token 消耗。
	IntentID     int64  `json:"intent_id"`
	Worker       string `json:"worker"` // agent lane: worker / planner / mainagent / goals
	Model        string `json:"model"`
	ProfileName  string `json:"profile_name"`
	LatencyMs    int    `json:"latency_ms"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	CacheRead    int    `json:"cache_read"`
	CacheWrite   int    `json:"cache_write"`
	Status       string `json:"status"` // ok | error
}

const llmUsageSchema = `
CREATE TABLE IF NOT EXISTS llm_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    task_id        TEXT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    worker         TEXT,
    model          TEXT,
    profile_name   TEXT,
    latency_ms     INTEGER,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_read     INTEGER NOT NULL DEFAULT 0,
    cache_write    INTEGER NOT NULL DEFAULT 0,
    status         TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_task  ON llm_usage(task_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_model ON llm_usage(task_id, model);
CREATE INDEX IF NOT EXISTS idx_llm_usage_exp   ON llm_usage(exploration_id);
`

// llmUsageMigrations 是 EnsureLLMUsageTable 里的幂等补列（老库升列）。这张表不在
// schema.sql 里、由上面常量建表——常量只覆盖新库，老库的列补齐靠这里的 ALTER。
// intent_id（B7 意图级 token 记账）是第一列。
var llmUsageMigrations = []string{
	`ALTER TABLE llm_usage ADD COLUMN IF NOT EXISTS intent_id BIGINT`,
}

// EnsureLLMUsageTable creates the llm_usage metering table if it does not exist.
func (d *DB) EnsureLLMUsageTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(llmUsageSchema); err != nil {
		return err
	}
	// 老库补列（ALTER ... IF NOT EXISTS 幂等；新库常量里已有,这些 ALTER 是 no-op）。
	// llm_usage 是轻量账本（行多但每行窄），按 id 顺序逐条跑,量级恒小。
	for _, mig := range llmUsageMigrations {
		if _, err := tx.Exec(mig); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertLLMUsage appends one metering row. Best-effort: callers log and continue on
// error (a lost metering row must never break the LLM call).
func (d *DB) InsertLLMUsage(u *LLMUsage) error {
	var expID any
	if u.ExplorationID > 0 {
		expID = u.ExplorationID
	}
	var intentID any
	if u.IntentID > 0 {
		intentID = u.IntentID
	}
	_, err := d.Exec(`
INSERT INTO llm_usage(task_id, exploration_id, intent_id, worker, model, profile_name, latency_ms, input_tokens, output_tokens, cache_read, cache_write, status)
VALUES (NULLIF($1,''),$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12)`,
		u.TaskID, expID, intentID, u.Worker, u.Model, u.ProfileName,
		u.LatencyMs, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.Status)
	return err
}

// IntentTokenUsage is per-intent token spend for one exploration (B7): the
// always-on llm_usage ledger sliced by the session's i<n> suffix. Calls counts
// every completion (success or error) so interrupted runs still bill correctly.
// 不挂意图的调用（intent_id 为空）被 WHERE intent_id>0 排除,天然不在结果里。
type IntentTokenUsage struct {
	IntentID     int64 `json:"intent_id"`
	Calls        int   `json:"calls"`
	InputTokens  int64 `json:"input_tokens"` // 含 cache_read/cache_write:为这段上下文花的入口侧 token
	OutputTokens int64 `json:"output_tokens"`
}

// TokenByIntent aggregates one exploration's llm_usage rows grouped by intent.
// 总消耗口径 = input + cache_read + cache_write + output（「为拿到这段输出花了多少
// token」）。供 graph_overview 给意图节点标消耗（哪个方向烧了多少钱）。
func (s *ExplorationStore) TokenByIntent() ([]IntentTokenUsage, error) {
	rows, err := s.db.Query(`
SELECT intent_id, COUNT(*) AS calls,
       COALESCE(SUM(input_tokens+cache_read+cache_write),0),
       COALESCE(SUM(output_tokens),0)
FROM llm_usage
WHERE exploration_id=$1 AND intent_id>0
GROUP BY intent_id ORDER BY intent_id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntentTokenUsage{}
	for rows.Next() {
		var t IntentTokenUsage
		if err := rows.Scan(&t.IntentID, &t.Calls, &t.InputTokens, &t.OutputTokens); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TokenByModel aggregates a task's LLM token usage grouped by model, most-used
// first, from the always-on llm_usage ledger. taskID is the task registry id.
// Accurate even with per-agent model bindings, pool rotation/failover, and
// interrupted runs, since every call (success or error) is metered.
func (d *DB) TokenByModel(taskID string) ([]ModelTokenStat, error) {
	rows, err := d.Query(`
SELECT COALESCE(NULLIF(model,''),'(unknown)') AS model, COUNT(*) AS calls,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE COALESCE(task_id,'') = $1
GROUP BY model
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC, model`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ModelTokenStat{}
	for rows.Next() {
		var m ModelTokenStat
		if err := rows.Scan(&m.Model, &m.Calls, &m.InputTokens, &m.OutputTokens,
			&m.CacheReadTokens, &m.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ProfileUsage aggregates the whole ledger's token spend for one LLM profile
// (global, all tasks). Powers the dashboard's per-profile token card (new source).
type ProfileUsage struct {
	ProfileName      string `json:"profile_name"`
	Calls            int    `json:"calls"`
	Tasks            int    `json:"tasks"`
	InputTokens      int    `json:"input_tokens"`
	OutputTokens     int    `json:"output_tokens"`
	CacheReadTokens  int    `json:"cache_read_tokens"`
	CacheWriteTokens int    `json:"cache_write_tokens"`
}

// UsageByProfile returns global token spend grouped by profile name, most-used
// first. profile_name may be empty for calls made on env/non-persisted configs.
func (d *DB) UsageByProfile() ([]ProfileUsage, error) {
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name, COUNT(*) AS calls,
       COUNT(DISTINCT task_id) AS tasks,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
GROUP BY profile_name
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileUsage{}
	for rows.Next() {
		var p ProfileUsage
		if err := rows.Scan(&p.ProfileName, &p.Calls, &p.Tasks,
			&p.InputTokens, &p.OutputTokens, &p.CacheReadTokens, &p.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]ProfileUsage, len(out))
	for _, current := range out {
		byName[current.ProfileName] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenProfiles {
			current := byName[cold.ProfileName]
			current.ProfileName = cold.ProfileName
			current.Calls += cold.Calls
			current.Tasks += cold.Tasks
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			current.CacheWriteTokens += cold.CacheWriteTokens
			byName[cold.ProfileName] = current
		}
	}
	out = out[:0]
	for _, current := range byName {
		out = append(out, current)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].InputTokens + out[i].OutputTokens
		right := out[j].InputTokens + out[j].OutputTokens
		if left != right {
			return left > right
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// ProfileDayUsage is one (profile, UTC calendar day) token bucket for the daily
// chart. Unlike the activity-based chart, ts is the real call time, so this is
// actual per-day consumption rather than tokens bucketed by task creation date.
type ProfileDayUsage struct {
	ProfileName     string `json:"profile_name"`
	Date            string `json:"date"` // YYYY-MM-DD (UTC)
	InputTokens     int    `json:"input_tokens"`
	OutputTokens    int    `json:"output_tokens"`
	CacheReadTokens int    `json:"cache_read_tokens"`
}

// UsageDaily returns per-(profile, day) token buckets for the past `days` days
// (default 365 when days<=0), so the dashboard can slice by profile + range.
func (d *DB) UsageDaily(days int) ([]ProfileDayUsage, error) {
	if days <= 0 {
		days = 365
	}
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name,
       to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0)
FROM llm_usage
WHERE ts >= now() - ($1 * interval '1 day')
GROUP BY profile_name, day
ORDER BY day`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileDayUsage{}
	for rows.Next() {
		var p ProfileDayUsage
		if err := rows.Scan(&p.ProfileName, &p.Date, &p.InputTokens, &p.OutputTokens, &p.CacheReadTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	byKey := make(map[string]ProfileDayUsage, len(out))
	for _, current := range out {
		byKey[current.ProfileName+"\x00"+current.Date] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenDaily {
			if cold.Date < cutoff {
				continue
			}
			key := cold.ProfileName + "\x00" + cold.Date
			current := byKey[key]
			current.ProfileName = cold.ProfileName
			current.Date = cold.Date
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			byKey[key] = current
		}
	}
	out = out[:0]
	for _, current := range byKey {
		out = append(out, current)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// JudgeDayUsage is one UTC-day token bucket for the intercept fallback judge,
// for the config page's recent-spend sparkline.
type JudgeDayUsage struct {
	Date         string `json:"date"` // YYYY-MM-DD (UTC)
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// JudgeUsage is the cumulative token spend of the intercept fallback judge
// (worker='judge' rows in the always-on ledger), plus a recent daily series.
type JudgeUsage struct {
	Calls            int             `json:"calls"`
	InputTokens      int             `json:"input_tokens"`
	OutputTokens     int             `json:"output_tokens"`
	CacheReadTokens  int             `json:"cache_read_tokens"`
	CacheWriteTokens int             `json:"cache_write_tokens"`
	Daily            []JudgeDayUsage `json:"daily"`
}

// JudgeUsageStats returns the fallback judge's all-time token totals and a
// per-day series over the past `days` days (default 30). Sourced from the
// always-on llm_usage ledger, so it is accurate across pool rotation and
// interrupted/failed judge calls. days only bounds the daily series; totals are
// all-time.
func (d *DB) JudgeUsageStats(days int) (JudgeUsage, error) {
	if days <= 0 {
		days = 30
	}
	var u JudgeUsage
	err := d.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE worker = 'judge'`).Scan(&u.Calls, &u.InputTokens, &u.OutputTokens,
		&u.CacheReadTokens, &u.CacheWriteTokens)
	if err != nil {
		return JudgeUsage{}, err
	}
	rows, err := d.Query(`
SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
FROM llm_usage
WHERE worker = 'judge' AND ts >= now() - ($1 * interval '1 day')
GROUP BY day
ORDER BY day`, days)
	if err != nil {
		return JudgeUsage{}, err
	}
	defer rows.Close()
	u.Daily = []JudgeDayUsage{}
	for rows.Next() {
		var day JudgeDayUsage
		if err := rows.Scan(&day.Date, &day.Calls, &day.InputTokens, &day.OutputTokens); err != nil {
			return JudgeUsage{}, err
		}
		u.Daily = append(u.Daily, day)
	}
	if err := rows.Err(); err != nil {
		return JudgeUsage{}, err
	}
	return u, nil
}

// ParseExpID turns the exploration-id segment parsed from a session string into an
// int64 (0 when empty/non-numeric, e.g. chat sessions keyed by conversation id).
func ParseExpID(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// UsageModelRow 是 llm_usage 按 (profile, model) 的历史全量聚合行——成本估算
// 需要模型维度（定价按模型），而 UsageByProfile 只有 profile 维度。
type UsageModelRow struct {
	ProfileName  string `json:"profile_name"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	Calls        int    `json:"calls"`
}

// UsageByModel returns per-(profile, model) lifetime token totals. Only the
// live llm_usage ledger is covered (archived-task aggregates carry no model
// dimension); callers should label the derived cost as the live-table estimate.
func (d *DB) UsageByModel() ([]UsageModelRow, error) {
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name, COALESCE(model,'') AS model,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COUNT(*)
FROM llm_usage
GROUP BY profile_name, model
ORDER BY SUM(input_tokens)+SUM(output_tokens) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UsageModelRow{}
	for rows.Next() {
		var r UsageModelRow
		if err := rows.Scan(&r.ProfileName, &r.Model, &r.InputTokens, &r.OutputTokens, &r.Calls); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TaskUsage is one task's live token totals (for per-task cost display).
type TaskUsage struct {
	TaskID       string `json:"task_id"`
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// UsageByTask returns token totals for one exact task_id.
func (d *DB) UsageByTask(taskID string) (TaskUsage, error) {
	u := TaskUsage{TaskID: taskID}
	err := d.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
FROM llm_usage WHERE task_id=$1`, taskID).Scan(&u.Calls, &u.InputTokens, &u.OutputTokens)
	return u, err
}

// UsageModelsByTask returns per-model token rows for one task so the caller can
// price each model separately.
func (d *DB) UsageModelsByTask(taskID string) ([]UsageModelRow, error) {
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name, COALESCE(model,'') AS model,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COUNT(*)
FROM llm_usage WHERE task_id=$1
GROUP BY profile_name, model
ORDER BY SUM(input_tokens)+SUM(output_tokens) DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UsageModelRow{}
	for rows.Next() {
		var r UsageModelRow
		if err := rows.Scan(&r.ProfileName, &r.Model, &r.InputTokens, &r.OutputTokens, &r.Calls); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// WorkerUsageRow is one task's per-role token breakdown (worker/planner/main/
// compactor/judge/goals). 任务 5 实测 worker 占 76.8%、planner 非意图调用占 23.4%——
// 没有这个口径，「钱花在哪」只能靠人翻 activity 猜。
type WorkerUsageRow struct {
	Worker       string `json:"worker"`
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	CacheRead    int    `json:"cache_read_tokens"`
}

// UsageByWorkerTask returns per-worker token aggregates for one task, ordered by
// total tokens desc. Cache-read stays separate from input: 前缀缓存命中（任务 5 实测
// 92.9%）意味着 input 里绝大部分是廉价重复读，成本口径要与计费侧一致。
func (d *DB) UsageByWorkerTask(taskID string) ([]WorkerUsageRow, error) {
	rows, err := d.Query(`
SELECT COALESCE(worker,'') AS worker, COUNT(*),
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read_tokens),0)
FROM llm_usage WHERE task_id=$1
GROUP BY worker
ORDER BY SUM(input_tokens)+SUM(output_tokens) DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WorkerUsageRow{}
	for rows.Next() {
		var r WorkerUsageRow
		if err := rows.Scan(&r.Worker, &r.Calls, &r.InputTokens, &r.OutputTokens, &r.CacheRead); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
