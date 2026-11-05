package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// CompleteTaskArchive performs the hot-store compaction only after the external
// package has been fully written and checksummed. The task/exploration rows remain
// as minimal ID stubs; all heavyweight task-owned rows move into the package.
func (d *DB) CompleteTaskArchive(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	archivePath, sha256 string,
	originalSize, compressedSize int64,
) error {
	if snapshot == nil || snapshot.FormatVersion != TaskArchiveFormatVersion {
		return ErrTaskArchiveFormatMismatch
	}
	countsRaw, err := json.Marshal(snapshot.DataCounts)
	if err != nil {
		return err
	}
	statsRaw, err := json.Marshal(snapshot.AggregateStats)
	if err != nil {
		return err
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return err
	}
	if state != Archiving || taskID != snapshot.TaskID || expID != snapshot.ExplorationID {
		return fmt.Errorf("%w: archive snapshot identity/state mismatch", ErrTaskArchiveState)
	}
	var dependent int64
	err = tx.QueryRow(`SELECT child.id FROM task_relations relation
JOIN tasks child ON child.id=relation.task_id AND child.deleted_at IS NULL
WHERE relation.source_task_id=$1 LIMIT 1`, taskID).Scan(&dependent)
	if err == nil {
		return fmt.Errorf("%w: task %d", ErrTaskArchiveDependent, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Prevent task/asset ownership from changing while exclusivity is rechecked.
	if _, err := tx.Exec(`LOCK TABLE assets, exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	// 审批行不再物理删除（P0-A2，append-only + 触发器拒绝）：快照照旧导出，
	// 库内行保留，任务侧列表在归档期间由「status=timeout 决定行」收口（见
	// restoreInterceptRows 的对称逻辑）。
	if _, err := tx.Exec(`DELETE FROM llm_records WHERE COALESCE(task_id,'')=$1`, strconv.FormatInt(taskID, 10)); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM llm_usage WHERE COALESCE(task_id,'')=$1 OR exploration_id=$2`, strconv.FormatInt(taskID, 10), expID); err != nil {
		return err
	}
	for _, table := range []string{"skill_usage", "tool_usage"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE task_id=$1 OR exploration_id=$2`, taskID, expID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM side_question_sessions WHERE task_id=$1`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM findings WHERE task_id=$1`, taskID); err != nil {
		return err
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM task_relations WHERE task_id=$1 OR source_task_id=$1`, []any{taskID}},
		{`DELETE FROM task_asset_links WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_llm_profiles WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_scope WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_constraints WHERE exploration_id=$1`, []any{expID}},
		{`DELETE FROM activity WHERE exploration_id=$1`, []any{expID}},
		{`DELETE FROM exploration_nodes WHERE exploration_id=$1`, []any{expID}},
	} {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE assets SET task_ids=array_remove(task_ids,$1) WHERE $1=ANY(task_ids)`, taskID); err != nil {
		return err
	}
	if len(snapshot.ExclusiveAssetIDs) > 0 {
		if _, err := tx.Exec(`DELETE FROM assets asset
WHERE asset.id=ANY($2::bigint[]) AND asset.company_id IS NULL
AND NOT EXISTS (SELECT 1 FROM tasks task WHERE task.id<>$1 AND task.deleted_at IS NULL AND task.id=ANY(asset.task_ids))
AND NOT EXISTS (
 SELECT 1 FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id
 JOIN tasks task ON task.exploration_id=node.exploration_id
 WHERE anchor.asset_id=asset.id AND task.id<>$1 AND task.deleted_at IS NULL
)`, taskID, snapshot.ExclusiveAssetIDs); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE explorations SET description='',goal='',status='open' WHERE id=$1`, expID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE tasks SET
 name='',category_id=NULL,description='',goal='',paused=true,queued=false,queued_at=NULL,queue_mode='',
 llm_profile_id=NULL,active_llm_profile_id=NULL,llm_chain_revision=llm_chain_revision+1,
 company_id=NULL,parent_ref=NULL,timeout_seconds=0,coverage_enabled=true,pinned_at=NULL,
 first_run_at=NULL,deadline_at=NULL,archived_at=now(),deleted_at=now()
WHERE id=$1`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE task_archives SET
	 state=$2,phase='ready',progress=100,error='',archive_path=$3,sha256=$4,
	 original_size=$5,compressed_size=$6,data_counts=$7,aggregate_stats=$8,
	 format_version=$9,archived_at=now(),warnings='[]'
WHERE id=$1`, archiveID, ArchiveReady, archivePath, sha256, originalSize, compressedSize,
		string(countsRaw), string(statsRaw), snapshot.FormatVersion); err != nil {
		return err
	}
	return tx.Commit()
}

// RestoreTaskArchive restores PostgreSQL rows from a verified manifest. It is
// idempotent for accounting/traffic retry scenarios and returns non-fatal
// warnings for global objects that intentionally are not recreated.
func (d *DB) RestoreTaskArchive(archiveID int64, snapshot *TaskArchiveSnapshot, remainingTimeoutSeconds int64) ([]string, error) {
	return d.restoreTaskArchive(archiveID, snapshot, remainingTimeoutSeconds, nil)
}

// RestoreTaskArchiveWithLLMRecords restores a v2 package whose heavyweight LLM
// record history is stored as a sequence of JSON objects outside manifest.json.
func (d *DB) RestoreTaskArchiveWithLLMRecords(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	remainingTimeoutSeconds int64,
	llmRecords io.Reader,
) ([]string, error) {
	if llmRecords == nil {
		return nil, errors.New("nil streamed LLM record reader")
	}
	return d.restoreTaskArchive(archiveID, snapshot, remainingTimeoutSeconds, llmRecords)
}

func (d *DB) restoreTaskArchive(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	remainingTimeoutSeconds int64,
	llmRecords io.Reader,
) ([]string, error) {
	if snapshot == nil || !IsTaskArchiveFormatSupported(snapshot.FormatVersion) {
		return nil, ErrTaskArchiveFormatMismatch
	}
	streamedLLMRecords := snapshot.StreamedTables["llm_records"]
	if (len(snapshot.StreamedTables) > 0 && snapshot.FormatVersion < 2) ||
		len(snapshot.StreamedTables) > 1 ||
		(len(snapshot.StreamedTables) == 1 && streamedLLMRecords != TaskArchiveLLMRecordsPath) {
		return nil, fmt.Errorf("%w: unsupported streamed table metadata", ErrTaskArchiveFormatMismatch)
	}
	if streamedLLMRecords != "" && llmRecords == nil {
		return nil, fmt.Errorf("%w: streamed LLM records are missing", ErrTaskArchiveFormatMismatch)
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return nil, err
	}
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return nil, err
	}
	if state != Restoring || taskID != snapshot.TaskID || expID != snapshot.ExplorationID {
		return nil, fmt.Errorf("%w: restore snapshot identity/state mismatch", ErrTaskArchiveState)
	}
	warnings := []string{}
	assetMap, assetWarnings, err := restoreArchiveAssets(tx, taskID, snapshot.Tables["assets"])
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, assetWarnings...)

	// The task row exists as an archived stub. Restore its global references only
	// when the current instance still owns them; never recreate categories/profiles.
	taskRows, err := decodeArchiveRows(snapshot.Tables["tasks"])
	if err != nil || len(taskRows) != 1 {
		return nil, fmt.Errorf("restore task row: expected one row: %w", err)
	}
	taskRow := taskRows[0]
	categoryID, _ := jsonInt64(taskRow["category_id"])
	if categoryID > 0 && !rowExists(tx, "task_categories", categoryID) {
		taskRow["category_id"] = nil
		warnings = append(warnings, fmt.Sprintf("任务分类 %d 已删除，已恢复为未分类", categoryID))
	}
	companyID, _ := jsonInt64(taskRow["company_id"])
	if companyID > 0 && !rowExists(tx, "companies", companyID) {
		taskRow["company_id"] = nil
		warnings = append(warnings, fmt.Sprintf("任务企业 %d 已删除，企业关联已跳过", companyID))
	}
	for _, key := range []string{"llm_profile_id", "active_llm_profile_id"} {
		profileID, _ := jsonInt64(taskRow[key])
		if profileID > 0 && !rowExists(tx, "llm_profiles", profileID) {
			taskRow[key] = nil
			warnings = append(warnings, fmt.Sprintf("LLM 配置 %d 已删除，已从任务配置中移除", profileID))
		}
	}
	if err := restoreExplorationStub(tx, snapshot.Tables["explorations"], expID); err != nil {
		return nil, err
	}
	if err := restoreTaskStub(tx, taskRow, taskID, remainingTimeoutSeconds); err != nil {
		return nil, err
	}

	remappedTables, err := remapArchiveAssetReferences(snapshot.Tables, assetMap)
	if err != nil {
		return nil, err
	}
	remappedTables["findings"], err = normalizeArchivedFindingVersions(remappedTables["findings"])
	if err != nil {
		return nil, err
	}
	// Insert graph rows in foreign-key order. The archived stub has no graph rows,
	// so an ID conflict signals external corruption and must stop the restore.
	for _, table := range []string{"exploration_nodes", "exploration_edges", "exploration_anchors", "task_constraints", "activity"} {
		if err := insertArchiveRows(tx, table, remappedTables[table]); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
	}
	if warning, err := restoreTaskRelations(tx, taskID, remappedTables["task_relations"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	for _, table := range []string{"side_question_sessions", "side_question_requests"} {
		if err := insertArchiveRows(tx, table, remappedTables[table]); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
	}
	if warning, err := restoreTaskScopes(tx, remappedTables["task_scope"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	if warning, err := restoreTaskLLMProfiles(tx, remappedTables["task_llm_profiles"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	for _, table := range []string{"task_asset_links", "findings"} {
		if err := insertArchiveRows(tx, table, remappedTables[table]); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
	}
	if err := restoreFindingTrafficTx(tx, snapshot); err != nil {
		return nil, fmt.Errorf("restore finding traffic: %w", err)
	}
	if streamedLLMRecords != "" {
		count, err := insertArchiveJSONSequenceRows(tx, "llm_records", llmRecords)
		if err != nil {
			return nil, fmt.Errorf("restore llm_records: %w", err)
		}
		if expected := snapshot.DataCounts["llm_records"]; count != expected {
			return nil, fmt.Errorf("restore llm_records: row count %d does not match manifest %d", count, expected)
		}
	} else if err := insertArchiveRows(tx, "llm_records", remappedTables["llm_records"]); err != nil {
		return nil, fmt.Errorf("restore llm_records: %w", err)
	}
	for _, table := range []string{"llm_usage", "skill_usage", "tool_usage"} {
		if err := insertArchiveRows(tx, table, remappedTables[table]); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
	}
	if err := restoreInterceptRows(tx, remappedTables["intercept_pending"],
		remappedTables["intercept_decisions"], remappedTables["intercept_executions"]); err != nil {
		return nil, err
	}
	warningsRaw, _ := json.Marshal(warnings)
	if _, err := tx.Exec(`UPDATE task_archives SET warnings=$2,phase='database_restored',progress=85,error='' WHERE id=$1`, archiveID, string(warningsRaw)); err != nil {
		return nil, err
	}
	return warnings, tx.Commit()
}

func restoreExplorationStub(tx *sql.Tx, raw json.RawMessage, expID int64) error {
	_, err := tx.Exec(`UPDATE explorations current SET
 description=archived.description,goal=archived.goal,status=archived.status,
 created_at=archived.created_at,updated_at=archived.updated_at
FROM json_populate_record(NULL::explorations,$2::json) archived
WHERE current.id=$1 AND archived.id=$1`, expID, string(firstArchiveRow(raw)))
	return err
}

func restoreTaskStub(tx *sql.Tx, row map[string]any, taskID, remaining int64) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE tasks current SET
 name=archived.name,category_id=archived.category_id,description=archived.description,goal=archived.goal,
 status=archived.status,paused=archived.paused,queued=false,queued_at=NULL,queue_mode='',
 llm_profile_id=archived.llm_profile_id,active_llm_profile_id=archived.active_llm_profile_id,
 llm_chain_revision=archived.llm_chain_revision,company_id=archived.company_id,parent_ref=archived.parent_ref,
 timeout_seconds=archived.timeout_seconds,plan_heartbeat_seconds=archived.plan_heartbeat_seconds,
 coverage_enabled=archived.coverage_enabled,pinned_at=archived.pinned_at,first_run_at=archived.first_run_at,
 deadline_at=CASE WHEN archived.paused AND $3>0 THEN now()+make_interval(secs=>$3::double precision)
                  ELSE archived.deadline_at END,
 deleted_at=NULL,archived_at=NULL,completed_at=archived.completed_at,
 created_at=archived.created_at,updated_at=archived.updated_at
FROM json_populate_record(NULL::tasks,$2::json) archived
WHERE current.id=$1 AND archived.id=$1`, taskID, string(raw), remaining)
	return err
}

func firstArchiveRow(raw json.RawMessage) json.RawMessage {
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		return json.RawMessage("{}")
	}
	return rows[0]
}

func decodeArchiveRows(raw json.RawMessage) ([]map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var rows []map[string]any
	if err := decoder.Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func rowExists(tx *sql.Tx, table string, id int64) bool {
	if table != "task_categories" && table != "llm_profiles" && table != "companies" && table != "tasks" && table != "assets" {
		return false
	}
	var exists bool
	_ = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&exists)
	return exists
}

func insertArchiveRows(tx *sql.Tx, table string, raw json.RawMessage) error {
	// json_populate_recordset inserts NULL for absent columns, bypassing SQL
	// defaults. Preserve compatibility with v3 archives predating side memory.
	if (table == "side_question_sessions" || table == "side_question_requests") && len(raw) > 0 {
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rows); err != nil {
			return err
		}
		field := "memory"
		if table == "side_question_requests" {
			field = "context_info"
		}
		for _, row := range rows {
			if len(row[field]) == 0 || string(row[field]) == "null" {
				row[field] = json.RawMessage(`{}`)
			}
		}
		var err error
		raw, err = json.Marshal(rows)
		if err != nil {
			return err
		}
	}
	allowed := map[string]bool{
		"exploration_nodes": true, "exploration_edges": true, "exploration_anchors": true,
		"task_constraints": true, "activity": true, "task_asset_links": true, "findings": true,
		"llm_records": true, "llm_usage": true, "skill_usage": true, "tool_usage": true,
		"side_question_sessions": true, "side_question_requests": true,
	}
	if !allowed[table] {
		return fmt.Errorf("archive restore table %q is not allowed", table)
	}
	if rawRowCount(raw) == 0 {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO `+table+` SELECT * FROM json_populate_recordset(NULL::`+table+`,$1::json)`, string(raw))
	return err
}

func insertArchiveJSONSequenceRows(tx *sql.Tx, table string, reader io.Reader) (int64, error) {
	if table != "llm_records" {
		return 0, fmt.Errorf("archive streamed restore table %q is not allowed", table)
	}
	statement, err := tx.Prepare(`INSERT INTO llm_records SELECT * FROM json_populate_record(NULL::llm_records,$1::json)`)
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	decoder := json.NewDecoder(reader)
	var count int64
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return 0, err
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return 0, errors.New("streamed archive row must be a JSON object")
		}
		if _, err := statement.Exec(string(trimmed)); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func restoreArchiveAssets(tx *sql.Tx, taskID int64, raw json.RawMessage) (map[int64]int64, []string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, nil, err
	}
	mapping := make(map[int64]int64, len(rows))
	warnings := []string{}
	for _, row := range rows {
		oldID, ok := jsonInt64(row["id"])
		if !ok || oldID <= 0 {
			return nil, nil, errors.New("archived asset has invalid id")
		}
		if companyID, ok := jsonInt64(row["company_id"]); ok && companyID > 0 && !rowExists(tx, "companies", companyID) {
			row["company_id"] = nil
			row["company_source"] = "explicit"
			warnings = append(warnings, fmt.Sprintf("资产 %d 的企业 %d 已删除，已恢复为未归属", oldID, companyID))
		}
		if existing, found, err := findArchiveAssetNaturalID(tx, row); err != nil {
			return nil, nil, err
		} else if found {
			mapping[oldID] = existing
			if _, err := tx.Exec(`UPDATE assets SET task_ids=CASE WHEN $1=ANY(task_ids) THEN task_ids ELSE array_append(task_ids,$1) END WHERE id=$2`, taskID, existing); err != nil {
				return nil, nil, err
			}
			continue
		}
		candidate := oldID
		if rowExists(tx, "assets", oldID) {
			if err := tx.QueryRow(`SELECT nextval(pg_get_serial_sequence('assets','id'))`).Scan(&candidate); err != nil {
				return nil, nil, err
			}
			row["id"] = candidate
			warnings = append(warnings, fmt.Sprintf("资产 ID %d 已被占用，恢复为 %d", oldID, candidate))
		}
		row["task_ids"] = mergeJSONTaskID(row["task_ids"], taskID)
		assetRaw, _ := json.Marshal(row)
		res, err := tx.Exec(`INSERT INTO assets SELECT * FROM json_populate_record(NULL::assets,$1::json) ON CONFLICT DO NOTHING`, string(assetRaw))
		if err != nil {
			return nil, nil, err
		}
		inserted, _ := res.RowsAffected()
		if inserted == 0 {
			existing, found, findErr := findArchiveAssetNaturalID(tx, row)
			if findErr != nil || !found {
				return nil, nil, errors.Join(findErr, fmt.Errorf("could not restore asset %d", oldID))
			}
			candidate = existing
			if _, err := tx.Exec(`UPDATE assets SET task_ids=CASE WHEN $1=ANY(task_ids) THEN task_ids ELSE array_append(task_ids,$1) END WHERE id=$2`, taskID, existing); err != nil {
				return nil, nil, err
			}
		}
		mapping[oldID] = candidate
	}
	return mapping, warnings, nil
}

func mergeJSONTaskID(value any, taskID int64) []int64 {
	out := []int64{}
	seen := map[int64]bool{}
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if id, ok := jsonInt64(item); ok && id > 0 && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if !seen[taskID] {
		out = append(out, taskID)
	}
	return out
}

func findArchiveAssetNaturalID(tx *sql.Tx, row map[string]any) (int64, bool, error) {
	typeName, _ := row["type"].(string)
	stringValue := func(key string) string {
		value, _ := row[key].(string)
		return value
	}
	var query string
	var args []any
	switch typeName {
	case "root_domain":
		query, args = `SELECT id FROM assets WHERE type='root_domain' AND domain=$1`, []any{stringValue("domain")}
	case "ip":
		query, args = `SELECT id FROM assets WHERE type='ip' AND ip=$1`, []any{stringValue("ip")}
	case "subdomain":
		query, args = `SELECT id FROM assets WHERE type='subdomain' AND domain=$1 AND COALESCE(record_type,'')=$2`, []any{stringValue("domain"), stringValue("record_type")}
	case "app":
		if bundle := stringValue("bundle_id"); bundle != "" {
			query, args = `SELECT id FROM assets WHERE type='app' AND bundle_id=$1`, []any{bundle}
		} else {
			query, args = `SELECT id FROM assets WHERE type='app' AND bundle_id IS NULL AND app_name=$1`, []any{stringValue("app_name")}
		}
	case "service":
		if stringValue("service_type") == "http" {
			query, args = `SELECT id FROM assets WHERE type='service' AND service_type='http' AND url=$1`, []any{stringValue("url")}
		} else {
			port, _ := jsonInt64(row["port"])
			query, args = `SELECT id FROM assets WHERE type='service' AND service_type='other' AND COALESCE(domain,'')=$1 AND COALESCE(ip,'')=$2 AND port=$3 AND service_name=$4`, []any{stringValue("domain"), stringValue("ip"), port, stringValue("service_name")}
		}
	case "endpoint":
		query, args = `SELECT id FROM assets WHERE type='endpoint' AND url=$1 AND method=$2`, []any{stringValue("url"), stringValue("method")}
	default:
		return 0, false, fmt.Errorf("unsupported archived asset type %q", typeName)
	}
	var id int64
	err := tx.QueryRow(query, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

func remapArchiveAssetReferences(tables map[string]json.RawMessage, mapping map[int64]int64) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(tables))
	for name, raw := range tables {
		out[name] = raw
	}
	for _, table := range []string{"exploration_anchors", "task_asset_links"} {
		rows, err := decodeArchiveRows(tables[table])
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if old, ok := jsonInt64(row["asset_id"]); ok {
				if replacement, exists := mapping[old]; exists {
					row["asset_id"] = replacement
				}
			}
		}
		out[table], _ = json.Marshal(rows)
	}
	for _, table := range []string{"exploration_nodes", "findings"} {
		rows, err := decodeArchiveRows(tables[table])
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			key := "asset_ids"
			container := row
			if table == "exploration_nodes" {
				payload, ok := row["payload"].(map[string]any)
				if !ok {
					continue
				}
				container = payload
			}
			if values, ok := container[key].([]any); ok {
				for i, value := range values {
					if old, ok := jsonInt64(value); ok {
						if replacement, exists := mapping[old]; exists {
							values[i] = replacement
						}
					}
				}
				container[key] = values
			}
		}
		out[table], _ = json.Marshal(rows)
	}
	return out, nil
}

func restoreTaskRelations(tx *sql.Tx, taskID int64, raw json.RawMessage) ([]string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	for _, row := range rows {
		sourceID, ok := jsonInt64(row["source_task_id"])
		if !ok || !liveTaskExists(tx, sourceID) {
			warnings = append(warnings, fmt.Sprintf("来源任务 %d 不可用，继承关系已跳过", sourceID))
			continue
		}
		created, _ := row["created_at"].(string)
		if _, err := tx.Exec(`INSERT INTO task_relations(task_id,source_task_id,created_at) VALUES($1,$2,COALESCE($3::timestamptz,now())) ON CONFLICT DO NOTHING`, taskID, sourceID, nilIfEmptyString(created)); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

func restoreTaskScopes(tx *sql.Tx, raw json.RawMessage) ([]string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	kept := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if companyID, ok := jsonInt64(row["company_id"]); ok && companyID > 0 && !rowExists(tx, "companies", companyID) {
			warnings = append(warnings, fmt.Sprintf("企业 %d 已删除，关联范围已跳过", companyID))
			continue
		}
		kept = append(kept, row)
	}
	if len(kept) == 0 {
		return warnings, nil
	}
	encoded, _ := json.Marshal(kept)
	_, err = tx.Exec(`INSERT INTO task_scope SELECT * FROM json_populate_recordset(NULL::task_scope,$1::json) ON CONFLICT DO NOTHING`, string(encoded))
	return warnings, err
}

func restoreTaskLLMProfiles(tx *sql.Tx, raw json.RawMessage) ([]string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	position := 0
	for _, row := range rows {
		profileID, ok := jsonInt64(row["profile_id"])
		if !ok || !rowExists(tx, "llm_profiles", profileID) {
			warnings = append(warnings, fmt.Sprintf("LLM 配置 %d 已删除，配置链项已跳过", profileID))
			continue
		}
		taskID, _ := jsonInt64(row["task_id"])
		status, _ := row["status"].(string)
		lastError, _ := row["last_error"].(string)
		exhaustedAt, _ := row["exhausted_at"].(string)
		createdAt, _ := row["created_at"].(string)
		updatedAt, _ := row["updated_at"].(string)
		if _, err := tx.Exec(`INSERT INTO task_llm_profiles(task_id,profile_id,position,status,last_error,exhausted_at,created_at,updated_at)
	VALUES($1,$2,$3,$4,NULLIF($5,''),$6::timestamptz,COALESCE($7::timestamptz,now()),COALESCE($8::timestamptz,now()))
	ON CONFLICT DO NOTHING`, taskID, profileID, position, status, lastError,
			nilIfEmptyString(exhaustedAt), nilIfEmptyString(createdAt), nilIfEmptyString(updatedAt)); err != nil {
			return nil, err
		}
		position++
	}
	return warnings, nil
}

// restoreInterceptRows re-inserts archived approval rows. P0 三表拆分后这里只
// 重插缺失的 pending 行并补插决定/执行行，不改写任何库内存量行：
//   - 兼容两代快照。旧快照行 JSON 带 status/decided_at/decision_source 键（列已
//     删除）——按旧 status 合成决定行（不接链尾，seq=NULL 落历史区）；decision_source
//     改名回填为 ask_source（沿用 rule_id 与 [模型] 前缀判据）。新快照行无这些键，
//     决定/执行行由快照的 intercept_decisions/intercept_executions 表提供——快照
//     自带决定行时**不得**再合成 timeout 收口行（否则会把真实历史错记成超时）。
//   - 已存在的 pending 行跳过（归档不再删除库内行，恢复必须幂等补缺）。
func restoreInterceptRows(tx *sql.Tx, pendingsRaw, decisionsRaw, executionsRaw json.RawMessage) error {
	rows, err := decodeArchiveRows(pendingsRaw)
	if err != nil {
		return err
	}
	// 先解码快照自带的决定行：凡是快照已给某 pending 提供了决定行，就不再为它
	// 合成 timeout 收口行（合成行会被 UNIQUE(pending_id) 挤掉真实行，或反过来
	// 占位挤掉快照行——顺序无关，都不能发生）。
	snapshotDecisions, err := decodeArchiveRows(decisionsRaw)
	if err != nil {
		return err
	}
	seeded := map[int64]bool{}
	for _, dr := range snapshotDecisions {
		if pid, ok := jsonInt64(dr["pending_id"]); ok && pid > 0 {
			seeded[pid] = true
		}
	}
	type decisionSeed struct {
		pendingID      int64
		decision       string
		action         string
		reason         string
		decidedBy      string
		decisionSource string
		decidedAt      any
	}
	seeds := []decisionSeed{}
	inserted := 0
	for _, row := range rows {
		// ── 两代快照键名兼容 ────────────────────────────────────────────
		hasStatusKey := false
		legacyStatus := ""
		if v, ok := row["status"]; ok {
			hasStatusKey = true
			legacyStatus, _ = v.(string)
		}
		legacyDecidedAt := row["decided_at"]
		delete(row, "status")
		delete(row, "decided_at")
		if source, ok := row["decision_source"].(string); ok {
			delete(row, "decision_source")
			if ask, _ := row["ask_source"].(string); ask == "" {
				row["ask_source"] = source
			}
		}
		if ask, _ := row["ask_source"].(string); ask == "" {
			// 归档早于来源列：按旧判据反推（快照数据的兜底，非业务代码前缀反推）。
			source := "unknown"
			if row["rule_id"] != nil {
				source = "rule"
			} else if reason, _ := row["reason"].(string); strings.HasPrefix(reason, "[模型]") {
				source = "model"
			}
			row["ask_source"] = source
		}
		audit, _ := row["audit"].(map[string]any)
		// An archived run cannot resume its former result callback.
		if audit != nil && audit["execution_status"] == "awaiting_result" {
			audit["execution_status"] = "unknown"
		}
		rowID, ok := jsonInt64(row["id"])
		if !ok || rowID <= 0 {
			return fmt.Errorf("archived intercept row has invalid id")
		}
		// 归档时仍在等审批的请求按 timeout 收口（旧行为的不可变化改写：
		// 改的是快照重插的新行，不是库内存量行）。快照已提供决定行的新格式
		// 行跳过合成——真实历史以快照决定行为准。
		decision := legacyStatus
		decidedAction := ""
		decisionReason := ""
		decidedAt := legacyDecidedAt
		switch {
		case !hasStatusKey && seeded[rowID]:
			// 新格式且快照自带决定行：不合成收口行，不改写冻结快照。
			decision = ""
		case !hasStatusKey, legacyStatus == "", legacyStatus == "pending":
			decision = "timeout"
			decidedAction = "deny"
			decisionReason = "任务归档期间审批已超时"
			row["reason"] = decisionReason
			decidedAt = time.Now().UTC()
			if audit != nil {
				audit["effective_action"] = "deny"
				audit["decision_reason"] = decisionReason
				audit["execution_status"] = "not_executed"
			}
		case legacyStatus == "allowed", legacyStatus == "denied", legacyStatus == "timeout":
			decidedAction = "deny"
			if legacyStatus == "allowed" {
				decidedAction = "allow"
			}
			if audit != nil {
				if ea, _ := audit["effective_action"].(string); ea == "allow" || ea == "deny" {
					decidedAction = ea
				}
				decisionReason, _ = audit["decision_reason"].(string)
			}
		default:
			return fmt.Errorf("archived intercept row %d has unknown status %q", rowID, legacyStatus)
		}
		auditRaw, err := json.Marshal(row["audit"])
		if err != nil {
			return err
		}
		if string(auditRaw) == "null" {
			auditRaw = nil
		}
		inputRaw, err := json.Marshal(row["tool_input"])
		if err != nil {
			return err
		}
		id := rowID
		var ruleID, convID any
		if v, ok := jsonInt64(row["rule_id"]); ok && v > 0 {
			ruleID = v
		}
		if v, ok := jsonInt64(row["conversation_id"]); ok && v > 0 {
			convID = v
		}
		taskID, _ := row["task_id"].(string)
		agentName, _ := row["agent_name"].(string)
		createdAt, _ := row["created_at"].(string)
		kind, _ := row["kind"].(string) // 旧快照无 kind 键 → ''（显式 NULL 会违反 NOT NULL）
		res, err := tx.Exec(`INSERT INTO intercept_pending
(id, rule_id, conversation_id, task_id, agent_name, tool_name, tool_input, reason, created_at, ask_source, kind, audit)
VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,COALESCE($9::timestamptz,now()),$10,$11,$12)
ON CONFLICT (id) DO NOTHING`,
			id, ruleID, convID, taskID, agentName,
			row["tool_name"], inputRaw, row["reason"], createdAt, row["ask_source"], kind, auditRaw)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // row already exists — decisions stay untouched
		}
		inserted++
		if decision != "" {
			seeds = append(seeds, decisionSeed{pendingID: id, decision: decision, action: decidedAction,
				reason: decisionReason, decidedBy: "archive", decisionSource: "archive", decidedAt: decidedAt})
		}
	}
	for _, seed := range seeds {
		if _, err := tx.Exec(`INSERT INTO intercept_decisions
(pending_id, decision, action, decision_reason, decided_by, decision_source, decided_at, seq, prev_hash, row_hash)
VALUES ($1,$2,$3,$4,$5,'archive',COALESCE($6::timestamptz,now()),NULL,'','')
ON CONFLICT (pending_id) DO NOTHING`,
			seed.pendingID, seed.decision, seed.action, seed.reason, seed.decidedBy, seed.decidedAt); err != nil {
			return err
		}
	}
	// 新快照（P0 后导出）自带决定/执行行：决定行剥掉哈希链列（seq=NULL 落历史区，
	// 恢复目标实例的 audit_key 不同，原哈希在本库无意义），已存在则跳过。
	decisionRows, err := decodeArchiveRows(decisionsRaw)
	if err != nil {
		return err
	}
	for _, row := range decisionRows {
		pendingID, ok := jsonInt64(row["pending_id"])
		if !ok || pendingID <= 0 {
			return fmt.Errorf("archived intercept decision has invalid pending_id")
		}
		decidedBy, _ := row["decided_by"].(string)
		decidedAt, _ := row["decided_at"].(string)
		if _, err := tx.Exec(`INSERT INTO intercept_decisions
(pending_id, decision, action, decision_reason, decided_by, decision_source, decided_at, seq, prev_hash, row_hash)
VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,COALESCE($7::timestamptz,now()),NULL,'','')
ON CONFLICT (pending_id) DO NOTHING`,
			pendingID, row["decision"], row["action"], row["decision_reason"], decidedBy, row["decision_source"], decidedAt); err != nil {
			return err
		}
	}
	executionRows, err := decodeArchiveRows(executionsRaw)
	if err != nil {
		return err
	}
	for _, row := range executionRows {
		pendingID, ok := jsonInt64(row["pending_id"])
		if !ok || pendingID <= 0 {
			return fmt.Errorf("archived intercept execution has invalid pending_id")
		}
		runID, _ := row["run_id"].(string)
		toolUseID, _ := row["tool_use_id"].(string)
		output, _ := row["output"].(string)
		endedAt, _ := row["ended_at"].(string)
		createdRaw, _ := row["created_at"].(string)
		var createdAt any
		if createdRaw != "" {
			createdAt = createdRaw
		}
		if _, err := tx.Exec(`INSERT INTO intercept_executions
(pending_id, run_id, tool_use_id, execution_status, output, output_truncated, ended_at, created_at)
VALUES ($1,NULLIF($2,''),NULLIF($3,''),$4,$5,$6,COALESCE($7::timestamptz,NULL),COALESCE($8::timestamptz,now()))`,
			pendingID, runID, toolUseID, row["execution_status"], output, row["output_truncated"], endedAt, createdAt); err != nil {
			return err
		}
	}
	if inserted == 0 {
		return nil
	}
	// 显式 id 插入不会推进序列：抬到当前最大值，避免后续 INSERT 撞已恢复 id。
	_, err = tx.Exec(`SELECT setval(pg_get_serial_sequence('intercept_pending','id'),
GREATEST((SELECT max(id) FROM intercept_pending), 1))`)
	return err
}

func liveTaskExists(tx *sql.Tx, id int64) bool {
	var exists bool
	_ = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, id).Scan(&exists)
	return exists
}

func nilIfEmptyString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// CompleteTaskArchiveRestore removes compact metadata after every external
// component has been verified and the package has been consumed.
func (d *DB) CompleteTaskArchiveRestore(archiveID int64) error {
	res, err := d.Exec(`DELETE FROM task_archives archive USING tasks task
WHERE archive.id=$1 AND archive.task_id=task.id AND task.deleted_at IS NULL AND task.archived_at IS NULL`, archiveID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrTaskArchiveState
	}
	return nil
}

// DeleteTaskArchiveStub permanently removes the cold task after its package has
// been staged for deletion. Dependency protection is rechecked transactionally.
func (d *DB) DeleteTaskArchiveStub(archiveID int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return err
	}
	if state != Deleting {
		return ErrTaskArchiveState
	}
	var dependent int64
	err = tx.QueryRow(`SELECT task_id FROM task_archives WHERE id<>$1 AND $2=ANY(source_task_ids) LIMIT 1`, archiveID, taskID).Scan(&dependent)
	if err == nil {
		return fmt.Errorf("%w: task %d", ErrTaskArchiveDeleteBlocked, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM tasks WHERE id=$1 AND archived_at IS NOT NULL`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM explorations WHERE id=$1`, expID); err != nil {
		return err
	}
	return tx.Commit()
}

// ArchivedAggregateStats returns compact summaries used by global dashboards so
// cold data does not disappear from historical totals.
func (d *DB) ArchivedAggregateStats() ([]json.RawMessage, error) {
	rows, err := d.Query(`SELECT archive.aggregate_stats
FROM task_archives archive
JOIN tasks task ON task.id=archive.task_id
WHERE task.archived_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
