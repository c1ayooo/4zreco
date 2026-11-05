package db

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// P0 验收（docs/Eino深度接入方案-2026-11-05.md §4-P0）：
//   - psql 手工 UPDATE/DELETE 被拒（触发器），audit_writer GUC 可放行；
//   - 两条并发 decide 后链不断、seq 无空洞；
//   - 手工改行后 VerifyAuditChain 报断链并给 seq；
//   - 归档恢复后历史行可展示且不污染链校验；
//   - 视图 status 计算与旧数据（audit 内嵌字段）兜底。
func TestInterceptImmutabilityAndChain(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scope := "approval-p0-" + t.Name()
	// Cleanup LIFO：先清行，再把链头回拨到存活行（顺序不能反）。
	t.Cleanup(func() { rewindChainHeadToSurvivors(t, d) })
	t.Cleanup(func() { purgeInterceptRows(t, d, scope) })

	create := func(t *testing.T, audit *InterceptAudit) int64 {
		t.Helper()
		id, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{"command":"pwd"}`), "review", "judge", audit)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	t.Run("update and delete rejected without audit_writer", func(t *testing.T) {
		id := create(t, &InterceptAudit{InitialAction: "ask", ExecutionStatus: "not_started"})
		// 决定行不存在时先证 pending 本体：UPDATE/DELETE 均被触发器拒绝
		//（无 FK 干扰——此时还没有子行）。
		for _, stmt := range []string{
			`UPDATE intercept_pending SET reason='tampered' WHERE id=$1`,
			`DELETE FROM intercept_pending WHERE id=$1`,
		} {
			if _, err := d.Exec(stmt, id); err == nil {
				t.Fatalf("mutation not rejected: %s", stmt)
			}
		}
		if ok, err := d.ResolveIntercept(id, "denied", "deny", "拒绝", "admin", "human"); err != nil || !ok {
			t.Fatalf("resolve: %v %v", ok, err)
		}
		// 三表的 UPDATE/DELETE 一律拒绝（行存在，触发器逐行命中）。
		for _, stmt := range []string{
			`UPDATE intercept_pending SET reason='tampered' WHERE id=$1`,
			`UPDATE intercept_decisions SET row_hash='forged' WHERE pending_id=$1`,
			`DELETE FROM intercept_decisions WHERE pending_id=$1`,
			`UPDATE intercept_executions SET output='forged' WHERE pending_id=$1`,
			`DELETE FROM intercept_executions WHERE pending_id=$1`,
		} {
			if _, err := d.Exec(stmt, id); err == nil {
				t.Fatalf("mutation not rejected: %s", stmt)
			}
		}
		// 受控放行口：audit_writer GUC 事务内可以删（迁移/归档同一机制）。
		// 删接链行会留洞——删除后把链头回拨到存活行，保持共享库链条一致。
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`SET LOCAL app.role='audit_writer'`); err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`DELETE FROM intercept_executions WHERE pending_id=$1`,
			`DELETE FROM intercept_decisions WHERE pending_id=$1`,
			`DELETE FROM intercept_pending WHERE id=$1`,
		} {
			if _, err := tx.Exec(stmt, id); err != nil {
				t.Fatalf("audit_writer escape rejected: %v (%s)", err, stmt)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		rewindChainHeadToSurvivors(t, d)
	})

	t.Run("concurrent decides keep the chain intact", func(t *testing.T) {
		const pendings, dups = 6, 4
		ids := make([]int64, pendings)
		for i := range ids {
			ids[i] = create(t, &InterceptAudit{InitialAction: "ask", ExecutionStatus: "not_started"})
		}
		// 本子测试自己的链头基线（前面的子测试可能已经推进过链）。
		baseSeq, baseHash := readChainHead(d)
		var wins sync.Map
		var wg sync.WaitGroup
		for i := range ids {
			wg.Add(1)
			go func(id int64) {
				defer wg.Done()
				ok, err := d.ResolveIntercept(id, "allowed", "allow", "人工允许执行", "admin", "human")
				if err != nil {
					t.Errorf("decide %d: %v", id, err)
					return
				}
				if ok {
					wins.Store(id, true)
				}
			}(ids[i])
		}
		for range dups {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Same pending decided twice concurrently: exactly one wins.
				ok, err := d.ResolveIntercept(ids[0], "denied", "deny", "重复决定", "admin", "human")
				if err != nil {
					t.Errorf("dup decide: %v", err)
				}
				if ok {
					wins.Store(int64(-1), true)
				}
			}()
		}
		wg.Wait()
		count := 0
		wins.Range(func(any, any) bool { count++; return true })
		if count != pendings {
			t.Fatalf("winners=%d want %d", count, pendings)
		}
		if st, err := d.VerifyAuditChain(); err != nil || !st.OK {
			t.Fatalf("chain broken after concurrent decides: %+v %v", st, err)
		}
		// seq 无空洞：新决定行占据基线之后的连续区间。
		var minSeq, maxSeq int64
		if err := d.QueryRow(`SELECT min(seq), max(seq) FROM intercept_decisions
WHERE pending_id IN (SELECT id FROM intercept_pending WHERE COALESCE(task_id,'')=$1) AND seq IS NOT NULL`, scope).Scan(&minSeq, &maxSeq); err != nil {
			t.Fatal(err)
		}
		if maxSeq-minSeq != pendings-1 || maxSeq != baseSeq+pendings {
			t.Fatalf("seq gap: min=%d max=%d base=%d", minSeq, maxSeq, baseSeq)
		}
		// prev_hash 链接 + status 视图计算。ids[0] 的赢家可能是它自己的
		// goroutine（allowed）也可能是重复决定 goroutine（denied），其余必为 allowed。
		rows, total, err := d.ListTaskInterceptsPage(scope, 1, 100, InterceptApprovalFilter{})
		if err != nil || total != pendings {
			t.Fatalf("view status: total=%d err=%v", total, err)
		}
		allowed := 0
		for _, r := range rows {
			if r.Status != "allowed" && r.Status != "denied" {
				t.Fatalf("row left undecided: %+v", r.InterceptPending)
			}
			if r.Status == "allowed" {
				allowed++
			}
			if r.DecisionSource != "human" || r.DecidedBy != "admin" || r.DecidedAt == nil {
				t.Fatalf("decision-side fields missing: %+v", r.InterceptPending)
			}
		}
		if allowed < pendings-1 {
			t.Fatalf("allowed=%d want >= %d", allowed, pendings-1)
		}
		var prev = baseHash
		for seq := minSeq; seq <= maxSeq; seq++ {
			var pendingID int64
			var prevHash, rowHash string
			if err := d.QueryRow(`SELECT COALESCE(pending_id,0), prev_hash, row_hash FROM intercept_decisions WHERE seq=$1`, seq).Scan(&pendingID, &prevHash, &rowHash); err != nil {
				t.Fatal(err)
			}
			if prevHash != prev {
				t.Fatalf("chain fork at seq %d", seq)
			}
			prev = rowHash
		}
	})

	t.Run("complete appends execution rows and detail reassembles audit", func(t *testing.T) {
		id := create(t, &InterceptAudit{RunID: "run", ToolUseID: "call", Correlation: "exact", InitialAction: "ask", ExecutionStatus: "not_started"})
		ok, err := d.ResolveIntercept(id, "allowed", "allow", "人工允许执行", "admin", "human")
		if err != nil || !ok {
			t.Fatalf("resolve: %v %v", ok, err)
		}
		// Cross-run result must not attach; the exact call's result appends a new row.
		if err := d.CompleteIntercept(id, "different-run", "call", "succeeded", "WRONG", false); err != nil {
			t.Fatal(err)
		}
		if err := d.CompleteIntercept(id, "run", "call", "failed", "permission denied", true); err != nil {
			t.Fatal(err)
		}
		got, err := d.GetInterceptDetail(id)
		if err != nil || got == nil {
			t.Fatalf("detail: %v %v", got, err)
		}
		if got.Audit.ExecutionStatus != "failed" || got.Audit.Output != "permission denied" || !got.Audit.OutputTruncated || got.Audit.ExecutionEndedAt == nil {
			t.Fatalf("assembled audit: %+v", got.Audit)
		}
		if got.Audit.EffectiveAction != "allow" || got.Audit.DecisionReason != "人工允许执行" {
			t.Fatalf("decision fields: %+v", got.Audit)
		}
		if got.Status != "allowed" {
			t.Fatalf("view status: %s", got.Status)
		}
		// 迟到的重复结果不得改写：守卫只认 awaiting_result，终态后的追加被拒
		//（与旧 CompleteIntercept 语义一致——每次审批至多一条终态执行行）。
		if err := d.CompleteIntercept(id, "run", "call", "succeeded", "late duplicate", false); err != nil {
			t.Fatal(err)
		}
		got, _ = d.GetInterceptDetail(id)
		if got.Audit.Output != "permission denied" {
			t.Fatalf("duplicate result rewrote output: %q", got.Audit.Output)
		}
	})

	t.Run("legacy audit fields survive without decision rows", func(t *testing.T) {
		// 模拟迁移前的旧行形状：audit 内嵌 effective_action/execution_status，
		// 决定行缺失 → 拼装层保留 audit 值，视图 status 仍为 pending。
		id, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{}`), "[模型] 请确认", "judge",
			&InterceptAudit{InitialAction: "ask", EffectiveAction: "allow", DecisionReason: "旧行理由", ExecutionStatus: "succeeded", Output: "旧输出"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.GetInterceptDetail(id)
		if err != nil || got == nil {
			t.Fatalf("detail: %v %v", got, err)
		}
		if got.Status != "pending" {
			t.Fatalf("legacy row should read pending: %s", got.Status)
		}
		if got.Audit.EffectiveAction != "allow" || got.Audit.ExecutionStatus != "succeeded" || got.Audit.Output != "旧输出" {
			t.Fatalf("legacy audit fields lost: %+v", got.Audit)
		}
		if got.AskSource != "judge" || got.Kind != "judge" {
			t.Fatalf("ask_source/kind: %s/%s", got.AskSource, got.Kind)
		}
	})

	t.Run("observation rows get chained auto decisions", func(t *testing.T) {
		// 规则 allow/deny 观测行（第二条写路径）：必须自带决定行，否则视图
		// 显示永久 pending；决定接链、来源=auto。audit 形状与 guard.Log 的
		// auditFor(ctx, dec, input, "denied") 一致。
		id, err := d.CreateDecidedIntercept(0, 0, scope, "test", "Bash", []byte(`{}`), "denied", "[模型] 拒绝", "judge",
			&InterceptAudit{InitialAction: "ask", EffectiveAction: "deny", ExecutionStatus: "not_executed"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.GetInterceptDetail(id)
		if err != nil || got == nil {
			t.Fatalf("observation detail: %v %v", got, err)
		}
		if got.Status != "denied" || got.DecisionSource != "auto" || got.AskSource != "judge" || got.Kind != "judge" {
			t.Fatalf("observation row fields: %+v", got.InterceptApprovalRow)
		}
		if got.Audit.EffectiveAction != "deny" || got.Audit.ExecutionStatus != "not_executed" {
			t.Fatalf("observation audit: %+v", got.Audit)
		}
		var seq any
		if err := d.QueryRow(`SELECT seq FROM intercept_decisions WHERE pending_id=$1`, id).Scan(&seq); err != nil || seq == nil {
			t.Fatalf("observation decision not chained: %v %v", seq, err)
		}
		if st, err := d.VerifyAuditChain(); err != nil || !st.OK {
			t.Fatalf("chain broken by observation row: %+v %v", st, err)
		}
	})

	t.Run("verify reports broken chain at seq", func(t *testing.T) {
		id := create(t, &InterceptAudit{InitialAction: "ask", ExecutionStatus: "not_started"})
		if ok, err := d.ResolveIntercept(id, "allowed", "allow", "人工允许执行", "admin", "human"); err != nil || !ok {
			t.Fatalf("resolve: %v %v", ok, err)
		}
		var seq int64
		var original string
		if err := d.QueryRow(`SELECT seq, row_hash FROM intercept_decisions WHERE pending_id=$1 AND seq IS NOT NULL`, id).Scan(&seq, &original); err != nil {
			t.Fatal(err)
		}
		tamper := func(hash string) {
			tx, err := d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`SET LOCAL app.role='audit_writer'`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`UPDATE intercept_decisions SET row_hash=$2 WHERE pending_id=$1 AND seq=$3`, id, hash, seq); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		tamper("forged-hash")
		st, err := d.VerifyAuditChain()
		if err != nil || st.OK || st.BrokenAtSeq != seq {
			t.Fatalf("tampered chain: %+v %v (want broken@%d)", st, err, seq)
		}
		tamper(original)
		if st, err := d.VerifyAuditChain(); err != nil || !st.OK {
			t.Fatalf("chain not restored: %+v %v", st, err)
		}
	})

	t.Run("archive restore lands in history zone without polluting the chain", func(t *testing.T) {
		var maxID int64
		if err := d.QueryRow(`SELECT COALESCE(max(id),0) FROM intercept_pending`).Scan(&maxID); err != nil {
			t.Fatal(err)
		}
		newID := maxID + 1
		// 旧格式快照行：带 status/decided_at/decision_source 键（列已删除）。
		legacyRow := map[string]any{
			"id":              newID,
			"rule_id":         nil,
			"conversation_id": nil,
			"task_id":         scope,
			"agent_name":      "archived-agent",
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": "whoami"},
			"status":          "allowed",
			"reason":          "[模型] 归档观测",
			"decided_at":      "2026-01-01T00:00:00Z",
			"created_at":      "2026-01-01T00:00:00Z",
			"decision_source": "model",
			"audit": map[string]any{
				"initial_action": "ask", "effective_action": "allow",
				"execution_status": "succeeded", "output": "归档输出", "correlation": "unavailable",
			},
		}
		pendingRaw, _ := json.Marshal([]map[string]any{legacyRow})
		if err := restoreInterceptRowsTx(t, d, pendingRaw, nil, nil); err != nil {
			t.Fatal(err)
		}
		got, err := d.GetInterceptDetail(newID)
		if err != nil || got == nil {
			t.Fatalf("restored legacy row: %v %v", got, err)
		}
		if got.Status != "allowed" {
			t.Fatalf("restored status: %s", got.Status)
		}
		if got.AskSource != "model" {
			t.Fatalf("decision_source key must map to ask_source: %q", got.AskSource)
		}
		if got.DecisionSource != "archive" || got.DecidedBy != "archive" {
			t.Fatalf("synthetic decision source: %s/%s", got.DecisionSource, got.DecidedBy)
		}
		if got.Audit.EffectiveAction != "allow" || got.Audit.ExecutionStatus != "succeeded" {
			t.Fatalf("restored audit: %+v", got.Audit)
		}
		// 历史区 +1 且链校验不受影响（历史区只计数不逐行校验）。
		if st, err := d.VerifyAuditChain(); err != nil || !st.OK || st.HistoryRows < 1 {
			t.Fatalf("chain polluted by restore: %+v %v", st, err)
		}
		// 已存在的 pending 行不重插（幂等补缺）：同 id 重放必须跳过且决定行不翻倍。
		if err := restoreInterceptRowsTx(t, d, pendingRaw, nil, nil); err != nil {
			t.Fatal(err)
		}
		var decisions int64
		if err := d.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE pending_id=$1`, newID).Scan(&decisions); err != nil {
			t.Fatal(err)
		}
		if decisions != 1 {
			t.Fatalf("restore replay duplicated decisions: %d", decisions)
		}
	})

	t.Run("new-format restore keeps the snapshot decision instead of timing out", func(t *testing.T) {
		// 复核回归：新格式快照（无 status 键）+ 库内缺失 pending 行时，快照自带
		// 的决定行必须原样落库——不得先合成 timeout 收口行把它挤掉。
		var maxID int64
		if err := d.QueryRow(`SELECT COALESCE(max(id),0) FROM intercept_pending`).Scan(&maxID); err != nil {
			t.Fatal(err)
		}
		newID := maxID + 1
		pendingRow := map[string]any{
			"id": newID, "rule_id": nil, "conversation_id": nil,
			"task_id": scope, "agent_name": "archived-new", "tool_name": "Bash",
			"tool_input": map[string]any{"command": "id"},
			"reason":     "[模型] 归档观测（新格式）", "created_at": "2026-01-01T00:00:00Z",
			"ask_source": "judge", "kind": "judge",
			"audit": map[string]any{"initial_action": "ask", "execution_status": "not_started"},
		}
		decisionRow := map[string]any{
			"pending_id": newID, "decision": "allowed", "action": "allow",
			"decision_reason": "人工允许执行", "decided_by": "admin", "decision_source": "human",
			"decided_at": "2026-01-01T00:01:00Z",
		}
		pendingRaw, _ := json.Marshal([]map[string]any{pendingRow})
		decisionRaw, _ := json.Marshal([]map[string]any{decisionRow})
		if err := restoreInterceptRowsTx(t, d, pendingRaw, decisionRaw, nil); err != nil {
			t.Fatal(err)
		}
		got, err := d.GetInterceptDetail(newID)
		if err != nil || got == nil {
			t.Fatalf("restored new-format row: %v %v", got, err)
		}
		if got.Status != "allowed" || got.DecisionSource != "human" || got.DecidedBy != "admin" {
			t.Fatalf("snapshot decision lost or mangled: status=%s source=%s by=%s",
				got.Status, got.DecisionSource, got.DecidedBy)
		}
		if got.Audit.EffectiveAction != "allow" {
			t.Fatalf("snapshot decision not assembled: %+v", got.Audit)
		}
		var decisions int64
		if err := d.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE pending_id=$1`, newID).Scan(&decisions); err != nil {
			t.Fatal(err)
		}
		if decisions != 1 {
			t.Fatalf("decision count: %d", decisions)
		}
		// 对照：新格式行若快照没给决定行（归档时未决），仍按 timeout 收口。
		newID2 := newID + 1
		undecided := map[string]any{
			"id": newID2, "rule_id": nil, "conversation_id": nil,
			"task_id": scope, "agent_name": "archived-new", "tool_name": "Bash",
			"tool_input": map[string]any{"command": "id"},
			"reason":     "[模型] 归档观测（新格式未决）", "created_at": "2026-01-01T00:00:00Z",
			"ask_source": "judge", "kind": "judge",
			"audit": map[string]any{"initial_action": "ask", "execution_status": "not_started"},
		}
		undecidedRaw, _ := json.Marshal([]map[string]any{undecided})
		if err := restoreInterceptRowsTx(t, d, undecidedRaw, nil, nil); err != nil {
			t.Fatal(err)
		}
		got2, err := d.GetInterceptDetail(newID2)
		if err != nil || got2 == nil {
			t.Fatalf("restored undecided row: %v %v", got2, err)
		}
		if got2.Status != "timeout" || got2.DecisionSource != "archive" {
			t.Fatalf("undecided row not closed out: status=%s source=%s", got2.Status, got2.DecisionSource)
		}
		if st, err := d.VerifyAuditChain(); err != nil || !st.OK {
			t.Fatalf("chain broken by new-format restore: %+v %v", st, err)
		}
	})
}

// restoreInterceptRowsTx runs the restore inside a transaction (INSERT-only, no
// audit_writer escape needed — the immutability triggers never block inserts).
func restoreInterceptRowsTx(t *testing.T, d *DB, pendings, decisions, executions []byte) error {
	t.Helper()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := restoreInterceptRows(tx, pendings, decisions, executions); err != nil {
		return err
	}
	return tx.Commit()
}

// TestAuditChainRowHashKeyed 验证 SetAuditKey 后的 HMAC 逐字节确定且与空 key 不同
//（纯单元，不落库；空 key 的链路已由上面的共享库测试覆盖）。
func TestAuditChainRowHashKeyed(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 600000, time.UTC)
	d := &DB{}
	d.SetAuditKey([]byte("unit-test-key"))
	h1 := d.chainRowHash(7, "prev", 42, "allowed", "allow", "r", "admin", "human", at)
	h2 := d.chainRowHash(7, "prev", 42, "allowed", "allow", "r", "admin", "human", at)
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("keyed hash not deterministic hex64: %s vs %s", h1, h2)
	}
	empty := (&DB{}).chainRowHash(7, "prev", 42, "allowed", "allow", "r", "admin", "human", at)
	if empty == h1 {
		t.Fatal("keyed hash equals unkeyed hash")
	}
	// 同一瞬间往返格式化必须稳定（写侧与 verify 读侧的 canonical 一致性）。
	if d.chainRowHash(7, "prev", 42, "allowed", "allow", "r", "admin", "human", at.Truncate(time.Microsecond)) != h1 {
		t.Fatal("microsecond truncation changed the hash")
	}
	// 任何字段变化都要换哈希。
	if d.chainRowHash(8, "prev", 42, "allowed", "allow", "r", "admin", "human", at) == h1 ||
		d.chainRowHash(7, "other", 42, "allowed", "allow", "r", "admin", "human", at) == h1 {
		t.Fatal("field change did not change the hash")
	}
}
