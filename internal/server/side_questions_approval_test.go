package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/sidequestion"
)

// B2 审批旁路的 HTTP 面验收：
//   - 有 audit 的审批记录 GET 现建快照（模型解析链第一步 audit.ProfileID 命中），
//     POST 正常起跑且系统提示为审查旁路提示词；
//   - 旁问全程不写审批三表、不改审批状态（append-only 语义不受影响）；
//   - 无 audit 的旧记录明确报「无可用审查快照」；不存在的审批 404。
func TestSideHTTPApprovalSnapshotAndIsolation(t *testing.T) {
	f := newSideHTTPFixture(t)
	scope := "side-approval-http-" + t.Name()
	t.Cleanup(func() { purgeServerInterceptRows(t, f.m.pg, scope) })

	profile := &db.LLMProfile{Name: "side-approval-profile", Format: "openai", BaseURL: "http://fixture.invalid", APIKey: "test-only", Model: "fixture", Streaming: true}
	profileID, err := f.m.pg.SaveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.m.pg.DeleteProfile(profileID) })
	cfg, ok := f.s.loadProfileConfig(profileID)
	if !ok {
		t.Fatal("profile unavailable")
	}
	f.s.provByProfile = map[int64]*provEntry{profileID: {prov: f.provider, cfg: cfg}}

	approvalID, err := f.m.pg.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{"command":"pwd"}`), "review", "judge",
		&db.InterceptAudit{
			ProfileID: profileID, InitialAction: "ask", ExecutionStatus: "not_started",
			UserMessage: "审批旁路用户消息", InitialReason: "规则命中",
			ModelInput: json.RawMessage(`{"version":5,"review":"context"}`),
		})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/intercept/history/%d/side-questions", approvalID)

	// GET：无持久快照 → 从冻结 audit 现建并落库。
	w := f.call(t, "GET", path, nil, 200)
	var history struct {
		Snapshot *struct {
			Model sidequestion.Model `json:"model"`
		} `json:"snapshot"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if history.Snapshot == nil || history.Snapshot.Model.ProfileID != profileID {
		t.Fatalf("approval snapshot model: %+v", history.Snapshot)
	}

	// POST：快照材料进首条消息，系统提示为审查旁路提示词。
	e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "这条命令做了什么？", "client_request_id": "c1"}, 202))
	select {
	case req := <-f.provider.started:
		if len(req.System) != 1 || req.System[0] != reviewSideSystem {
			t.Fatalf("review side system prompt: %q", req.System)
		}
		material := req.Messages[0].Text()
		for _, want := range []string{"Bash", "审批旁路用户消息", "规则命中"} {
			if !strings.Contains(material, want) {
				t.Fatalf("approval material missing %q: %s", want, material)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval side run never started")
	}
	f.provider.release <- struct{}{}
	done := waitSide(t, f.m.pg, e.ID, "completed")

	// 幂等 client_id 回归：同 ID 同问题返回既有请求，不重跑。
	again := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "这条命令做了什么？", "client_request_id": "c1"}, 200))
	if again.ID != e.ID {
		t.Fatal("duplicate approval request re-executed")
	}

	// 旁问不碰审批三表：状态保持 pending、理由不变、无决定行。
	detail, err := f.m.pg.GetInterceptDetail(approvalID)
	if err != nil || detail == nil {
		t.Fatalf("approval detail: %+v err=%v", detail, err)
	}
	if detail.Status != "pending" || detail.Reason != "review" {
		t.Fatalf("approval mutated by side question: %+v", detail)
	}
	var decisions int
	if err = f.m.pg.QueryRow(`SELECT count(*) FROM intercept_decisions WHERE pending_id=$1`, approvalID).Scan(&decisions); err != nil || decisions != 0 {
		t.Fatalf("side question touched decisions: %d %v", decisions, err)
	}
	// 旁问历史落在 approval-{id} 会话下。
	items, err := f.m.pg.SideHistory(t.Context(), fmt.Sprintf("approval-%d", approvalID), 0, 20)
	if err != nil || len(items) != 1 || items[0].ID != done.ID {
		t.Fatalf("approval side history: %+v err=%v", items, err)
	}

	// 无 audit 的旧记录明确报错；不存在的审批 404。
	noAuditID, err := f.m.pg.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{"command":"ls"}`), "review", "judge")
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "GET", fmt.Sprintf("/api/intercept/history/%d/side-questions", noAuditID), nil, 500)
	f.call(t, "POST", fmt.Sprintf("/api/intercept/history/%d/side-questions", noAuditID), map[string]string{"question": "q", "client_request_id": "c2"}, 500)
	f.call(t, "GET", fmt.Sprintf("/api/intercept/history/%d/side-questions", approvalID+100000), nil, 404)

	// DELETE 清空旁问历史（审批行本身不可删、不受影响）。
	f.call(t, "DELETE", path, nil, 200)
	if items, err = f.m.pg.SideHistory(t.Context(), fmt.Sprintf("approval-%d", approvalID), 0, 20); err != nil || len(items) != 0 {
		t.Fatalf("approval side clear: %+v %v", items, err)
	}
}
