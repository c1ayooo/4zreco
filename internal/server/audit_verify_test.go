package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

// P0-3/P0-5 端到端：decide 路由把 requireAuth 注入的凭据身份落 decided_by，
// /api/audit/verify 逐行校验哈希链并区分历史区。
func TestAuditVerifyHTTP(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	m := &Manager{pg: d, interceptor: intercept.New(d)}
	s := &Server{m: m}
	s.jwtKey.Store([]byte("audit-verify-http-signing-key"))
	// 不设独立 audit key：共享测试库的锚行由其他测试以空 key 写入，verify 必须与
	// 写入侧同 key（生产中 key 是稳定持久化文件，不存在这种跨进程混 key）。
	h := s.Handler()
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	const scope = "audit-verify-http"
	t.Cleanup(func() { purgeServerInterceptRows(t, d, scope) })

	do := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// 未鉴权的 verify 必须被拒。
	if rec := do(http.MethodGet, "/api/audit/verify", "", false); rec.Code != 401 {
		t.Fatalf("unprotected verify: %d", rec.Code)
	}

	id, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{}`), "[模型] 请确认", "judge",
		&db.InterceptAudit{InitialAction: "ask", ExecutionStatus: "not_started"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(http.MethodPost, "/api/intercept/pending/"+strconv.FormatInt(id, 10)+"/decide", `{"decision":"bogus"}`, true); rec.Code != 400 {
		t.Fatalf("bogus decision: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/intercept/pending/"+strconv.FormatInt(id, 10)+"/decide", `{"decision":"allowed"}`, true); rec.Code != 200 {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}
	var row db.InterceptPending
	if err := d.QueryRow(`SELECT id, status, decided_by, decision_source, ask_source, kind FROM v_intercept WHERE id=$1`, id).
		Scan(&row.ID, &row.Status, &row.DecidedBy, &row.DecisionSource, &row.AskSource, &row.Kind); err != nil {
		t.Fatal(err)
	}
	if row.Status != "allowed" || row.DecidedBy != "4ZRECO" || row.DecisionSource != "human" || row.AskSource != "judge" || row.Kind != "judge" {
		t.Fatalf("decide fields: %+v", row)
	}
	rec := do(http.MethodGet, "/api/audit/verify", "", true)
	var status db.AuditChainStatus
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &status) != nil {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if !status.OK || status.BrokenAtSeq != 0 || status.LastSeq < 1 {
		t.Fatalf("verify status: %+v", status)
	}
}
