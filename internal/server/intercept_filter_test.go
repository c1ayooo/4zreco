package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

func TestInterceptFilterHTTP(t *testing.T) {
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
	s.jwtKey.Store([]byte("approval-filter-test-key"))
	h := s.Handler()
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	scope := "approval-http-filter"
	t.Cleanup(func() { purgeServerInterceptRows(t, d, scope, scope+"-other") })
	_, baseline, err := d.ListAllInterceptsPage(1, 20, db.InterceptApprovalFilter{Status: "denied", AskSource: "judge"})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "allowed", "denied", "timeout"} {
		// pending 走请求表插入路径；其余状态由观测行 API 直接落决定行。
		if state == "pending" {
			if _, err := d.CreateInterceptPending(0, 0, scope, "test", "Bash", []byte(`{}`), "[模型] fixture", "judge"); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := d.CreateDecidedIntercept(0, 0, scope, "test", "Bash", []byte(`{}`), state, "[模型] fixture", "judge"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.CreateDecidedIntercept(0, 0, scope+"-other", "test", "Bash", []byte(`{}`), "denied", "[模型] fixture", "judge"); err != nil {
		t.Fatal(err)
	}
	do := func(path string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, base := range []string{"/api/intercept/history", "/api/intercept/task/" + scope} {
		if rec := do(base+"?status=denied&ask_source=judge", false); rec.Code != 401 {
			t.Fatalf("unprotected list: %d", rec.Code)
		}
		for _, query := range []string{"?status=invalid", "?ask_source=invalid", "?decision_source=invalid", "?page=1&status=denied%27+OR+1%3D1--", "?size=20&ask_source=MODEL"} {
			if rec := do(base+query, true); rec.Code != 400 {
				t.Fatalf("invalid filter %s: %d %s", query, rec.Code, rec.Body.String())
			}
		}
		// Filtering without explicit page parameters must still apply the filters.
		rec := do(base+"?status=denied&ask_source=judge", true)
		var body struct {
			Items []db.InterceptApprovalRow `json:"items"`
			Total int                       `json:"total"`
			Page  int                       `json:"page"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		want := baseline + 2
		if base != "/api/intercept/history" {
			want = 1
		}
		if body.Total != want || body.Page != 1 {
			t.Fatalf("filter total=%d want=%d page=%d", body.Total, want, body.Page)
		}
		for _, r := range body.Items {
			if r.Status != "denied" || r.AskSource != "judge" {
				t.Fatalf("nonmatching item: %+v", r)
			}
		}
	}
	for _, tc := range []struct {
		query             string
		total, rows, page int
	}{
		{"", 4, 4, 0},
		{"?page=2&size=2&ask_source=judge", 4, 2, 2},
		{"?page=2&size=1&status=denied&ask_source=judge", 1, 0, 2},
		{"?status=denied&ask_source=unknown", 0, 0, 1},
		{"?page=0&size=0&status=pending", 1, 1, 1},
	} {
		rec := do("/api/intercept/task/"+scope+tc.query, true)
		var body struct {
			Items []db.InterceptApprovalRow `json:"items"`
			Total int                       `json:"total"`
			Page  int                       `json:"page"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Total != tc.total || len(body.Items) != tc.rows || body.Page != tc.page {
			t.Fatalf("%s: %d %s", tc.query, rec.Code, rec.Body.String())
		}
	}
}
