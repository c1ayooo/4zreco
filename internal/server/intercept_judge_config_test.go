package server

// intercept_judge_config_test.go — B1 移植：/api/intercept/judge-config 的
// incomplete_script_action 校验与持久化（PG 门控）。移植自 ARTEX 0.3.29
// intercept_config_test.go 的 TestJudgeConfigIncompleteScriptDefaultAndOverride，
// 去掉本仓库尚未移植的 retry_count/retry_interval_ms 断言。

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

func TestJudgeConfigIncompleteScriptDefaultAndOverride(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("no test database configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	// 先记录既有值，测试后恢复（不把测试写入带进运行配置）。
	var saved string
	var exists bool
	if value, ok, err := pg.GetSetting("llm_judge_incomplete_script_action"); err != nil {
		t.Fatal(err)
	} else {
		saved, exists = value, ok
	}
	t.Cleanup(func() {
		if exists {
			_, _ = pg.Exec(`UPDATE settings SET value=$2 WHERE key=$1`, "llm_judge_incomplete_script_action", saved)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, "llm_judge_incomplete_script_action")
		}
	})
	s := &Server{m: &Manager{pg: pg, interceptor: intercept.New(pg)}}
	for _, tc := range []struct {
		option, want string
		code         int
	}{
		{"", "model", 200},
		{`,"incomplete_script_action":"ask"`, "ask", 200},
		{`,"incomplete_script_action":"model"`, "model", 200},
		{`,"incomplete_script_action":"invalid"`, "model", 400},
	} {
		req := httptest.NewRequest("PUT", "/api/intercept/judge-config", strings.NewReader(`{"fail_action":"allow","ask_timeout_action":"deny"`+tc.option+`}`))
		w := httptest.NewRecorder()
		s.interceptSetJudgeConfig(w, req)
		if w.Code != tc.code {
			t.Fatalf("option=%s status=%d body=%s", tc.option, w.Code, w.Body.String())
		}
		if got := s.m.interceptor.GetJudgeConfig().IncompleteScriptAction; got != tc.want {
			t.Fatalf("option=%s action=%s want=%s", tc.option, got, tc.want)
		}
	}
}
