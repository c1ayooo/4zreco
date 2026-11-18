package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

// ── 状态机单测（无 DB） ─────────────────────────────────────────────

func TestLoginBreakerStateMachine(t *testing.T) {
	resetLoginBreakers()
	defer resetLoginBreakers()
	key, hash := "t/1/0", "h1"

	if locked, _ := loginBreakerCheck(key, hash); locked {
		t.Fatal("首次调用不应熔断")
	}
	if msg := loginBreakerRecordFailure(key, hash, 401); !strings.Contains(msg, "再失败 1 次") {
		t.Fatalf("第一次失败应提示剩余次数，得到 %q", msg)
	}
	// 成功一次清零
	loginBreakerRecordSuccess(key, hash)
	if msg := loginBreakerRecordFailure(key, hash, 401); !strings.Contains(msg, "再失败 1 次") {
		t.Fatalf("成功后计数应清零，得到 %q", msg)
	}
	// 连续两次失败 → 熔断
	if msg := loginBreakerRecordFailure(key, hash, 401); !strings.Contains(msg, "已熔断") {
		t.Fatalf("连续两次 401 应熔断，得到 %q", msg)
	}
	if locked, msg := loginBreakerCheck(key, hash); !locked || !strings.Contains(msg, "已熔断") {
		t.Fatalf("熔断期内应本地拒绝，locked=%v msg=%q", locked, msg)
	}

	// 凭据内容变化（改密）→ 自动复位
	_, hash2 := loginBreakerKey(1, 2, 0, "ops", "new-pass")
	if locked, _ := loginBreakerCheck(key, hash2); locked {
		t.Fatal("凭据更新后不应继续熔断")
	}

	// TTL 到期 half-open 放行一次；仍失败则立即重新熔断
	key3, hash3 := "t/3/0", "h3"
	loginBreakerRecordFailure(key3, hash3, 401)
	loginBreakerRecordFailure(key3, hash3, 403)
	if locked, _ := loginBreakerCheck(key3, hash3); !locked {
		t.Fatal("两次失败后应熔断")
	}
	base := time.Now()
	loginBreakerNow = func() time.Time { return base.Add(loginBreakerLockTTL + time.Minute) }
	defer func() { loginBreakerNow = time.Now }()
	if locked, _ := loginBreakerCheck(key3, hash3); locked {
		t.Fatal("TTL 到期应 half-open 放行")
	}
	if msg := loginBreakerRecordFailure(key3, hash3, 401); !strings.Contains(msg, "已熔断") {
		t.Fatalf("half-open 后仍失败应重新熔断，得到 %q", msg)
	}
	if locked, _ := loginBreakerCheck(key3, hash3); !locked {
		t.Fatal("重新熔断期内应继续拒绝")
	}
}

func TestClassifyLoginOutcome(t *testing.T) {
	cases := map[int]string{
		401: "failure", 403: "failure",
		200: "success", 201: "success", 204: "success",
		400: "neutral", 500: "neutral", 302: "neutral",
	}
	for status, want := range cases {
		if got := classifyLoginOutcome(status); got != want {
			t.Errorf("classifyLoginOutcome(%d)=%q, want %q", status, got, want)
		}
	}
}

// ── session_login 端到端（真 PG + httptest） ─────────────────────

func TestSessionLoginBreakerIntegration(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	assets := d.Assets()

	task, err := d.CreateTask("login breaker test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	if _, err := assets.AddAgentScope(task.ID, "cidr", "10.77.1.0/24", "test", "agent"); err != nil {
		t.Fatal(err)
	}
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,ip,task_ids,auth,last_seen)
VALUES ('service','lb.test','lb.test','10.77.1.10',ARRAY[$1]::bigint[],
        ARRAY['{"type":"form","username":"ops","password":"old-pass"}'::jsonb], now())
RETURNING id`, task.ID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) }()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		_ = r.ParseForm()
		// 第 4 次之后的请求本不该发生（熔断本地拒绝 + 改密后 2 次成功）；防御性断言。
		if n > 4 {
			t.Errorf("目标端收到第 %d 次登录请求——熔断未生效", n)
		}
		if r.PostForm.Get("password") == "new-pass" {
			w.Header().Set("Set-Cookie", "sid=ok; Path=/")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	resetLoginBreakers()
	defer resetLoginBreakers()

	runDir := filepath.Join(t.TempDir(), "tasks", strconv.FormatInt(task.ID, 10))
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := &ToolSet{as: assets, taskID: task.ID, runDir: runDir}
	login := func() string {
		res, callErr := ts.sessionLogin().Call(context.Background(), json.RawMessage(fmt.Sprintf(
			`{"session":"breaker","url":%q,"asset_id":%d,"auth_mode":"form"}`,
			srv.URL+"/login", assetID)), nil)
		if callErr != nil {
			return "GOERR: " + callErr.Error()
		}
		if res.IsError {
			return "ERR: " + res.Flatten()
		}
		return "OK: " + res.Flatten()
	}

	// 第一次 401：计数 1，提示还剩一次
	out := login()
	if !strings.Contains(out, "再失败 1 次") || !strings.Contains(out, "401") {
		t.Fatalf("第一次 401 应提示剩余次数：%s", out)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("第一次应发出 1 次请求，实际 %d", n)
	}
	// 第二次 401：达到阈值，结果里带熔断说明
	out = login()
	if !strings.Contains(out, "已熔断") {
		t.Fatalf("第二次 401 应熔断：%s", out)
	}
	// 第三次：本地拒绝，不发出任何请求
	out = login()
	if !strings.Contains(out, "ERR") || !strings.Contains(out, "熔断") {
		t.Fatalf("熔断期内应本地拒绝：%s", out)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("熔断后不应再发请求，目标端收到 %d 次", n)
	}

	// 操作员改密（凭据哈希变化）→ 自动复位，请求放行且成功清零
	if _, err := d.Exec(`UPDATE assets SET auth=ARRAY['{"type":"form","username":"ops","password":"new-pass"}'::jsonb] WHERE id=$1`, assetID); err != nil {
		t.Fatal(err)
	}
	out = login()
	if !strings.Contains(out, "OK") || !strings.Contains(out, "会话已写入") {
		t.Fatalf("改密后登录应成功：%s", out)
	}
	if n := atomic.LoadInt32(&hits); n != 3 {
		t.Fatalf("改密后应恰好发出 1 次新请求，目标端共 %d 次", n)
	}
	// 成功后熔断状态清零：再成功一次也不会被拒绝
	out = login()
	if !strings.Contains(out, "OK") {
		t.Fatalf("成功清零后再次登录应正常：%s", out)
	}
}
