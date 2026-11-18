package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// U8：5xx 只回固定文案 + err_id，内部错误原文（SQL/路径/驱动细节）不得出现在响应体。
func TestWriteErrRedacts5xx(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErr(rec, 500, `查询失败: pq: relation "findings" does not exist (dsn=postgres://u:p@h/db)`)

	body := rec.Body.String()
	for _, leak := range []string{"pq:", "findings", "postgres://", "dsn="} {
		if strings.Contains(body, leak) {
			t.Errorf("5xx 响应体泄露内部细节 %q：%s", leak, body)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v (%s)", err, body)
	}
	if payload["err_id"] == "" || payload["err_id"] == nil {
		t.Errorf("5xx 应带 err_id 供日志关联：%s", body)
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, "服务内部错误") {
		t.Errorf("5xx 应回固定文案，得到 %q", msg)
	}
}

// 日志侧同样不能落明文凭据：驱动错误常把 DSN 原样带进 message。
func TestRedactErrDetailScrubsDSNPassword(t *testing.T) {
	cases := map[string]string{
		`dial tcp: postgres://4zreco:s3cret@127.0.0.1:5432/db`: `dial tcp: postgres://4zreco:***@127.0.0.1:5432/db`,
		`no dsn here`: `no dsn here`,
	}
	for in, want := range cases {
		if got := redactErrDetail(in); got != want {
			t.Errorf("redactErrDetail(%q)=%q, want %q", in, got, want)
		}
	}
}

// 4xx 原样透传：大量 409 是可操作提示，不能被脱敏掉。
func TestWriteErrKeeps4xxMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErr(rec, 409, "任务正在删除，无法控制意图")
	if got := rec.Body.String(); !strings.Contains(got, "任务正在删除") {
		t.Errorf("4xx 文案应原样透传，得到 %s", got)
	}
}
