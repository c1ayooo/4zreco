package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// startFakeHostd 在临时 unix socket 上起一个最小 hostd 替身：
//   - POST /jobs：tool_id=="sqlmap" 回 400（模拟「已安装」类拒绝），
//     其余回 200 + {"id":"job-N"}；
//   - 其余路径 404。
func startFakeHostd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "hostd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var seq atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ToolID string `json:"tool_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ToolID == "sqlmap" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("sqlmap 已安装"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"id":"job-%d"}`, seq.Add(1))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	return sock
}

// 批量安装：合法项逐个转发给助手并带回 job id；未知项与被助手拒绝的项
// 进 skipped 带原因；重复项去重。
func TestHostenvInstallBatch(t *testing.T) {
	sock := startFakeHostd(t)
	t.Setenv("ZRECO_HOSTD_SOCKET", sock)
	s := &Server{}

	body, _ := json.Marshal(map[string]any{
		"ids": []string{"nmap", "sqlmap", "no-such-tool", "nmap", "ffuf"},
	})
	w := httptest.NewRecorder()
	s.hostenvInstallBatch(w, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(string(body))))

	if w.Code != http.StatusOK {
		t.Fatalf("状态码=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Started []struct {
			JobID  string `json:"job_id"`
			ToolID string `json:"tool_id"`
		} `json:"started"`
		Skipped []struct {
			ToolID string `json:"tool_id"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Started) != 2 {
		t.Fatalf("started=%v，应为 nmap 与 ffuf 两项", res.Started)
	}
	gotTools := map[string]bool{}
	for _, j := range res.Started {
		gotTools[j.ToolID] = true
		if j.JobID == "" {
			t.Fatalf("started 项缺少 job_id: %+v", j)
		}
	}
	if !gotTools["nmap"] || !gotTools["ffuf"] {
		t.Fatalf("started 应含 nmap/ffuf: %+v", res.Started)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("skipped=%v，应为 sqlmap 与 no-such-tool 两项", res.Skipped)
	}
	reasons := map[string]string{}
	for _, sk := range res.Skipped {
		reasons[sk.ToolID] = sk.Reason
	}
	if reasons["no-such-tool"] != "未知工具" {
		t.Fatalf("no-such-tool 的跳过原因=%q", reasons["no-such-tool"])
	}
	if reasons["sqlmap"] == "" {
		t.Fatal("sqlmap 被助手拒绝时应带回原因")
	}
}

// 空列表与超长列表直接 400，不碰助手。
func TestHostenvInstallBatchValidation(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.hostenvInstallBatch(w, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(`{"ids":[]}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空列表应 400，got %d", w.Code)
	}
	w2 := httptest.NewRecorder()
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "x"
	}
	b, _ := json.Marshal(map[string]any{"ids": ids})
	s.hostenvInstallBatch(w2, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(string(b))))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("超长列表应 400，got %d", w2.Code)
	}
}
