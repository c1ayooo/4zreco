package agent

// 红队工具第二批（v0.4.64 批次）的单元测试：cookie jar 往返、作业生命周期
// （start/status/output/stop + KillJobsForTaskDir 收尸）、脚本名清洗、维度推断
// 与续跳映射。作业测试依赖 bash（Linux/CI 环境有；Windows 上构建本来就排除了
// syscall 路径，但 bash 包装是跨平台的——本文件在无 bash 的环境跳过）。

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJarStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions", "main.jar")
	j := newJarStore(path)
	u, _ := url.Parse("https://target.example.com/app/")
	j.SetCookies(u, []*http.Cookie{
		{Name: "sid", Value: "abc123", Domain: "target.example.com", Path: "/"},
		{Name: "tok", Value: "x=y", Domain: "target.example.com", Path: "/", HttpOnly: true},
	})
	// 原子写回后文件必须是 curl 可读的 Netscape 格式。
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("jar 文件未落盘: %v", err)
	}
	if !strings.Contains(string(b), "target.example.com\tTRUE\t/\tFALSE\t") {
		t.Fatalf("Netscape 格式不符:\n%s", b)
	}
	if !strings.Contains(string(b), "#HttpOnly_target.example.com") {
		t.Fatalf("HttpOnly 前缀丢失:\n%s", b)
	}
	// 新实例（模拟下一意图）从同一文件恢复登录态。
	j2 := newJarStore(path)
	got := j2.Cookies(u)
	if len(got) != 2 {
		t.Fatalf("恢复出 %d 条 cookie，要 2 条: %v", len(got), got)
	}
	// 子域不匹配的 host 不带 domain cookie。
	other, _ := url.Parse("https://other.example.com/")
	if got := j2.Cookies(other); len(got) != 0 {
		t.Fatalf("domain 隔离失效: %v", got)
	}
}

func TestSessionJarPathRejectsBadNames(t *testing.T) {
	ts := NewToolSet(nil, "")
	ts.SetRunDir(filepath.Join(t.TempDir(), "tasks", "9", "i1"))
	if p := ts.sessionJarPath("../evil"); p == "" || strings.Contains(p, "..") {
		t.Fatalf("非法 session 名未被清洗: %q", p)
	}
	if p := ts.sessionJarPath("main"); !strings.HasSuffix(p, filepath.Join("shared", "sessions", "main.jar")) {
		t.Fatalf("正常 session 名路径不符: %q", p)
	}
	if ts.sessionJarPath("") != "" {
		t.Fatalf("空 session 名应返回空串")
	}
}

func TestSharedDirLayout(t *testing.T) {
	base := t.TempDir()
	// worker 形态：tasks/<id>/i<intent> → shared 落任务目录。
	ts := NewToolSet(nil, "")
	ts.SetRunDir(filepath.Join(base, "tasks", "7", "i3"))
	if d := ts.sharedDir(); d != filepath.Join(base, "tasks", "7", "shared") {
		t.Fatalf("worker shared 目录错: %s", d)
	}
	// planner/main 形态：tasks/<id> 本身（父目录基名是 tasks，不能再往上取）。
	ts2 := NewToolSet(nil, "")
	ts2.SetRunDir(filepath.Join(base, "tasks", "7"))
	if d := ts2.sharedDir(); d != filepath.Join(base, "tasks", "7", "shared") {
		t.Fatalf("planner shared 目录错: %s", d)
	}
}

func TestJobLifecycle(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("需要 bash")
	}
	base := t.TempDir()
	ts := NewToolSet(nil, "")
	ts.SetRunDir(filepath.Join(base, "tasks", "11", "i2"))
	start, _ := ts.jobStart().Call(context.Background(), []byte(`{"name":"scan","command":"echo hello; sleep 0.3"}`), nil)
	if start.IsError {
		t.Fatalf("job_start 失败: %s", start.Flatten())
	}
	// 有界轮询作业结束（不写短 sleep 断言，防负载 flaky）。
	deadline := time.Now().Add(5 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		res, _ := ts.jobStatus().Call(context.Background(), []byte(`{"name":"scan"}`), nil)
		if s := res.Flatten(); strings.Contains(s, `"state":"finished"`) {
			state = s
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state == "" {
		t.Fatalf("作业未在 5s 内进入 finished")
	}
	out, _ := ts.jobOutput().Call(context.Background(), []byte(`{"name":"scan"}`), nil)
	if !strings.Contains(out.Flatten(), "hello") {
		t.Fatalf("job_output 缺少输出: %s", out.Flatten())
	}
}

func TestJobStopKillsRunningJob(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("需要 bash")
	}
	base := t.TempDir()
	ts := NewToolSet(nil, "")
	ts.SetRunDir(filepath.Join(base, "tasks", "12", "i2"))
	ctx := context.Background()
	if _, err := ts.jobStart().Call(ctx, []byte(`{"name":"long","command":"sleep 30"}`), nil); err != nil {
		t.Fatalf("job_start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		res, _ := ts.jobStatus().Call(ctx, []byte(`{"name":"long"}`), nil)
		if strings.Contains(res.Flatten(), `"state":"running"`) {
			running = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !running {
		t.Fatalf("作业未进入 running")
	}
	res, _ := ts.jobStop().Call(ctx, []byte(`{"name":"long"}`), nil)
	if !strings.Contains(res.Flatten(), `"stopped":true`) {
		t.Fatalf("job_stop 未停掉: %s", res.Flatten())
	}
}

func TestKillJobsForTaskDir(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("需要 bash")
	}
	base := t.TempDir()
	ts := NewToolSet(nil, "")
	ts.SetRunDir(filepath.Join(base, "tasks", "13", "i2"))
	ctx := context.Background()
	if _, err := ts.jobStart().Call(ctx, []byte(`{"name":"victim","command":"sleep 30"}`), nil); err != nil {
		t.Fatalf("job_start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, _ := ts.jobStatus().Call(ctx, []byte(`{"name":"victim"}`), nil)
		if strings.Contains(res.Flatten(), `"state":"running"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	taskDir := filepath.Join(base, "tasks", "13")
	if n := KillJobsForTaskDir(taskDir); n != 1 {
		t.Fatalf("KillJobsForTaskDir 收尸 %d 个，要 1 个", n)
	}
	if n := KillJobsForTaskDir(taskDir); n != 0 {
		t.Fatalf("二次收尸不应再有作业: %d", n)
	}
}

func TestChainNextMapping(t *testing.T) {
	if d, g := chainNext(dimInjection); d != dimDataExport || g == "" {
		t.Fatalf("injection 下一跳错: %s", d)
	}
	if d, _ := chainNext(dimCredReuse); d != dimLateral {
		t.Fatalf("cred-reuse 下一跳错: %s", d)
	}
	if d, g := chainNext(dimRecon); d != "" || g != "" {
		t.Fatalf("recon 不应续跳: %s", d)
	}
}

func TestDimensionInferAndNormalize(t *testing.T) {
	if d := normalizeDimension("authz/登录后越权"); d != dimAuthz {
		t.Fatalf("复合维度归一错: %s", d)
	}
	if d := inferDimension("利用支付接口改价并验证订单状态"); d != dimPayment {
		t.Fatalf("summary 推断错: %s", d)
	}
	if d := inferDimension("扫描端口指纹"); d != dimRecon {
		t.Fatalf("侦察推断错: %s", d)
	}
	// 上游口径：authz/recon 不算「利用/深挖」类（多步链放宽墙钟的判定面）。
	if ExploitDimensionFromPayload([]byte(`{"summary":"越权读取他人订单"}`)) {
		t.Fatalf("authz 不应判为利用类")
	}
	if !ExploitDimensionFromPayload([]byte(`{"summary":"用注入点导出库表数据"}`)) {
		t.Fatalf("injection 应判为利用类")
	}
}

func TestSanitizeJobAndScriptNames(t *testing.T) {
	if sanitizeJobName("a/b") != "ab" {
		t.Fatalf("路径分隔符未剥")
	}
	if sanitizeJobName("  ") != "" {
		t.Fatalf("纯空白应拒绝")
	}
	if sanitizeScriptName("../../etc/passwd") != "....etcpasswd" {
		t.Fatalf("穿越清洗不符: %s", sanitizeScriptName("../../etc/passwd"))
	}
	if sanitizeScriptName(".") != "" || sanitizeScriptName("..") != "" {
		t.Fatalf(". 与 .. 应拒绝")
	}
}

