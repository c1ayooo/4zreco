package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkgogo "github.com/chainreactors/sdk/gogo"
	sdkspray "github.com/chainreactors/sdk/spray"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// 扫描器领域工具必须挂在三个执行角色上（对齐 search_recent_critical 的绑定测试）：
// worker 摸面要扫端口/指纹，planner 规划要态势，人在环路也要能直接问。
func TestScannerToolsAreBoundToAllThreeRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := func(tools []actool.CoreTool) map[string]bool {
		m := map[string]bool{}
		for _, tl := range tools {
			m[tl.Name()] = true
		}
		return m
	}
	workers := names(ts.WorkerTools())
	planners := names(ts.PlannerTools())
	mains := names(ts.MainAgentTools())
	for _, name := range []string{"gogo_scan", "spray_finger"} {
		if !workers[name] || !planners[name] || !mains[name] {
			t.Errorf("%s 未绑定到三个角色（worker=%v planner=%v mainagent=%v）——只读发现类必须三角色同款",
				name, workers[name], planners[name], mains[name])
		}
	}
}

// normalizeScanTarget：URL 取 hostname、端口剥除、CIDR 透传、空/畸形拒绝。
// 域名解析路径依赖环境网络，不做成功断言（只保证不 panic、失败时报错信息完整）。
func TestNormalizeScanTarget(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1:8080", "127.0.0.1", true},
		{"http://127.0.0.1:18080/path", "127.0.0.1", true},
		{"10.0.0.0/24", "10.0.0.0/24", true},
		{"", "", false},
		{"http://", "", false},
	}
	for _, c := range cases {
		got, err := normalizeScanTarget(ctx, c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("normalizeScanTarget(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("normalizeScanTarget(%q) 竟然成功: %q", c.in, got)
		}
	}
}

func TestValidateScanPorts(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"", "top2", true},
		{"TOP2", "top2", true},
		{"80,443", "80,443", true},
		{"1-1000", "1-1000", true},
		{"all", "all", true},
		{"80, http", "", false},
		{"top100", "", false}, // 常见误传：gogo 本版预设没有 top100，必须挡在入口
		{"-5", "", false},
	}
	for _, c := range cases {
		got, err := validateScanPorts(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("validateScanPorts(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("validateScanPorts(%q) 竟然成功: %q", c.in, got)
		}
	}
}

// 端到端冒烟：SDK 进程内引擎对本地 httptest 目标真实执行一次 gogo 扫描与
// spray 指纹，并走工具面（CoreTool.Call）验证紧凑 JSON 摘要可解析。
// 验证 go.mod 锁定的依赖链在运行期可用（指纹库能加载、结果能回）。全链路
// 只碰 httptest 的回环监听端口，无外部网络依赖。
func TestScannerEnginesSmokeLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = w.Write([]byte("<html><head><title>smoke target</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	port := strings.SplitN(strings.TrimPrefix(srv.URL, "http://"), "/", 2)[0]
	port = port[strings.LastIndex(port, ":")+1:]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// gogo：对 127.0.0.1 的 httptest 监听端口做单端口扫描，应回一条命中。
	eng, err := gogoScanEngine()
	if err != nil {
		t.Fatalf("gogo 引擎初始化失败: %v", err)
	}
	gctx := sdkgogo.NewContext().WithContext(ctx)
	results, err := eng.Scan(gctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("gogo Scan 失败: %v", err)
	}
	found := false
	for _, r := range results {
		if r != nil && r.Ip == "127.0.0.1" && r.Port == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("gogo Scan 未命中本地 httptest 端口 %s（结果 %d 条）", port, len(results))
	}

	// spray：对 httptest URL 做 Check，应回一条 status=200 的结果。
	seng, err := sprayFingerEngine()
	if err != nil {
		t.Fatalf("spray 引擎初始化失败: %v", err)
	}
	sctx := sdkspray.NewContext().WithContext(ctx)
	sres, err := seng.Check(sctx, []string{srv.URL})
	if err != nil {
		t.Fatalf("spray Check 失败: %v", err)
	}
	if len(sres) == 0 || sres[0] == nil || sres[0].Status != http.StatusOK {
		t.Fatalf("spray Check 对本地存活目标返回异常: %+v, err=%v", sres, err)
	}

	// 工具面端到端：CoreTool.Call 验证 JSON 摘要形状。
	ts := NewToolSet(nil, "")
	tool := ts.sprayFinger()
	in, _ := json.Marshal(map[string]any{"urls": []string{srv.URL}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("spray_finger Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("spray_finger 返回错误结果: %s", res.Flatten())
	}
	var out struct {
		Count   int `json:"count"`
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("spray_finger 输出不是合法 JSON: %v; raw=%s", err, res.Flatten())
	}
	if out.Count < 1 || len(out.Results) == 0 || out.Results[0].Status != http.StatusOK {
		t.Fatalf("spray_finger 摘要异常: %+v", out)
	}
}
