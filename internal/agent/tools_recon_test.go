package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// 侦察领域工具必须挂在三个执行角色上（对齐 tools_scanners_test.go 的绑定测试）：
// worker 摸面要爬端点/查测绘，planner 规划要态势与公开情报，人在环路也要能直接问。
func TestReconToolsAreBoundToAllThreeRoles(t *testing.T) {
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
	for _, name := range []string{"katana_scan", "passive_search", "web_search"} {
		if !workers[name] || !planners[name] || !mains[name] {
			t.Errorf("%s 未绑定到三个角色（worker=%v planner=%v mainagent=%v）——只读发现类必须三角色同款",
				name, workers[name], planners[name], mains[name])
		}
	}
}

// isolateConfig 把运行时配置指到一个不存在的文件并把凭据类环境变量清空，
// 让「未配置」路径的断言不被本机 config.json / 环境污染。
func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv("ZRECO_CONFIG", t.TempDir()+"/absent.json")
	for _, k := range []string{"ZRECO_FOFA_EMAIL", "ZRECO_FOFA_KEY", "ZRECO_HUNTER_KEY",
		"ZRECO_WEBSEARCH_ENDPOINT", "ZRECO_WEBSEARCH_KEY"} {
		t.Setenv(k, "")
	}
}

// 未配置凭据时 passive_search / web_search 必须返回明确中文错误，不崩溃、不 panic。
func TestReconToolsUnconfiguredHint(t *testing.T) {
	isolateConfig(t)
	ts := NewToolSet(nil, "")

	in, _ := json.Marshal(map[string]any{"query": `app="nginx"`})
	res, err := ts.passiveSearchTool().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("passive_search Call 返回了 error（应回 Errorf 结果）: %v", err)
	}
	if !res.IsError {
		t.Fatalf("passive_search 未配置时应返回错误结果，实际: %s", res.Flatten())
	}
	msg := res.Flatten()
	for _, want := range []string{"未配置", "passive_search", "ZRECO_FOFA_KEY"} {
		if !strings.Contains(msg, want) {
			t.Errorf("passive_search 未配置提示缺 %q: %s", want, msg)
		}
	}

	in, _ = json.Marshal(map[string]any{"query": "log4j CVE"})
	res, err = ts.webSearchTool().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("web_search Call 返回了 error（应回 Errorf 结果）: %v", err)
	}
	if !res.IsError {
		t.Fatalf("web_search 未配置时应返回错误结果，实际: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "未配置搜索服务") {
		t.Errorf("web_search 未配置提示不含「未配置搜索服务」: %s", res.Flatten())
	}
}

// web_search 配置驱动：env 里有 key（可用 ZRECO_WEBSEARCH_ENDPOINT 指向本地假端点）
// 时应真实调用 Tavily 兼容 API 并回紧凑摘要。全链路只碰 httptest 回环，无外网。
func TestWebSearchConfiguredLocalEndpoint(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			APIKey     string `json:"api_key"`
			Query      string `json:"query"`
			MaxResults int    `json:"max_results"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.APIKey == "" || req.Query == "" {
			http.Error(w, "missing api_key/query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"title": "result one", "url": "https://example.com/a", "content": "first snippet"},
				{"title": "result two", "url": "https://example.com/b"},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("ZRECO_WEBSEARCH_ENDPOINT", srv.URL)
	t.Setenv("ZRECO_WEBSEARCH_KEY", "test-key")

	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"query": "test", "limit": 2})
	res, err := ts.webSearchTool().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("web_search Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("web_search 返回错误结果: %s", res.Flatten())
	}
	var out struct {
		Count   int `json:"count"`
		Results []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Snippet string `json:"snippet,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("web_search 输出不是合法 JSON: %v; raw=%s", err, res.Flatten())
	}
	if out.Count != 2 || len(out.Results) != 2 {
		t.Fatalf("web_search 摘要异常: %+v", out)
	}
	if out.Results[0].Title != "result one" || out.Results[0].Snippet != "first snippet" {
		t.Errorf("web_search 首条结果字段不符: %+v", out.Results[0])
	}
	if out.Results[1].Snippet != "" {
		t.Errorf("无 content 的结果不应带 snippet: %+v", out.Results[1])
	}
}

// katana_scan 端到端冒烟：standard 引擎对本地 httptest 目标真实爬取，验证
// 端点+参数紧凑摘要形状（全链路回环，无外部网络）。
func TestKatanaScanSmokeLocal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body>
			<a href="/page1?x=1&y=2">one</a>
			<a href="/page2">two</a>
			</body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "page1")
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "page2")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"url": srv.URL, "depth": 2, "max_results": 20})
	res, err := ts.katanaScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("katana_scan Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("katana_scan 返回错误结果: %s", res.Flatten())
	}
	var out struct {
		Count     int `json:"count"`
		Endpoints []struct {
			URL    string   `json:"url"`
			Status int      `json:"status,omitempty"`
			Params []string `json:"params,omitempty"`
			Form   map[string]any
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("katana_scan 输出不是合法 JSON: %v; raw=%s", err, res.Flatten())
	}
	if out.Count < 1 || len(out.Endpoints) < 1 {
		t.Fatalf("katana_scan 对本地可爬目标返回空结果: %s", res.Flatten())
	}
	// 至少应命中起点或 /page1；query 参数应被解析进 params。
	foundParam := false
	for _, e := range out.Endpoints {
		if strings.Contains(e.URL, "/page1") && len(e.Params) > 0 {
			foundParam = true
		}
	}
	if !foundParam {
		t.Errorf("katana_scan 未在 /page1 端点上解析出查询参数: %s", res.Flatten())
	}
}

// queryParams：查询参数解析成有序 name[=value] 短列表，无参数返回 nil。
func TestQueryParams(t *testing.T) {
	if got := queryParams("https://a.com/x?b=2&a=1&a=&c"); len(got) != 3 || got[0] != "a=1" || got[1] != "b=2" || got[2] != "c" {
		t.Errorf("queryParams 解析结果不符: %v", got)
	}
	if got := queryParams("https://a.com/x"); got != nil {
		t.Errorf("无参数应返回 nil: %v", got)
	}
}

// clampInt：0 取默认，超界夹逼。
func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, def, want int }{
		{0, 1, 10, 3, 3},
		{-5, 1, 10, 3, 3},
		{5, 1, 10, 3, 5},
		{99, 1, 10, 3, 10},
	}
	for _, c := range cases {
		if got := clampInt(c.v, c.lo, c.hi, c.def); got != c.want {
			t.Errorf("clampInt(%d,%d,%d,%d) = %d; want %d", c.v, c.lo, c.hi, c.def, got, c.want)
		}
	}
}

// katana_scan 入参校验：非 http(s) URL 必须挡在入口。
func TestKatanaScanRejectsBadURL(t *testing.T) {
	isolateConfig(t)
	ts := NewToolSet(nil, "")
	in, _ := json.Marshal(map[string]any{"url": "ftp://example.com"})
	res, err := ts.katanaScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("katana_scan Call 返回了 error（应回 Errorf 结果）: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "http(s)") {
		t.Fatalf("katana_scan 应拒绝非 http(s) URL: isErr=%v msg=%s", res.IsError, res.Flatten())
	}
}
