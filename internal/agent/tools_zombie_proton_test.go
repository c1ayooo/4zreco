package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkzombie "github.com/chainreactors/sdk/zombie"

	"github.com/c1ayooo/4zreco/internal/db"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// 强动作扫描器工具必须挂在三个执行角色上（对齐 listener_start 的绑定面）。
func TestZombieProtonToolsAreBoundToAllThreeRoles(t *testing.T) {
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
	for _, name := range []string{"zombie_weakpass", "proton_secrets"} {
		if !workers[name] || !planners[name] || !mains[name] {
			t.Errorf("%s 未绑定到三个角色（worker=%v planner=%v mainagent=%v）——角色分配对齐 listener_*",
				name, workers[name], planners[name], mains[name])
		}
	}
}

// 强动作工具必须用 writeTool 包装（ReadOnly=false）——readTool 会让调度器
// 把对目标发真实认证尝试的调用当只读并发放行。
func TestZombieProtonToolsAreNotReadOnly(t *testing.T) {
	ts := NewToolSet(nil, "")
	for _, tl := range []actool.CoreTool{ts.zombieWeakpass(), ts.protonSecrets()} {
		if tl.IsReadOnly(nil) {
			t.Errorf("%s IsReadOnly()=true——强动作工具不允许标只读", tl.Name())
		}
	}
}

// parseZombieTarget：服务前缀/端口默认值/凭据段/域名解析失败各分支。
func TestParseZombieTarget(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		in           string
		wantService  string
		wantIP       string
		wantPort     string
		wantUser     string
		wantHasCreds bool
		ok           bool
	}{
		{"ssh://127.0.0.1", "ssh", "127.0.0.1", "22", "", false, true},
		{"mysql://root:root@127.0.0.1:3306", "mysql", "127.0.0.1", "3306", "root", true, true},
		{"redis://127.0.0.1:6379", "redis", "127.0.0.1", "6379", "", false, true},
		{"ssh://127.0.0.1:2222", "ssh", "127.0.0.1", "2222", "", false, true},
		{"postgresql://postgres@127.0.0.1", "postgresql", "127.0.0.1", "5432", "postgres", true, true},
		{"", "", "", "", "", false, false},
		{"127.0.0.1", "", "", "", "", false, false},                // 缺服务前缀
		{"ftp://badservice-x", "", "", "", "", false, false},       // 未知服务
		{"ssh:///", "", "", "", "", false, false},                  // 缺主机
		{"ssh://nosuchhost.invalid", "", "", "", "", false, false}, // 域名解析失败
	}
	for _, c := range cases {
		spec, err := parseZombieTarget(ctx, c.in)
		if c.ok {
			if err != nil {
				t.Errorf("parseZombieTarget(%q) 意外失败: %v", c.in, err)
				continue
			}
			if spec.Service != c.wantService || spec.IP != c.wantIP || spec.Port != c.wantPort ||
				spec.Username != c.wantUser || spec.HasCreds != c.wantHasCreds {
				t.Errorf("parseZombieTarget(%q) = %+v; want service=%s ip=%s port=%s user=%s hasCreds=%v",
					c.in, spec, c.wantService, c.wantIP, c.wantPort, c.wantUser, c.wantHasCreds)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseZombieTarget(%q) 竟然成功: %+v", c.in, spec)
		}
	}
}

// 内置弱口令字典：引擎 init 加载内嵌配置后 Keywords 必须有兜底清单——
// 「不给字典就用内置弱口令」的默认行为依赖它。
func TestBuiltinWeakListsAvailable(t *testing.T) {
	if _, err := zombieWeakpassEngine(); err != nil {
		t.Fatalf("zombie 引擎初始化失败: %v", err)
	}
	users, pwds := builtinWeakLists("nosuchservice")
	if len(users) == 0 || len(pwds) == 0 {
		t.Fatalf("未知服务时未回退 top100 兜底字典: users=%d pwds=%d", len(users), len(pwds))
	}
	su, sp := builtinWeakLists("ssh")
	if len(su) == 0 || len(sp) == 0 {
		t.Fatalf("ssh 未取到服务定向字典: users=%d pwds=%d", len(su), len(sp))
	}
}

// proton 内置规则集加载 + ScanData 命中（对齐 P2 的本地冒烟风格；只碰内存数据，
// 无网络依赖）。同时验证证据纪律：工具回显里【不得】出现 secret 原文。
func TestProtonSecretsEngineAndToolSmoke(t *testing.T) {
	eng, err := protonSecretsEngine()
	if err != nil {
		t.Fatalf("proton 引擎初始化失败: %v", err)
	}
	secret := "AKIAIOSFODNN7EXAMPLE"
	findings := eng.ScanData([]byte("aws_access_key_id = "+secret+"\npassword = hunter2secret\n"), "app.env")
	if len(findings) == 0 {
		t.Fatal("内置规则集对明文 AWS AKID 样本零命中——模板数据没加载")
	}
	hitAWS := false
	for _, f := range findings {
		if f.TemplateID == "aws-access-key" {
			hitAWS = true
		}
	}
	if !hitAWS {
		t.Fatalf("aws-access-key 规则未命中，命中: %+v", findings)
	}

	// 工具面：data 入参、无证据存储（taskID=0 的空壳 ToolSet）→ fail-closed：
	// 返回错误且错误里【不得】出现 secret 原文。带证据存储的回显形状在
	// TestProtonSecretsEvidenceRecorded 里验证。
	ts := NewToolSet(nil, "")
	tool := ts.protonSecrets()
	in, _ := json.Marshal(map[string]any{"data": "token = " + secret + "\n"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("proton_secrets Call 失败: %v", err)
	}
	if !res.IsError {
		t.Fatalf("无证据存储且命中时应 fail-closed 返回错误，实际: %s", res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, "命中") {
		t.Fatalf("fail-closed 错误应说明命中条数: %s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("证据纪律被破坏：secret 原文 %q 出现在工具回显里", secret)
	}
}

// 证据附件路径：命中必须落 evidence（save_evidence 的内部实现路径）。
// 用假 recorder 验证：命中时写了文件、登记了 artifact、回显带 evidence_artifact_id。
func TestProtonSecretsEvidenceRecorded(t *testing.T) {
	runDir := t.TempDir()
	var recordedPath string
	ts := NewToolSet(nil, "")
	ts.taskID = 42
	ts.runDir = runDir
	ts.artifactRecorder = &fakeArtifactRecorder{
		onRecord: func(relPath string) { recordedPath = relPath },
	}
	tool := ts.protonSecrets()
	in, _ := json.Marshal(map[string]any{"data": "password = topsecret-pw-value\n"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("返回错误结果: %s", res.Flatten())
	}
	if recordedPath == "" {
		t.Fatal("recordScanEvidence 未被调用——命中明细没有落证据")
	}
	abs := filepath.Join(runDir, filepath.Clean(recordedPath))
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("证据文件读不到: %v", err)
	}
	if !strings.Contains(string(b), "topsecret-pw-value") {
		t.Fatal("证据文件里没有命中明细（应含 secret 原文）")
	}
	if !strings.Contains(res.Flatten(), "evidence_artifact_id") {
		t.Fatalf("回显缺 evidence_artifact_id: %s", res.Flatten())
	}
}

// 无证据存储（artifactRecorder=nil）时必须 fail-closed：不能为了「有产出」
// 把命中明细（凭据原文）泄进 trace。
func TestProtonSecretsFailsClosedWithoutEvidenceStore(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	ts := NewToolSet(nil, "")
	tool := ts.protonSecrets()
	in, _ := json.Marshal(map[string]any{"data": "slack: " + secret + "\n"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if !res.IsError {
		t.Fatalf("无证据存储时应返回错误（fail-closed），实际: %s", res.Flatten())
	}
	if strings.Contains(res.Flatten(), secret) {
		t.Fatalf("证据纪律被破坏：secret 原文 %q 出现在错误回显里", secret)
	}
}

// fakeArtifactRecorder 是 ArtifactRecorder 的最小桩：只抓 relPath。
type fakeArtifactRecorder struct {
	onRecord func(relPath string)
}

func (f *fakeArtifactRecorder) RecordArtifact(taskID, findingID int64, runDir, relPath, name, kind, sourceURL, note string) (*db.TaskArtifact, error) {
	if f.onRecord != nil {
		f.onRecord(relPath)
	}
	return &db.TaskArtifact{ID: 777, Name: name, Kind: kind}, nil
}

// zombie 端到端冒烟：SDK 引擎对本地关闭端口（httptest 关停后的端口不保证，
// 直接用 127.0.0.1 上大概率无服务的 127.0.0.1:1）跑 Brute 小字典——链路要通、
// 不 panic、返回 0 命中。真实弱口令命中需要对目标服务暴力认证，不在单测范围。
func TestZombieWeakpassEngineSmokeLocal(t *testing.T) {
	eng, err := zombieWeakpassEngine()
	if err != nil {
		t.Fatalf("zombie 引擎初始化失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	zctx := sdkzombie.NewContext().WithContext(ctx).WithThreads(4)
	// 直接走工具的执行核心太重，这里走引擎 API 验证依赖链可用。
	zt := []sdkzombie.Target{{IP: "127.0.0.1", Port: "1", Service: "ssh"}}
	if _, err := eng.Brute(zctx, zt, []string{"root"}, []string{"toor"}); err != nil {
		t.Fatalf("zombie Brute 执行失败: %v", err)
	}
}

// 工具面冒烟：closed 端口 + 显式凭据（sniper 模式）→ 0 命中、回显无密码字段泄漏。
func TestZombieWeakpassToolSmokeNoHits(t *testing.T) {
	ts := NewToolSet(nil, "")
	tool := ts.zombieWeakpass()
	in, _ := json.Marshal(map[string]any{
		"target":      []string{"ssh://root:toor@127.0.0.1:1"},
		"timeout_sec": 30,
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("返回错误结果: %s", res.Flatten())
	}
	var out struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("输出不是合法 JSON: %v; raw=%s", err, res.Flatten())
	}
	if out.Count != 0 {
		t.Fatalf("closed 端口不应有命中: %s", res.Flatten())
	}
	if strings.Contains(res.Flatten(), "toor") {
		t.Fatal("回显泄露了显式传入的密码")
	}
}

// userlist/passlist 笛卡尔积超限必须挡在执行前。
func TestZombieWeakpassGuardsOversizedBrute(t *testing.T) {
	ts := NewToolSet(nil, "")
	tool := ts.zombieWeakpass()
	users := make([]string, 100)
	for i := range users {
		users[i] = "u" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + itoa(i)
	}
	pwd := make([]string, 300)
	for i := range pwd {
		pwd[i] = "p" + itoa(i)
	}
	in, _ := json.Marshal(map[string]any{"target": []string{"ssh://127.0.0.1:1"}, "userlist": users, "passlist": pwd})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if !res.IsError {
		t.Fatal("超限字典应被拒绝")
	}
}

// proton file 入参：目录必须拒绝、真实文件可扫。
func TestProtonSecretsFileParam(t *testing.T) {
	ts := NewToolSet(nil, "")
	tool := ts.protonSecrets()
	dir := t.TempDir()
	in, _ := json.Marshal(map[string]any{"file": dir})
	res, _ := tool.Call(context.Background(), in, nil)
	if !res.IsError {
		t.Fatal("目录入参应被拒绝")
	}
	f := filepath.Join(dir, "cfg.yaml")
	// 内容不命中任何内置规则——避免触发「命中但无证据存储」的 fail-closed 错误。
	if err := os.WriteFile(f, []byte("# just a comment\nhello plain world\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, _ = json.Marshal(map[string]any{"file": f})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("文件入参意外失败: %s", res.Flatten())
	}
}
