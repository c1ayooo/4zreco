package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// spyHook 记录转发给 inner 的调用，用来验证日志层是【旁路】而不是拦截层。
type spyHook struct {
	preCalls  int
	postCalls int
	stopCalls int
	block     bool
	msg       string
}

func (s *spyHook) PreToolUse(_ context.Context, _ string, _ []byte) (bool, string, []byte) {
	s.preCalls++
	return s.block, s.msg, nil
}

func (s *spyHook) PostToolUse(_ context.Context, _ string, _, _ []byte, _ bool) {
	s.postCalls++
}

func (s *spyHook) Stop(_ context.Context, _ []llm.Message) (bool, []string, string) {
	s.stopCalls++
	return false, nil, ""
}

// 日志层不得吞掉 inner 的拦截决定：worker 的 steer/拦截全靠 inner 生效。
func TestToolLogForwardsBlockDecision(t *testing.T) {
	spy := &spyHook{block: true, msg: "被拦截"}
	h := wrapToolLog(spy, KindWorker, "worker-1 · #1")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, IntentID: 7, Kind: KindWorker})

	block, msg, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"rm -rf /"}`))
	if !block {
		t.Fatal("日志层把 inner 的 block 决定吞掉了——worker 的拦截会失效")
	}
	if msg != "被拦截" {
		t.Fatalf("block 消息未透传: got %q", msg)
	}
	if spy.preCalls != 1 {
		t.Fatalf("inner 未被调用: preCalls=%d", spy.preCalls)
	}
}

// 日志层必须把三个事件都转发，且顺序为 pre→post→stop。
func TestToolLogForwardsAllEvents(t *testing.T) {
	spy := &spyHook{}
	h := wrapToolLog(spy, KindPlanner, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 9, Kind: KindPlanner})

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"nmap -sV 10.0.0.1"}`))
	h.PostToolUse(ctx, "Bash", []byte(`{}`), []byte("ok"), false)
	h.Stop(ctx, nil)

	if spy.preCalls != 1 || spy.postCalls != 1 || spy.stopCalls != 1 {
		t.Fatalf("事件未全部转发: pre=%d post=%d stop=%d", spy.preCalls, spy.postCalls, spy.stopCalls)
	}
}

// 被平台拦截的调用，pre 行必须标 BLOCKED——日志层是【先转发 inner 再记日志】，
// 所以它知道 inner 的拦截决定。这是「blocked」唯一可靠的判据。
func TestToolLogMarksBlockedPreLine(t *testing.T) {
	spy := &spyHook{block: true, msg: "被拦截"}
	h := wrapToolLog(spy, KindWorker, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, IntentID: 9, Kind: KindWorker})

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	block, _, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"rm -rf /"}`))
	if !block {
		t.Fatal("拦截决定未透传")
	}
	out := buf.String()
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("被拦截的调用日志行应标 BLOCKED，实际: %q", out)
	}
	if !strings.Contains(out, "Bash") {
		t.Fatalf("日志行应含工具名，实际: %q", out)
	}
}

// 未被拦截的调用不能标 BLOCKED——否则 blocked 的计数会虚高。
func TestToolLogDoesNotMarkBlockedWhenAllowed(t *testing.T) {
	h := wrapToolLog(&spyHook{}, KindWorker, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, Kind: KindWorker})

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"nmap 10.0.0.1"}`))
	if strings.Contains(buf.String(), "BLOCKED") {
		t.Fatalf("放行的调用不应标 BLOCKED: %q", buf.String())
	}
}

// 无 inner 时本层就是全部：必须放行而不是误拦。
func TestToolLogWithoutInnerAllowsAll(t *testing.T) {
	h := toolLogSink(KindMain)
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 1, Kind: KindMain})
	block, msg, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"ls"}`))
	if block || msg != "" {
		t.Fatalf("无 inner 时不应拦截: block=%v msg=%q", block, msg)
	}
}

// Bash 命令摘要只取第一行并限长——多行脚本不能把 journal 撑爆。
func TestSummarizeToolInputTrimsCommand(t *testing.T) {
	in, _ := json.Marshal(map[string]string{
		"command": "curl -s http://x/ | sh\n第二条命令很长很长很长很长很长",
	})
	got := summarizeToolInput("Bash", in)
	if strings.Contains(got, "第二条") {
		t.Fatalf("命令摘要应只取第一行: %q", got)
	}
	if len([]rune(got)) > 100 {
		t.Fatalf("命令摘要过长: %d 字符", len([]rune(got)))
	}
}

// 空输入不能 panic（工具入参缺失是常见情况）。
func TestSummarizeToolInputEmpty(t *testing.T) {
	if got := summarizeToolInput("Bash", nil); got != "" {
		t.Fatalf("空输入应返回空串: %q", got)
	}
	if got := summarizeToolInput("未知工具", []byte("{}")); got != "" {
		t.Fatalf("空 JSON 应返回空串: %q", got)
	}
}

// 结果分类：平台拦截（精确）与目标侧 WAF（启发式，仅 Bash）必须分开——
// 混在一起会让 blocked 的计数完全失去意义（实测「生成漏洞报告」的命令
// 因为输出里含漏洞描述被误判成 blocked）。
func TestClassifyToolResult(t *testing.T) {
	if got := classifyToolResult("Bash", []byte("boom"), true); got != "error" {
		t.Fatalf("isErr 应判 error: %q", got)
	}
	if got := classifyToolResult("Bash", []byte("HTTP 403 Forbidden"), false); got != "waf" {
		t.Fatalf("Bash 的 403 应判 waf: %q", got)
	}
	if got := classifyToolResult("Bash", []byte("found 3 open ports"), false); got != "ok" {
		t.Fatalf("正常输出应判 ok: %q", got)
	}
	if got := classifyToolResult("Bash", []byte(platformBlockMarker+" 此操作被禁止。"), false); got != "blocked" {
		t.Fatalf("平台拦截应判 blocked: %q", got)
	}
	// 回归：list_findings 返回的漏洞数据里含 403/denied，不是被拦截也不是 WAF。
	data := []byte(`{"findings":[{"title":"CVE-2021-403 越权"},{"desc":"denied by WAF"}]}`)
	if got := classifyToolResult("list_findings", data, false); got != "ok" {
		t.Fatalf("数据类工具的输出不应判 blocked/waf: %q", got)
	}
	if got := classifyToolResult("list_findings", []byte(platformBlockMarker+" 禁止"), false); got != "blocked" {
		t.Fatalf("平台拦截前缀对任何工具都应生效: %q", got)
	}
}

// 日志前缀必须带出 agent 角色与归属 id——否则日志无法定位到具体意图。
func TestToolLogPrefixCarriesAttribution(t *testing.T) {
	h := toolLogSink(KindWorker)
	ctx := WithRunInfo(context.Background(), RunInfo{
		TaskID: 3, ExplorationID: 3, IntentID: 42, Kind: KindWorker,
	})
	p := h.prefix(ctx)
	for _, want := range []string{"worker", "task=3", "exp=3", "intent=#42"} {
		if !strings.Contains(p, want) {
			t.Fatalf("前缀缺少 %q: %q", want, p)
		}
	}
}
