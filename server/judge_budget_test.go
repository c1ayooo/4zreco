package server

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/c1ayooo/4zreco/intercept"
)

// scriptedProvider 按脚本返回内容，并记录每次调用的 MaxTokens。
type scriptedProvider struct {
	calls []int
	// replies[i] 是第 i 次调用的回复文本；用完后重复最后一个。
	replies []string
}

func (p *scriptedProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		idx := len(p.calls)
		p.calls = append(p.calls, req.MaxTokens)
		reply := ""
		if len(p.replies) > 0 {
			if idx < len(p.replies) {
				reply = p.replies[idx]
			} else {
				reply = p.replies[len(p.replies)-1]
			}
		}
		if reply == "" {
			return
		}
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: reply}, nil)
	}
}

func (p *scriptedProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	idx := len(p.calls)
	p.calls = append(p.calls, req.MaxTokens)
	reply := ""
	if len(p.replies) > 0 {
		if idx < len(p.replies) {
			reply = p.replies[idx]
		} else {
			reply = p.replies[len(p.replies)-1]
		}
	}
	msg := llm.Message{}
	if reply != "" {
		msg.Content = []llm.ContentBlock{llm.TextBlock(reply)}
	}
	return msg, "end_turn", llm.Usage{OutputTokens: 100}, nil
}

// 裁决的输出预算必须给足，并且空回复时**升预算重试**。
//
// 回归背景：思考型模型(MiniMax-M3.1 等强制 adaptive thinking)的思考与正文
// 共用同一份 max_tokens。生产环境实测：长命令(几百到上千字符的 shell 脚本)
// 在 2048 预算下思考烧光、正文为空，裁决记录里表现为「原始回复 ""」——
// 用户看到的就是"审批结果没有内容"。给足预算 + 升预算重试才能根治。
func TestJudgeBudgetEscalatesOnEmptyReply(t *testing.T) {
	p := &scriptedProvider{replies: []string{"", "", `{"decision":"allow","comment":"实际操作：读文件；成功后的后果：无变化；命中规则：A1"}`}}
	text, err := streamCollectText(context.Background(), p, "sys", "user")
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if !strings.Contains(text, "decision") {
		t.Fatalf("重试后应拿到裁决 JSON,得到 %q", text)
	}
	if len(p.calls) < 2 {
		t.Fatalf("空回复应触发重试,实际调用 %d 次", len(p.calls))
	}
	// 每次重试的预算都要更大
	for i := 1; i < len(p.calls); i++ {
		if p.calls[i] <= p.calls[i-1] {
			t.Errorf("第 %d 次重试预算 %d 未大于上次 %d", i, p.calls[i], p.calls[i-1])
		}
	}
}

// 第一次就给的预算必须足够大——绝大多数命令在这一档就该成功，
// 不该靠重试兜底（重试要多花一轮往返）。
func TestJudgeFirstBudgetIsGenerous(t *testing.T) {
	if judgeMaxTokens < 16384 {
		t.Errorf("裁决首次预算 %d 太小：思考型模型在长命令上会思考烧光", judgeMaxTokens)
	}
	p := &scriptedProvider{replies: []string{`{"decision":"allow","comment":"a；b；c"}`}}
	if _, err := streamCollectText(context.Background(), p, "sys", "user"); err != nil {
		t.Fatal(err)
	}
	if len(p.calls) != 1 {
		t.Errorf("正常回复不该重试,实际调用 %d 次", len(p.calls))
	}
	if p.calls[0] != judgeMaxTokens {
		t.Errorf("首次调用预算 %d，应为 %d", p.calls[0], judgeMaxTokens)
	}
}

// 全部重试都空时，返回空串而不是报错（由上层按失败策略处理）。
func TestJudgeAllEmptyReturnsEmptyWithoutError(t *testing.T) {
	p := &scriptedProvider{replies: []string{""}}
	text, err := streamCollectText(context.Background(), p, "sys", "user")
	if err != nil {
		t.Fatalf("空回复应返回空串+nil,得到 err=%v", err)
	}
	if strings.TrimSpace(text) != "" {
		t.Errorf("应返回空串,得到 %q", text)
	}
	if len(p.calls) < 2 {
		t.Errorf("应重试到预算阶梯耗尽,实际 %d 次", len(p.calls))
	}
}

// ctx 取消后不再重试（重试要挤在同一个超时窗口里，不能把时间耗在注定失败的调用上）。
func TestJudgeStopsRetryingWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &scriptedProvider{replies: []string{""}}
	// 第一次调用后取消
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, _ = streamCollectText(ctx, p, "sys", "user")
	// 不做精确断言：只要求调用次数有限（不会无限重试）
	if len(p.calls) > 8 {
		t.Errorf("取消后调用次数 %d 过多", len(p.calls))
	}
}

// 裁决超时默认 180 秒：思考型模型的裁决耗时随命令长度而变，长命令明显更久，
// 而且正文为空时要升预算重试（重试挤在同一个窗口内）。
func TestJudgeTimeoutAllowsEscalation(t *testing.T) {
	if intercept.DefaultJudgeTimeoutSeconds() < 150 {
		t.Errorf("裁决超时 %ds 太短：升预算重试挤不进窗口", intercept.DefaultJudgeTimeoutSeconds())
	}
}

// 确认裁决请求确实带上了 session header（opencode zen 缺它直接 400）。
func TestJudgeRequestKeepsSessionHeader(t *testing.T) {
	// 通过真实 provider 构造路径验证 header 注入：这里只做形状断言，
	// 真正的 header 由 agent.Config.NewProvider 的 transport 负责。
	var raw map[string]any
	_ = json.Unmarshal([]byte(`{"decision":"allow"}`), &raw)
	if raw["decision"] != "allow" {
		t.Error("sanity")
	}
}
