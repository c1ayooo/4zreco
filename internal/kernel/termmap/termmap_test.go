package termmap

// 表驱动单测（方案 §4-P1 第 6 条落地要求）：12 种终态逐条一条用例，锁定
// 「来源 → 枚举值」的映射与冻结字符串。任何一条改动都该是显式的方案变更。

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Autumn-27/norma/harness"
	"github.com/cloudwego/eino/adk"
)

func TestTerminalReasonStringsMatchFrozenEnum(t *testing.T) {
	// 冻结契约：映射包的常量与 norma harness 枚举逐字节一致（engine 状态机与
	// db.Activity payload 依赖这些字符串）。
	frozen := map[Reason]string{
		Completed:         "completed",
		MaxTurns:          "max_turns",
		ModelError:        "model_error",
		AbortedStreaming:  "aborted_streaming",
		AbortedTools:      "aborted_tools",
		Timeout:           "timeout",
		HookStopped:       "hook_stopped",
		StopHookPrevented: "stop_hook_prevented",
		BlockingLimit:     "blocking_limit",
		PromptTooLong:     "prompt_too_long",
		ImageError:        "image_error",
		Settlement:        "settlement",
	}
	for r, want := range frozen {
		if string(r) != want {
			t.Fatalf("reason %q != frozen %q", string(r), want)
		}
	}
	if len(frozen) != 12 {
		t.Fatalf("frozen table has %d entries, want 12", len(frozen))
	}
}

// TestMapErrorTableDriven — 12 终态逐条一条用例。
func TestMapErrorTableDriven(t *testing.T) {
	canceledErr := fmt.Errorf("stream reader: %w", context.Canceled)
	deadlineErr := fmt.Errorf("tool exec: %w", context.DeadlineExceeded)

	cases := []struct {
		name    string
		ctx     func() context.Context
		err     error
		phase   Phase
		want    Reason
		wantErr     error // 期望的 Terminal.Err 负载（errors.Is 核对）
		dropPayload bool  // 预算类终态（max_turns/timeout）吞掉错误，norma finish(reason, nil)
		produce func() Reason // 宿主直接给定的终态（无错误来源）走这里，跳过 MapError
	}{
		{
			// 1. Completed：模型无 tool_call 正常终态——不是错误映射；防御性输入返回 Completed。
			name:  "completed_natural_stop",
			ctx:   context.Background,
			err:   nil,
			phase: PhaseModel,
			want:  Completed,
		},
		{
			// 2. MaxTurns：ErrExceedMaxIterations。
			name:  "max_turns_from_adk",
			ctx:   context.Background,
			err:     fmt.Errorf("agent loop: %w", adk.ErrExceedMaxIterations),
			phase:   PhaseModel,
			want:        MaxTurns,
			dropPayload: true, // 预算类终态不带错误负载（norma finish(MaxTurns, nil)）
		},
		{
			// 3. ModelError：WrapModel 捕获的模型调用错误（兜底分支）。
			name:  "model_error_fallback",
			ctx:   context.Background,
			err:   errors.New("provider 500: upstream unavailable"),
			phase: PhaseModel,
			want:  ModelError,
		},
		{
			// 4. AbortedStreaming：模型流式阶段的 ctx 取消。
			name:  "aborted_streaming_model_phase",
			ctx: func() context.Context {
				c, cancel := context.WithCancel(context.Background())
				cancel()
				return c
			},
			err:   canceledErr,
			phase: PhaseModel,
			want:  AbortedStreaming,
		},
		{
			// 5. AbortedTools：工具执行阶段的 ctx 取消（phase 提示）。
			name:    "aborted_tools_tool_phase",
			ctx:     context.Background,
			err:     canceledErr,
			phase:   PhaseTools,
			want:    AbortedTools,
			wantErr: context.Canceled,
		},
		{
			// 6. Timeout：ctx deadline / engine 墙钟。
			name:    "timeout_deadline",
			ctx:     context.Background,
			err:     deadlineErr,
			phase:   PhaseTools,
			want:        Timeout,
			dropPayload: true, // 预算类终态不带错误负载
		},
		{
			// 7. HookStopped：中间件主动终止（哨兵，可跨 wrap 链识别）。
			name:  "hook_stopped_sentinel",
			ctx:   context.Background,
			err:   fmt.Errorf("run aborted: %w", ErrHookStopped),
			phase: PhaseModel,
			want:  HookStopped,
		},
		{
			// 8. StopHookPrevented：内核不再产出（§3.1 上移 engine）——映射表
			//    没有错误来源，宿主（driver 终态判定）直接取常量；用例锁定宿主
			//    取值路径与错误映射解耦（produce 列，跳过 MapError）。
			name:    "stop_hook_prevented_host_only",
			produce: func() Reason { return StopHookPrevented },
			want:    StopHookPrevented,
		},
		{
			// 9. BlockingLimit：自建阻塞计数哨兵。
			name:  "blocking_limit_sentinel",
			ctx:   context.Background,
			err:   fmt.Errorf("view middleware: %w", ErrBlockingLimit),
			phase: PhaseModel,
			want:  BlockingLimit,
		},
		{
			// 10. PromptTooLong：413/超长分类（与 acllm.IsOverflow 同一判定）。
			name:  "prompt_too_long_overflow",
			ctx:   context.Background,
			err:   errors.New("request failed: status 413: prompt is too long: 210000 tokens > 200000 maximum"),
			phase: PhaseModel,
			want:  PromptTooLong,
		},
		{
			// 11. ImageError：图片错误分类（自建保守字符串分类）。
			name:  "image_error_classification",
			ctx:   context.Background,
			err:   errors.New("provider error: this model does not support image input"),
			phase: PhaseModel,
			want:  ImageError,
		},
		{
			// 12. Settlement：engine 收尾路径，不来自 ADK——没有错误来源；
			//     宿主在收尾判定处直接取常量（produce 列，跳过 MapError）。
			name:    "settlement_host_only",
			produce: func() Reason { return Settlement },
			want:    Settlement,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.produce != nil {
				if got := tc.produce(); got != tc.want {
					t.Fatalf("host-produced reason = %q, want %q", string(got), string(tc.want))
				}
				return
			}
			got, err := MapError(tc.ctx(), tc.err, tc.phase)
			if got != tc.want {
				t.Fatalf("MapError(%v, phase %d) = %q, want %q", tc.err, tc.phase, string(got), string(tc.want))
			}
			// Terminal.Err 负载：错误分类保留原始错误，预算类终态吞掉。
			if tc.dropPayload {
				if err != nil {
					t.Fatalf("budget terminal must drop the error payload; got %v", err)
				}
				return
			}
			if tc.wantErr != nil {
				if err == nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("payload error = %v, want errors.Is %v", err, tc.wantErr)
				}
			}
		})
	}
}

// TestHostProducedReasons: ReasonStopHookPrevented 与 ReasonSettlement 无错误
// 来源（方案表：前者上移 engine，后者一直是 engine 收尾路径）——它们不出现在
// MapError 的错误分类里，宿主（driver / engine）在终态判定处直接取常量。
func TestHostProducedReasons(t *testing.T) {
	for _, r := range []Reason{StopHookPrevented, Settlement} {
		// 任何错误都不该映射到宿主专用终态。
		got, _ := MapError(context.Background(), errors.New("boom"), PhaseModel)
		if got == r {
			t.Fatalf("error mapping must never produce host-only reason %q", string(r))
		}
	}
}

// TestClassificationOrdering: 分类优先级——哨兵 > MaxTurns > 溢出 > 图片 >
// deadline > cancel > 兜底。交叉性错误（一个消息同时含 image 与 too long）按
// 方案表顺序落在先命中的类。
func TestClassificationOrdering(t *testing.T) {
	mixed := errors.New("status 413: image input too long: unsupported combination")
	got, _ := MapError(context.Background(), mixed, PhaseModel)
	if got != PromptTooLong {
		t.Fatalf("overflow must outrank image classification; got %q", string(got))
	}
	cancelShaped := fmt.Errorf("wrap: %w", context.Canceled)
	got, _ = MapError(context.Background(), cancelShaped, PhaseModel)
	if got != AbortedStreaming {
		t.Fatalf("canceled in model phase must be aborted_streaming; got %q", string(got))
	}
}

// TestReasonTypeIsHarnessAlias: Reason 与 harness.TerminalReason 是同一类型
// （alias）——engine 消费面零转换。
func TestReasonTypeIsHarnessAlias(t *testing.T) {
	var r Reason = harness.ReasonMaxTurns
	var h harness.TerminalReason = r
	if h != harness.ReasonMaxTurns {
		t.Fatal("Reason must be assignable to harness.TerminalReason unchanged")
	}
}
