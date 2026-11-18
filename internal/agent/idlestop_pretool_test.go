package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/harness"
	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

// 持续调工具的 worker，空转判据也必须能收场。
//
// 回归背景（2026-10-21 线上实测）：任务 5 的 5 个意图跑了 34~58 轮、
// **一次写回都没有**（tool_result 里只有 Bash/Read/WebFetch，没有一次
// record_fact / report_finding / insert_assets），却一直不被收场。
//
// 根因：idlestop 挂在 harness 的 **Stop** hook 上，而 SDK 只在
// `len(toolUses) == 0`（模型该轮没调工具）时才调用 Stop
// （harness/query.go:466）。一个持续干活的 worker 每轮都调工具 →
// **Stop 永远不被调用** → 空转判据形同虚设。
//
// 而 PreToolUse（harness/tools.go:78）才是**每次工具调用前**都调的钩子，
// steer_work 的纠偏机制正是挂在它上面生效的。空转判据必须搬到那里。
func TestIdleStopFiresWhileWorkerKeepsCallingTools(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(reason string) {})
	ageStopper(hooks.stop, time.Hour) // 越过起跑宽限期

	// 模拟一个持续调工具的 worker：每一轮 PreToolUse 都过，工具也都执行了，
	// 但始终没有任何写回。**期间不调用 Stop**（SDK 在这种场景下不会调它）。
	for round := 0; round < idleStopRounds+2; round++ {
		block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"true"}`))
		if block {
			// 被拦住说明空转判据生效：提示模型收场并写回。
			if !strings.Contains(msg, "写回") {
				t.Errorf("拦截消息应说明要写回: %q", msg)
			}
			if !strings.Contains(msg, "停止") && !strings.Contains(msg, "收手") {
				t.Errorf("拦截消息应要求停止探测: %q", msg)
			}
			return
		}
		// 工具「执行」了，但没有任何写回 → 下一轮仍然零增量。
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	t.Fatalf("连续 %d 轮调工具且零写回后，空转判据应拦住本次工具调用", idleStopRounds+2)
}

// 持续产出的 worker 绝不能被 PreToolUse 拦住——深度探索不受影响。
func TestIdleStopDoesNotBlockProductiveWorker(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	for round := 0; round < 10; round++ {
		fw.addFacts(1) // 每轮都有写回
		block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if block {
			t.Fatalf("第 %d 轮有写回却被拦住——持续产出的 worker 必须能一直跑", round+1)
		}
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
}

// PreToolUse 的拦截必须只在「零写回达到阈值」时发生，且要给一次缓冲：
// 第一次拦住是提示，模型若仍不停，第二次才真收场。
func TestIdleStopPreToolUseNudgesThenStops(t *testing.T) {
	fw := &fakeWrites{}
	stoppedReason := ""
	hooks := wrapIdleStop(nil, fw.get, func(reason string) { stoppedReason = reason })
	ageStopper(hooks.stop, time.Hour)

	// 阈值是连续 idleStopRounds 轮无写回，所以前几轮都放行。
	// 计数由 PostToolUse 推进（工具执行后），判据在 PreToolUse（工具执行前）——
	// 所以「第 N 次工具执行」被拦是在「第 N+1 次 PreToolUse」上。循环跑够
	// idleStopRounds+1 次，必然撞上拦截。
	var block bool
	var msg string
	for i := 0; i < idleStopRounds+1; i++ {
		block, msg, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if block {
			break
		}
		// 工具执行了（零写回）→ 推进一轮计数。
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	if !block {
		t.Fatalf("连续 %d 轮零写回后应拦住本次工具调用", idleStopRounds)
	}
	if msg == "" {
		t.Error("拦截时必须给出提示文案")
	}
	if stoppedReason != "" {
		t.Error("第一次拦截不应直接收场（要给模型写回的机会）")
	}

	// 模型收到提示后仍不停（继续零写回）：先继续拦截提醒，到 prevent 轮
	// 才真收场（U3/上游 v0.4.62：nudge 3 轮 + prevent 5 轮，不再无限 block 辩论）。
	var block2 bool
	// nudge 后再推进 prevent-nudge 轮；cancel 发生在「到 prevent 轮的那次
	// PreToolUse」上（peek 判据），所以循环后再补一次 PreToolUse 触发。
	for i := 0; i < idleStopPreventRounds-idleStopRounds; i++ {
		block2, _, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if !block2 {
			t.Fatalf("提示后第 %d 轮仍零写回，应继续拦截", i+1)
		}
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	block2, _, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
	if !block2 {
		t.Fatal("到 prevent 轮仍应拦截")
	}
	if stoppedReason == "" {
		t.Errorf("到 prevent 轮(%d)应真收场并记原因", idleStopPreventRounds)
	}
}

// 同轮并发工具调用（issue #8，上游 v0.4.72）：prevent 必须**额外要求 nudge 之后
// 又推进过至少一轮**——同轮并发发出的其余 tool_use 不能从「首次提示」直接跳到
// 终结，worker 没机会写回就被打断、在途结果永久丢失。
func TestIdleStopConcurrentSameRoundDoesNotSkipToPrevent(t *testing.T) {
	fw := &fakeWrites{}
	var cancelCalls int
	hooks := wrapIdleStop(nil, fw.get, func(string) {}, func(err error) { cancelCalls++ })
	ageStopper(hooks.stop, time.Hour)

	// 推到 nudge 档（连续 idleStopRounds 轮零写回）。
	for i := 0; i < idleStopRounds+1; i++ {
		hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	// nudge 之后的**同一轮**里并发发出的第二个 tool_use：rounds 未推进，
	// 只能落在提示档，绝不触发 cancel。
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
	if !block {
		t.Fatal("已 nudge 后的同轮并发调用应继续拦截")
	}
	if strings.Contains(msg, "本轮就此结束") {
		t.Errorf("同轮并发调用不得跳到终结档: %q", msg)
	}
	if cancelCalls != 0 {
		t.Fatalf("同轮并发调用不得取消 run context，cancel 被调了 %d 次", cancelCalls)
	}

	// 之后逐轮推进（模型仍未写回）：cancel 只会在 rounds 达到 prevent 档且
	// 已推进过（≠nudge 当轮）时首次触发。生产上 cancel 之后 run 已死，不会再有
	// 后续 PreToolUse；这里验证「同轮不取消、推进后必取消」。
	fired := false
	for i := 0; i < idleStopPreventRounds+1; i++ {
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
		if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`)); block && cancelCalls > 0 {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("推进到 prevent 档后应触发 run context 取消")
	}
}

// 拦住工具调用时，inner（guard 管控链）仍要照常被调用——不能因为我们的
// 空转判据就绕过了拦截规则。
func TestIdleStopPreToolUseStillCallsInner(t *testing.T) {
	fw := &fakeWrites{}
	inner := &recordingHookRunner{}
	hooks := wrapIdleStop(inner, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// 零写回达到阈值 → 我们的判据要拦住。
	for i := 0; i < idleStopRounds; i++ {
		if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`)); !block {
			hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
		}
	}

	// inner 至少被调用过一次（说明链路没被短路）。
	if inner.preCalls == 0 {
		t.Error("inner.PreToolUse 未被调用——拦截链被短路了")
	}
}

// recordingHookRunner 记录 PreToolUse 被调了几次。
type recordingHookRunner struct {
	preCalls int
}

func (r *recordingHookRunner) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	r.preCalls++
	return false, "", nil
}

func (r *recordingHookRunner) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
}

func (r *recordingHookRunner) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

var _ harness.HookRunner = (*recordingHookRunner)(nil)

// 写回类工具绝不能被空转判据拦住。
//
// 回归风险：worker 攒了一堆成果正要 record_fact 写回，这时被拦住 = 成果全丢。
// 那比空转更糟——空转只是浪费时间，拦住写回是丢数据。
func TestIdleStopNeverBlocksWriteBackTools(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// 先把计数推到阈值（连续零写回）。
	for i := 0; i < idleStopRounds+1; i++ {
		if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`)); !block {
			hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
		}
	}

	for _, name := range []string{"record_fact", "insert_assets", "report_finding"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if block {
			t.Errorf("写回工具 %q 被空转判据拦住了（msg=%q）——成果会丢", name, msg)
		}
	}
}

// 写回类工具不推进空转计数——写回本身就是「有产出」（writes 增长会让计数
// 被 refreshLocked 清零），不该再额外 +1，否则「一轮有产出」会被算成两轮，
// 阈值从 3 轮缩到 1.5 轮。
func TestIdleStopWriteBackDoesNotAdvanceCounter(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// 两轮探测工具（零写回）→ 计数 2。
	for i := 0; i < 2; i++ {
		hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	roundsAfterProbes := hooks.stop.rounds
	if roundsAfterProbes != 2 {
		t.Fatalf("两轮探测后计数 = %d, want 2", roundsAfterProbes)
	}

	// 一次写回工具：计数不应变化（写回会让 writes 增长 → refreshLocked 清零）。
	hooks.PreToolUse(context.Background(), "record_fact", []byte(`{}`))
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{}`), []byte(`ok`), false)
	if hooks.stop.rounds != roundsAfterProbes {
		t.Errorf("写回工具推进了计数：%d → %d（写回不推进）",
			roundsAfterProbes, hooks.stop.rounds)
	}
}
