package agent

// F1 并发回归（2026-11-13 体检修复）：gate 的 OnResult 在信号量释放【之后】的
// 工具 goroutine 上触发（acllm/toolgate.go），并发工具执行下 capturePump 的
// traceResults 会被并发读写。修复前它是裸 map，-race 下本测试必报
// concurrent map read / concurrent map write（进程级 fatal）。

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

func TestCaptureOnResultConcurrentToolGoroutines(t *testing.T) {
	p := newCapturePump(context.Background(), "并发工具执行", nil, nil)
	defer p.finish()

	const goroutines = 8
	const calls = 50
	callID := func(g, i int) string { return fmt.Sprintf("call-%d-%d", g, i) }

	var wg sync.WaitGroup
	// 多个 goroutine 并发进入 onResult——每个先打一遍共享 callID（去重读+写路径），
	// 再打各自独立 callID（首次写路径），复刻 gate 并发工具的进入形态。
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < calls; i++ {
				p.onResult("shared-call", "Bash", "ok", false)
				p.onResult(callID(g, i), "Bash", "ok", false)
			}
		}(g)
	}
	// 泵侧同时消费 rec（drain 的 tool_use/tool_result 活动走同一 actMu），
	// 贴近真实的并发交错面。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < goroutines*calls; i++ {
			p.rec(db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "{}"})
		}
	}()
	wg.Wait()

	// 去重账本必须完整：共享 callID 与每个独立 callID 都要被标记过。
	if !p.traceResults["shared-call"] {
		t.Fatal("shared callID missing from traceResults")
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < calls; i++ {
			if !p.traceResults[callID(g, i)] {
				t.Fatalf("traceResults missing %s", callID(g, i))
			}
		}
	}
}
