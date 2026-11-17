package agent

import (
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// O3 收敛回归：kernelOptionsSeed.todos 必须接回 askernel.Options.Todos。
// 曾因漏接导致 planner.Plan 里 opts.Todos.List() 空指针 panic（全量门禁
// internal/server 整包崩），worker/mainagent/chat 的 TodoWrite 工具也被静默丢掉。
func TestKernelOptionsPropagatesTodos(t *testing.T) {
	store := actool.NewTodoStore()
	opts := kernelOptions(kernelOptionsSeed{todos: store})
	if opts.Todos != store {
		t.Fatalf("kernelOptions dropped seed.todos: got %v, want the passed store", opts.Todos)
	}
	opts.Todos.List() // 非 nil store 必须可用（空指针时这里 panic）
	// nil = 不挂 TodoWrite（session.go 按 nil 判定），必须原样传播为 nil 而非 panic。
	if nilOpts := kernelOptions(kernelOptionsSeed{}); nilOpts.Todos != nil {
		t.Fatalf("kernelOptions with nil seed.todos: got %v, want nil", nilOpts.Todos)
	}
}
