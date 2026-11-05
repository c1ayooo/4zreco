// Concurrency discipline for bridged tool execution
// (docs/Eino深度接入方案-2026-11-05.md §3.3 并发语义映射).
//
// norma's rule, restated for the eino ToolsNode (which is parallel by default
// and has no read-only/concurrency-safe flags of its own):
//
//	safe   (readTool: ReadOnly+Concurrent) → shared slots under the
//	        MaxConcurrency semaphore, running alongside other safe tools
//	unsafe (writeTool: neither flag set)   → exclusive access: it waits until
//	        EVERY in-flight tool finished, and every later tool waits for it
//
// The eino ToolsNode itself fans tool calls out concurrently, so the discipline
// lives inside the gate's endpoint (toolgate.go): acquire before t.Call,
// release after. 4zrec's verified implementation is copied here
// (askernel/middleware.go toolScheduler): an RWMutex layered over the
// MaxConcurrency semaphore — the read side is the safe path, the write side is
// the unsafe path. The write lock gives an unsafe tool everything §3.3
// requires at once: global exclusivity (waits for all in-flight tools to end,
// FIFO at the RWMutex), which subsumes the per-tool-name mutual exclusion two
// same-name unsafe calls need. What §3.3 forbids — a global mutex one-size-
// fits-all that would serialize parallel read-only probing and double the
// worker's per-turn wall clock — is exactly what the read side avoids.
package acllm

import "sync"

// toolScheduler enforces norma's concurrency rule with an RWMutex over a
// MaxConcurrency semaphore: concurrency-safe tools share the read side, a
// non-safe tool takes the write side (exclusive access).
type toolScheduler struct {
	ex  sync.RWMutex
	sem chan struct{}
}

func newToolScheduler(maxConcurrency int) *toolScheduler {
	if maxConcurrency <= 0 {
		maxConcurrency = 10 // norma harness Query default
	}
	return &toolScheduler{sem: make(chan struct{}, maxConcurrency)}
}

// acquire claims one concurrency slot, then the shared (safe) or exclusive
// (unsafe) side of the discipline.
func (s *toolScheduler) acquire(safe bool) {
	s.sem <- struct{}{}
	if safe {
		s.ex.RLock()
	} else {
		s.ex.Lock()
	}
}

// release mirrors acquire in reverse order.
func (s *toolScheduler) release(safe bool) {
	if safe {
		s.ex.RUnlock()
	} else {
		s.ex.Unlock()
	}
	<-s.sem
}
