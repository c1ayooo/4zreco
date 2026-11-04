package agent

import (
	"context"

	"github.com/c1ayooo/4zreco/internal/db"
)

// RunInfo identifies WHICH run a tool call belongs to. Tool assembly only receives
// (ctx, agentKey) — the task/exploration ids live in the caller's arguments, not the
// ctx — so anything wired at assembly time (currently the Skill ledger in
// server/assembly.go) has no way to attribute a call to a task. Each run attaches
// its own RunInfo before calling AugmentTools; the wiring closure reads it once and
// captures it, so per-run attribution stays correct without threading parameters
// through the tool layer. Same pattern as TaskClock (see taskclock.go).
//
// Zero value = attribution unknown; every consumer must treat it as optional.
type RunInfo struct {
	TaskID        int64  // task registry id; 0 for non-task runs (chat sessions)
	ExplorationID int64  // exploration id; 0 when unknown
	IntentID      int64  // worker's intent node; 0 for planner/mainagent/chat
	SessionID     string // chat conversation id; empty for task runs
	// Kind names the agent role. RunInfo's id triple cannot tell planner from
	// mainagent (both have TaskID+ExplorationID and no IntentID), and the tool
	// log needs the distinction: "planner called no tools for 20 minutes" and
	// "mainagent called no tools for 20 minutes" are different failures.
	Kind string // "planner" | "worker" | "main" | "chat"; empty = unknown
}

// Agent role labels carried in RunInfo.Kind.
const (
	KindPlanner = "planner"
	KindWorker  = "worker"
	KindMain    = "main"
	KindChat    = "chat"
)

// explorationID reads a store's exploration id, tolerating a nil store (planner and
// worker runs can be driven without one in tests).
func explorationID(ts *db.ExplorationStore) int64 {
	if ts == nil {
		return 0
	}
	return ts.ID()
}

type runInfoKey struct{}

// WithRunInfo attaches run attribution to ctx.
func WithRunInfo(ctx context.Context, ri RunInfo) context.Context {
	return context.WithValue(ctx, runInfoKey{}, ri)
}

// RunInfoFrom reads the RunInfo (zero value if none attached).
func RunInfoFrom(ctx context.Context) RunInfo {
	if v, ok := ctx.Value(runInfoKey{}).(RunInfo); ok {
		return v
	}
	return RunInfo{}
}
