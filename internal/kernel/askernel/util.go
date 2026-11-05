package askernel

import "time"

// today renders the local date for the per-request system-reminder
// (norma agentcore.buildSystemReminder parity).
func today() string { return time.Now().Format("2006-01-02") }
