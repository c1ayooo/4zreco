package server

import (
	"net"
	"testing"
)

// TestNewManagerOccupiedProxyPortDisablesCapture is the regression test for the
// silent-recorder incident: another instance holding the proxy port used to
// leave capture toggled on with zero traffic ever recorded — Open() succeeded,
// the bind failed inside Start()'s goroutine as one background log line, and
// ProxyAddr kept handing the dead address to every agent. Startup must now
// probe the port and wire no recorder at all, whatever the persisted toggle
// says. Needs Postgres (DSN), like the other manager tests.
func TestNewManagerOccupiedProxyPortDisablesCapture(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m, err := NewManager(t.TempDir(), ln.Addr().String())
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	if m.traffic != nil {
		t.Fatal("occupied proxy port must leave m.traffic nil (fail fast)")
	}
	if m.TrafficProxyAlive() {
		t.Fatal("occupied proxy port must report TrafficProxyAlive=false")
	}
	// Even with the persisted toggle on, a dead recorder must not be advertised.
	if err := m.SetTrafficEnabled(true); err != nil {
		t.Fatalf("set traffic toggle: %v", err)
	}
	if addr := m.ProxyAddr(); addr == ln.Addr().String() {
		t.Fatalf("dead recorder must not be handed out as ProxyAddr, got %q", addr)
	}
	if m.ProxyCACert() != "" {
		t.Fatal("dead recorder must not hand out a CA cert")
	}
}
