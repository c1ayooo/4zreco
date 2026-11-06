package traffic

import (
	"net"
	"testing"
	"time"
)

// TestServingFlipsOnStartAndBindFailure nails the recorder-liveness contract:
// Serving() is true while the proxy listens, and flips false the moment a
// failed Start returns — the bind-conflict case that used to die as one log
// line while the capture toggle kept claiming recording was on (real incident:
// an old instance holding the port made a fresh instance record nothing).
func TestServingFlipsOnStartAndBindFailure(t *testing.T) {
	// Occupied port: Start must return a bind error and Serving must be false.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tr, err := Open(t.TempDir(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if err := tr.Start(); err == nil {
		t.Fatal("Start on an occupied port must fail")
	}
	if tr.Serving() {
		t.Fatal("Serving must be false after a failed Start")
	}

	// Free port: Serving turns true once the proxy is listening, false after Close.
	tr2, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- tr2.Start() }()
	deadline := time.Now().Add(5 * time.Second)
	for !tr2.Serving() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tr2.Serving() {
		t.Fatal("Serving must be true while the proxy listens")
	}
	if err := tr2.proxy.Close(); err != nil {
		t.Fatalf("proxy close: %v", err)
	}
	// Start's return after an explicit proxy close is an expected shutdown
	// error ("http: Server closed") — what matters is the liveness flag.
	<-startErr
	if tr2.Serving() {
		t.Fatal("Serving must be false after Start returns")
	}
	_ = tr2.Close()
}
