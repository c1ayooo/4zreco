package traffic

import (
	"testing"
)

func TestSetPoolValidation(t *testing.T) {
	s := &selector{}
	if err := s.SetPool(nil, "bogus"); err == nil {
		t.Fatal("bogus strategy must be rejected")
	}
	if err := s.SetPool([]PoolEntry{
		{URL: "socks5://127.0.0.1:1080", Name: "a", Enabled: true},
		{URL: "not-a-proxy", Name: "bad", Enabled: true},
	}, "round_robin"); err != nil {
		t.Fatal(err)
	}
	// bad entry skipped, good one kept
	if len(s.entries) != 1 {
		t.Fatalf("entries=%d want 1", len(s.entries))
	}
}

func TestPickRoundRobinAndEmpty(t *testing.T) {
	s := &selector{}
	if got := s.Pick("example.com:443"); got != nil {
		t.Fatalf("empty pool must return nil, got %v", got)
	}
	_ = s.SetPool([]PoolEntry{
		{URL: "http://a:1", Name: "a", Enabled: true},
		{URL: "http://b:2", Name: "b", Enabled: true},
	}, "round_robin")
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		u := s.Pick("example.com:443")
		seen[u.String()]++
	}
	if len(seen) != 2 {
		t.Fatalf("round robin only used %v", seen)
	}
}

func TestPickStickyHost(t *testing.T) {
	s := &selector{}
	_ = s.SetPool([]PoolEntry{
		{URL: "http://a:1", Name: "a", Enabled: true},
		{URL: "http://b:2", Name: "b", Enabled: true},
	}, "sticky_host")
	first := s.Pick("target.test:443").String()
	for i := 0; i < 5; i++ {
		if got := s.Pick("target.test:443").String(); got != first {
			t.Fatalf("sticky broken: %s != %s", got, first)
		}
	}
}

func TestCircuitBreaker(t *testing.T) {
	s := &selector{}
	_ = s.SetPool([]PoolEntry{{URL: "http://a:1", Name: "a", Enabled: true}}, "round_robin")
	// 4 failures stay below threshold; the 5th opens the breaker.
	for i := 0; i < 4; i++ {
		s.ReportResult("http://a:1", false)
	}
	if got := s.Pick("x.test:443"); got == nil {
		t.Fatal("4 failures must not trip breaker")
	}
	s.ReportResult("http://a:1", false)
	if got := s.Pick("x.test:443"); got != nil {
		t.Fatal("5th failure must open breaker (Pick returns nil)")
	}
	// a success clears the counter — never reaches breaker
	s2 := &selector{}
	_ = s2.SetPool([]PoolEntry{{URL: "http://b:1", Name: "b", Enabled: true}}, "round_robin")
	for i := 0; i < 3; i++ {
		s2.ReportResult("http://b:1", false)
	}
	s2.ReportResult("http://b:1", true)
	s2.ReportResult("http://b:1", false)
	s2.ReportResult("http://b:1", false)
	if got := s2.Pick("x.test:443"); got == nil {
		t.Fatal("success must reset failure counter (4 < 5)")
	}
}
