package acllm

// Deterministic concurrency-discipline tests for toolScheduler (§3.3).
//
// No sleeps-as-assertions: every case is synchronized by channel barriers.
// A tool "acquiring" signals its goroutine reached the scheduler and blocks on
// a release channel it cannot open itself, so overlap/exclusion is structural,
// not timing-based. Negative assertions (X must NOT run while Y holds) use a
// bounded poll with a generous window — the blocker is stuck on a lock the
// holder visibly holds, so only extreme machine load could flake it.

import (
	"testing"
	"time"
)

const (
	pollWindow     = 300 * time.Millisecond // bounded window for "must NOT have happened"
	positiveWindow = 3 * time.Second        // bounded wait for "must have happened"
)

// waitFor receives n signals from ch within positiveWindow, or fails.
func waitFor(t *testing.T, ch <-chan struct{}, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-ch:
		case <-time.After(positiveWindow):
			t.Fatalf("timed out waiting for signal %d/%d", i+1, n)
		}
	}
}

// mustStayBlocked asserts no signal arrives on ch within pollWindow.
func mustStayBlocked(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s proceeded while it must stay blocked", label)
	case <-time.After(pollWindow):
	}
}

// TestSchedulerSafeToolsShareSlots: safe acquires run alongside each other —
// the §3.3 requirement a global mutex would violate.
func TestSchedulerSafeToolsShareSlots(t *testing.T) {
	s := newToolScheduler(10)
	started := make(chan struct{}, 3)
	release := make(chan struct{})

	for i := 0; i < 3; i++ {
		go func() {
			s.acquire(true)
			started <- struct{}{}
			<-release
			s.release(true)
		}()
	}
	// All three must be INSIDE the discipline simultaneously.
	waitFor(t, started, 3)
	mustStayBlocked(t, started, "fourth overlap signal")

	close(release) // let all three finish
}

// TestSchedulerUnsafeExcludesEverything: while a safe tool runs, an unsafe
// acquire waits (global exclusivity); after the safe tool finishes the unsafe
// one proceeds, and then a fresh safe acquire waits for IT.
func TestSchedulerUnsafeExcludesEverything(t *testing.T) {
	s := newToolScheduler(10)

	safeStarted := make(chan struct{}, 1)
	safeRelease := make(chan struct{})
	go func() {
		s.acquire(true)
		safeStarted <- struct{}{}
		<-safeRelease
		s.release(true)
	}()
	waitFor(t, safeStarted, 1)

	unsafeStarted := make(chan struct{}, 1)
	unsafeRelease := make(chan struct{})
	go func() {
		s.acquire(false)
		unsafeStarted <- struct{}{}
		<-unsafeRelease // hold exclusivity until the test has verified blocking
		s.release(false)
	}()
	mustStayBlocked(t, unsafeStarted, "unsafe acquire behind safe holder")

	close(safeRelease) // safe tool finishes
	waitFor(t, unsafeStarted, 1)

	// Now the unsafe tool holds exclusivity: a new safe acquire must wait.
	safe2Started := make(chan struct{}, 1)
	safe2Release := make(chan struct{})
	go func() {
		s.acquire(true)
		safe2Started <- struct{}{}
		<-safe2Release
		s.release(true)
	}()
	mustStayBlocked(t, safe2Started, "safe acquire behind unsafe holder")
	close(safe2Release)
	close(unsafeRelease)
}

// TestSchedulerUnsafeSerializesUnsafe: two unsafe acquires never overlap
// (this is the per-tool-name mutual exclusion the gate needs for write tools —
// the write side of the discipline subsumes it).
func TestSchedulerUnsafeSerializesUnsafe(t *testing.T) {
	s := newToolScheduler(10)

	firstIn := make(chan struct{}, 1)
	firstRelease := make(chan struct{})
	go func() {
		s.acquire(false)
		firstIn <- struct{}{}
		<-firstRelease
		s.release(false)
	}()
	waitFor(t, firstIn, 1)

	secondIn := make(chan struct{}, 1)
	go func() {
		s.acquire(false)
		secondIn <- struct{}{}
		s.release(false)
	}()
	mustStayBlocked(t, secondIn, "second unsafe acquire")
	close(firstRelease)
	waitFor(t, secondIn, 1)
}

// TestSchedulerSemaphoreBounds: MaxConcurrency caps even safe-side parallelism.
func TestSchedulerSemaphoreBounds(t *testing.T) {
	s := newToolScheduler(2)
	started := make(chan struct{}, 3)
	release := make(chan struct{})

	for i := 0; i < 3; i++ {
		go func() {
			s.acquire(true)
			started <- struct{}{}
			<-release
			s.release(true)
		}()
	}
	waitFor(t, started, 2) // two slots in use
	mustStayBlocked(t, started, "third safe acquire beyond MaxConcurrency=2")
	close(release)
	waitFor(t, started, 1) // freed slot lets the third through
}
