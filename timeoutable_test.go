// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"testing"
	"time"
)

func TestTimedOutDisabled(t *testing.T) {
	// nil timeout_in -> never times out.
	if New(testConfig(), newModel()).TimedOut(baseTime.Add(-1000 * time.Hour)) {
		t.Fatal("a nil timeout should never time out")
	}
}

func TestTimedOut(t *testing.T) {
	cfg := testConfig()
	d := 30 * time.Minute
	cfg.TimeoutIn = &d
	r := New(cfg, newModel())

	// Zero last-access -> not timed out.
	if r.TimedOut(time.Time{}) {
		t.Fatal("a zero last-access should not time out")
	}
	// Recent activity -> not timed out.
	if r.TimedOut(baseTime.Add(-5 * time.Minute)) {
		t.Fatal("recent activity should not time out")
	}
	// Idle beyond the window -> timed out.
	if !r.TimedOut(baseTime.Add(-time.Hour)) {
		t.Fatal("activity older than timeout_in should time out")
	}
}

func TestTimeoutIn(t *testing.T) {
	if _, ok := New(testConfig(), newModel()).TimeoutIn(); ok {
		t.Fatal("default timeout should be disabled")
	}
	cfg := testConfig()
	d := 15 * time.Minute
	cfg.TimeoutIn = &d
	if got, ok := New(cfg, newModel()).TimeoutIn(); !ok || got != d {
		t.Fatalf("TimeoutIn = %v,%v want %v,true", got, ok, d)
	}
}
