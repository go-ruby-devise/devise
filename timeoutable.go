// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "time"

// --- Timeoutable module ---
//
// Ports Devise::Models::Timeoutable: idle-session expiry.

// TimedOut reports whether a session whose last activity was at lastAccess has
// timed out, faithful to timedout?: never when timeout_in is nil, otherwise when
// lastAccess is at or before timeout_in ago. Devise also returns false while a
// valid remember cookie exists; that short-circuit is the caller's to apply via
// [Record.RememberExpired], since it depends on request state.
func (r *Record) TimedOut(lastAccess time.Time) bool {
	if r.cfg.TimeoutIn == nil {
		return false
	}
	if lastAccess.IsZero() {
		return false
	}
	return !lastAccess.After(r.cfg.now().Add(-*r.cfg.TimeoutIn))
}

// TimeoutIn returns the configured idle window, or false when timeout is
// disabled (timeout_in nil), faithful to Timeoutable#timeout_in.
func (r *Record) TimeoutIn() (time.Duration, bool) {
	if r.cfg.TimeoutIn == nil {
		return 0, false
	}
	return *r.cfg.TimeoutIn, true
}
