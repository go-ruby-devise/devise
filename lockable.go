// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "errors"

// --- Lockable module ---
//
// Ports Devise::Models::Lockable: locking after too many failed attempts, time-
// and token-based unlocking, and the valid_for_authentication? lock gate.

// ErrUnlockTokenNotFound is returned by [Config.UnlockAccessByToken] when no
// record matches the unlock token.
var ErrUnlockTokenNotFound = errors.New("devise: unlock token not found")

// LockAccess locks the account, faithful to lock_access!: it stamps locked_at,
// mints an unlock token when the email unlock strategy is enabled, saves, and
// (when sendInstructions is true and the strategy allows email) invokes the
// unlock mailer callback.
func (r *Record) LockAccess(sendInstructions bool) error {
	r.m.Set(AttrLockedAt, r.cfg.now())
	var raw string
	if r.unlockStrategyEnabled(UnlockEmail) {
		raw = r.setUnlockToken()
	}
	if err := r.m.Save(); err != nil {
		return err
	}
	if sendInstructions && r.unlockStrategyEnabled(UnlockEmail) && r.cfg.SendUnlockInstructions != nil {
		r.cfg.SendUnlockInstructions(r, raw)
	}
	return nil
}

// UnlockAccess unlocks the account, faithful to unlock_access!: it clears
// locked_at, resets failed_attempts to 0, clears unlock_token, and saves.
func (r *Record) UnlockAccess() error {
	r.m.Set(AttrLockedAt, nil)
	r.m.Set(AttrFailedAttempts, 0)
	r.m.Set(AttrUnlockToken, nil)
	return r.m.Save()
}

// AccessLocked reports whether the account is currently locked, faithful to
// access_locked?: locked_at is set and the lock has not expired.
func (r *Record) AccessLocked() bool {
	_, ok := r.getTime(AttrLockedAt)
	return ok && !r.lockExpired()
}

// FailedAttempts returns the current failed-attempt count (failed_attempts).
func (r *Record) FailedAttempts() int { return r.getInt(AttrFailedAttempts) }

// lockExpired reports whether a time-based lock has elapsed, faithful to
// lock_expired?: only meaningful when the time unlock strategy is enabled.
func (r *Record) lockExpired() bool {
	if !r.unlockStrategyEnabled(UnlockTime) {
		return false
	}
	lockedAt, ok := r.getTime(AttrLockedAt)
	if !ok {
		return false
	}
	return lockedAt.Before(r.cfg.now().Add(-r.cfg.UnlockIn))
}

// attemptsExceeded reports whether failed_attempts has reached maximum_attempts,
// faithful to attempts_exceeded?.
func (r *Record) attemptsExceeded() bool {
	return r.FailedAttempts() >= r.cfg.MaximumAttempts
}

// unlockStrategyEnabled reports whether an unlock strategy is active, faithful to
// unlock_strategy_enabled?: the "both" strategy enables time and email.
func (r *Record) unlockStrategyEnabled(s UnlockStrategy) bool {
	switch r.cfg.UnlockStrategy {
	case UnlockBoth:
		return s == UnlockTime || s == UnlockEmail
	default:
		return r.cfg.UnlockStrategy == s
	}
}

// lockStrategyEnabled reports whether the failed-attempts lock strategy is on,
// faithful to lock_strategy_enabled?(:failed_attempts).
func (r *Record) lockStrategyEnabled() bool {
	return r.cfg.LockStrategy == LockFailedAttempts
}

// setUnlockToken mints an unlock token, stores its digest, and returns the raw
// token, faithful to Lockable's use of the token generator for :unlock_token.
func (r *Record) setUnlockToken() string {
	gen := r.cfg.tokenGenerator()
	raw, enc := gen.Generate(AttrUnlockToken, func(digest string) bool {
		_, ok := r.cfg.find(map[string]any{AttrUnlockToken: digest})
		return ok
	})
	r.m.Set(AttrUnlockToken, enc)
	return raw
}

// ValidForAuthentication runs the password check through Lockable's gate,
// faithful to Lockable#valid_for_authentication?. When the failed-attempts
// strategy is off it is just check(). Otherwise: a successful check on an
// unlocked account passes; any other outcome increments failed_attempts, locks
// the account when the threshold is reached (else saves the new count), and
// fails. It mirrors Devise's return of the check result, gated by the lock.
func (r *Record) ValidForAuthentication(check func() bool) bool {
	if !r.lockStrategyEnabled() {
		return check()
	}
	if check() && !r.AccessLocked() {
		return true
	}
	r.m.Set(AttrFailedAttempts, r.FailedAttempts()+1)
	if r.attemptsExceeded() {
		if !r.AccessLocked() {
			// LockAccess saves; ignore its error here to match Devise's
			// save(validate: false) fire-and-continue.
			_ = r.LockAccess(true)
		}
	} else {
		_ = r.m.Save()
	}
	return false
}

// UnlockAccessByToken is the class-level unlock flow, faithful to
// unlock_access_by_token: it digests the raw token, finds the record, and
// unlocks it.
func (c *Config) UnlockAccessByToken(rawToken string) (*Record, error) {
	enc := c.tokenGenerator().Digest(AttrUnlockToken, rawToken)
	m, ok := c.find(map[string]any{AttrUnlockToken: enc})
	if !ok {
		return nil, ErrUnlockTokenNotFound
	}
	r := New(c, m)
	if err := r.UnlockAccess(); err != nil {
		return r, err
	}
	return r, nil
}
