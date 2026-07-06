// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"testing"
	"time"
)

func TestLockAccessWithEmail(t *testing.T) {
	var sentRaw string
	cfg := testConfig() // UnlockBoth -> email enabled
	cfg.SendUnlockInstructions = func(_ *Record, raw string) { sentRaw = raw }
	m := newModel()
	r := New(cfg, m)
	if err := r.LockAccess(true); err != nil {
		t.Fatalf("LockAccess: %v", err)
	}
	if _, ok := m.attrs[AttrLockedAt].(time.Time); !ok {
		t.Fatal("locked_at should be stamped")
	}
	if m.attrs[AttrUnlockToken] == nil {
		t.Fatal("an unlock token should be minted for the email strategy")
	}
	if sentRaw == "" {
		t.Fatal("the unlock mailer should have been invoked")
	}
}

func TestLockAccessNoInstructions(t *testing.T) {
	called := false
	cfg := testConfig()
	cfg.SendUnlockInstructions = func(*Record, string) { called = true }
	if err := New(cfg, newModel()).LockAccess(false); err != nil {
		t.Fatalf("LockAccess: %v", err)
	}
	if called {
		t.Fatal("mailer should not fire when sendInstructions is false")
	}
}

func TestLockAccessTimeStrategyNoToken(t *testing.T) {
	cfg := testConfig()
	cfg.UnlockStrategy = UnlockTime // email disabled
	m := newModel()
	if err := New(cfg, m).LockAccess(true); err != nil {
		t.Fatalf("LockAccess: %v", err)
	}
	if m.attrs[AttrUnlockToken] != nil {
		t.Fatal("no unlock token should be minted without the email strategy")
	}
}

func TestLockAccessTokenRetry(t *testing.T) {
	cfg := testConfig()
	cfg.Finder = countingTrueFinder(1)
	if err := New(cfg, newModel()).LockAccess(false); err != nil {
		t.Fatalf("LockAccess: %v", err)
	}
}

func TestLockAccessSaveError(t *testing.T) {
	m := newModel()
	m.saveErr = errSave
	if err := New(testConfig(), m).LockAccess(true); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestUnlockAccess(t *testing.T) {
	m := newModel(AttrLockedAt, baseTime, AttrFailedAttempts, 5, AttrUnlockToken, "tok")
	if err := New(testConfig(), m).UnlockAccess(); err != nil {
		t.Fatalf("UnlockAccess: %v", err)
	}
	if m.attrs[AttrLockedAt] != nil || m.attrs[AttrUnlockToken] != nil || m.attrs[AttrFailedAttempts] != 0 {
		t.Fatal("UnlockAccess should clear the lock state")
	}
}

func TestUnlockAccessSaveError(t *testing.T) {
	m := newModel()
	m.saveErr = errSave
	if err := New(testConfig(), m).UnlockAccess(); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestAccessLocked(t *testing.T) {
	cfg := testConfig()
	cfg.UnlockStrategy = UnlockNone // no time expiry

	// Not locked.
	if New(cfg, newModel()).AccessLocked() {
		t.Fatal("a record without locked_at is not locked")
	}
	// Locked, no expiry.
	if !New(cfg, newModel(AttrLockedAt, baseTime)).AccessLocked() {
		t.Fatal("a locked record with no time strategy stays locked")
	}
	// Locked but time-expired.
	timeCfg := testConfig() // UnlockBoth includes time; unlock_in = 1h
	old := New(timeCfg, newModel(AttrLockedAt, baseTime.Add(-2*time.Hour)))
	if old.AccessLocked() {
		t.Fatal("a lock older than unlock_in should have expired")
	}
	// Locked and still within the time window.
	fresh := New(timeCfg, newModel(AttrLockedAt, baseTime.Add(-10*time.Minute)))
	if !fresh.AccessLocked() {
		t.Fatal("a fresh time-locked record should still be locked")
	}
}

func TestLockExpiredGuards(t *testing.T) {
	// Time strategy disabled -> never expired.
	noTime := testConfig()
	noTime.UnlockStrategy = UnlockEmail
	if New(noTime, newModel(AttrLockedAt, baseTime.Add(-100*time.Hour))).lockExpired() {
		t.Fatal("without the time strategy a lock never expires")
	}
	// Time strategy on but no locked_at -> not expired.
	if New(testConfig(), newModel()).lockExpired() {
		t.Fatal("no locked_at should not read as expired")
	}
}

func TestFailedAttempts(t *testing.T) {
	if New(testConfig(), newModel(AttrFailedAttempts, 4)).FailedAttempts() != 4 {
		t.Fatal("FailedAttempts should read the column")
	}
}

func TestUnlockStrategyEnabled(t *testing.T) {
	both := New(testConfig(), newModel()) // UnlockBoth
	if !both.unlockStrategyEnabled(UnlockTime) || !both.unlockStrategyEnabled(UnlockEmail) {
		t.Fatal("both should enable time and email")
	}
	if both.unlockStrategyEnabled(UnlockNone) {
		t.Fatal("both should not enable none")
	}
	cfg := testConfig()
	cfg.UnlockStrategy = UnlockEmail
	only := New(cfg, newModel())
	if !only.unlockStrategyEnabled(UnlockEmail) || only.unlockStrategyEnabled(UnlockTime) {
		t.Fatal("email-only should enable email but not time")
	}
}

func TestValidForAuthenticationLockDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.LockStrategy = LockNone
	r := New(cfg, newModel())
	if !r.ValidForAuthentication(func() bool { return true }) {
		t.Fatal("with locking off it should return the check result")
	}
}

func TestValidForAuthenticationSuccess(t *testing.T) {
	r := New(testConfig(), newModel())
	if !r.ValidForAuthentication(func() bool { return true }) {
		t.Fatal("a correct password on an unlocked account should pass")
	}
}

func TestValidForAuthenticationFailIncrements(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m) // maximum_attempts = 20
	if r.ValidForAuthentication(func() bool { return false }) {
		t.Fatal("a wrong password should fail")
	}
	if m.attrs[AttrFailedAttempts] != 1 {
		t.Fatalf("failed_attempts = %v, want 1", m.attrs[AttrFailedAttempts])
	}
	if m.attrs[AttrLockedAt] != nil {
		t.Fatal("one failure should not lock")
	}
}

func TestValidForAuthenticationLocksAtThreshold(t *testing.T) {
	cfg := testConfig()
	cfg.MaximumAttempts = 3
	m := newModel(AttrFailedAttempts, 2) // one more failure hits the threshold
	r := New(cfg, m)
	if r.ValidForAuthentication(func() bool { return false }) {
		t.Fatal("the failing attempt should return false")
	}
	if m.attrs[AttrLockedAt] == nil {
		t.Fatal("hitting maximum_attempts should lock the account")
	}
}

func TestValidForAuthenticationCorrectButLocked(t *testing.T) {
	cfg := testConfig()
	cfg.UnlockStrategy = UnlockNone
	cfg.MaximumAttempts = 100
	m := newModel(AttrLockedAt, baseTime, AttrFailedAttempts, 1)
	r := New(cfg, m)
	// Correct password but the account is already locked -> still fails and
	// increments (not yet at threshold, so it saves).
	if r.ValidForAuthentication(func() bool { return true }) {
		t.Fatal("a locked account must fail even with the right password")
	}
	if m.attrs[AttrFailedAttempts] != 2 {
		t.Fatalf("failed_attempts = %v, want 2", m.attrs[AttrFailedAttempts])
	}
}

func TestValidForAuthenticationExceededAndAlreadyLocked(t *testing.T) {
	cfg := testConfig()
	cfg.UnlockStrategy = UnlockNone
	cfg.MaximumAttempts = 3
	m := newModel(AttrLockedAt, baseTime, AttrFailedAttempts, 5) // already over, already locked
	r := New(cfg, m)
	if r.ValidForAuthentication(func() bool { return false }) {
		t.Fatal("should fail")
	}
	// Already locked + exceeded: no re-lock, no extra save beyond the increment.
	if m.attrs[AttrFailedAttempts] != 6 {
		t.Fatalf("failed_attempts = %v, want 6", m.attrs[AttrFailedAttempts])
	}
}

func TestUnlockAccessByToken(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw := r.setUnlockToken() // stores the enc digest on m
	cfg.Finder = tableFinder(m)

	got, err := cfg.UnlockAccessByToken(raw)
	if err != nil {
		t.Fatalf("UnlockAccessByToken: %v", err)
	}
	if got.Model() != m || m.attrs[AttrUnlockToken] != nil {
		t.Fatal("the account should be unlocked")
	}
}

func TestUnlockAccessByTokenNotFound(t *testing.T) {
	cfg := testConfig()
	if _, err := cfg.UnlockAccessByToken("bogus"); !errors.Is(err, ErrUnlockTokenNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

func TestUnlockAccessByTokenSaveError(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw := r.setUnlockToken()
	cfg.Finder = tableFinder(m)
	m.saveErr = errSave
	if _, err := cfg.UnlockAccessByToken(raw); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}
