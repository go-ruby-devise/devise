// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"testing"
	"time"
)

func TestSetResetPasswordToken(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m)
	raw, err := r.SetResetPasswordToken()
	if err != nil {
		t.Fatalf("SetResetPasswordToken: %v", err)
	}
	if raw == "" {
		t.Fatal("expected a raw token")
	}
	if m.attrs[AttrResetPasswordToken] == "" || m.attrs[AttrResetPasswordToken] == nil {
		t.Fatal("expected the enc digest to be stored")
	}
	if _, ok := m.attrs[AttrResetPasswordSentAt].(time.Time); !ok {
		t.Fatal("expected reset_password_sent_at to be stamped")
	}
	if m.saves != 1 {
		t.Fatalf("saves = %d, want 1", m.saves)
	}
}

func TestSetResetPasswordTokenRetry(t *testing.T) {
	cfg := testConfig()
	cfg.Finder = countingTrueFinder(1) // one digest collision then free
	r := New(cfg, newModel())
	if _, err := r.SetResetPasswordToken(); err != nil {
		t.Fatalf("SetResetPasswordToken: %v", err)
	}
}

func TestSetResetPasswordTokenSaveError(t *testing.T) {
	m := newModel()
	m.saveErr = errSave
	r := New(testConfig(), m)
	if _, err := r.SetResetPasswordToken(); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestSendResetPasswordInstructions(t *testing.T) {
	var gotRaw string
	cfg := testConfig()
	cfg.SendResetPasswordInstructions = func(_ *Record, raw string) { gotRaw = raw }
	r := New(cfg, newModel())
	raw, err := r.SendResetPasswordInstructions()
	if err != nil {
		t.Fatalf("SendResetPasswordInstructions: %v", err)
	}
	if gotRaw != raw {
		t.Fatal("the mailer callback should receive the raw token")
	}
}

func TestSendResetPasswordInstructionsError(t *testing.T) {
	m := newModel()
	m.saveErr = errSave
	r := New(testConfig(), m)
	if _, err := r.SendResetPasswordInstructions(); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestResetPasswordPeriodValid(t *testing.T) {
	cfg := testConfig() // reset_password_within = 6h, now = baseTime

	// No token sent.
	if New(cfg, newModel()).ResetPasswordPeriodValid() {
		t.Fatal("no sent-at should be invalid")
	}
	// Within the window.
	fresh := New(cfg, newModel(AttrResetPasswordSentAt, baseTime.Add(-time.Hour)))
	if !fresh.ResetPasswordPeriodValid() {
		t.Fatal("a one-hour-old token should be valid")
	}
	// Past the window.
	stale := New(cfg, newModel(AttrResetPasswordSentAt, baseTime.Add(-7*time.Hour)))
	if stale.ResetPasswordPeriodValid() {
		t.Fatal("a seven-hour-old token should be expired")
	}
}

func TestResetPasswordByTokenSuccess(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw, err := r.SetResetPasswordToken()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg.Finder = tableFinder(m) // find by the stored enc digest

	got, err := cfg.ResetPasswordByToken(raw, "newpass1", "newpass1")
	if err != nil {
		t.Fatalf("ResetPasswordByToken: %v", err)
	}
	if !got.ValidPassword("newpass1") {
		t.Fatal("the new password should be set")
	}
	if m.attrs[AttrResetPasswordToken] != nil {
		t.Fatal("the reset token should be cleared")
	}
}

func TestResetPasswordByTokenNotFound(t *testing.T) {
	cfg := testConfig() // no finder -> no match
	if _, err := cfg.ResetPasswordByToken("bogus", "a", "a"); !errors.Is(err, ErrResetTokenNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

func TestResetPasswordByTokenExpired(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw, _ := r.SetResetPasswordToken()
	// Age the token past the window.
	m.attrs[AttrResetPasswordSentAt] = baseTime.Add(-10 * time.Hour)
	cfg.Finder = tableFinder(m)
	if _, err := cfg.ResetPasswordByToken(raw, "newpass1", "newpass1"); !errors.Is(err, ErrResetTokenExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestResetPasswordByTokenConfirmationMismatch(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw, _ := r.SetResetPasswordToken()
	cfg.Finder = tableFinder(m)
	_, err := cfg.ResetPasswordByToken(raw, "newpass1", "different")
	var ve ValidationError
	if !errors.As(err, &ve) || ve.Reason != "confirmation" {
		t.Fatalf("expected a confirmation ValidationError, got %v", err)
	}
}

func TestResetPasswordSaveError(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw, _ := r.SetResetPasswordToken()
	cfg.Finder = tableFinder(m)
	m.saveErr = errSave
	if _, err := cfg.ResetPasswordByToken(raw, "newpass1", "newpass1"); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestResetPasswordDigestError(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := New(cfg, m)
	raw, _ := r.SetResetPasswordToken()
	cfg.Finder = tableFinder(m)
	cfg.Stretches = 99 // make SetPassword (inside ResetPassword) fail
	if _, err := cfg.ResetPasswordByToken(raw, "newpass1", "newpass1"); err == nil {
		t.Fatal("expected a digest error")
	}
}

func TestValidationErrorError(t *testing.T) {
	e := ValidationError{Attribute: "password", Reason: "confirmation"}
	if e.Error() != "devise: password confirmation" {
		t.Fatalf("unexpected Error() = %q", e.Error())
	}
}
