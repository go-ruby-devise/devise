// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"testing"
	"time"
)

func TestGenerateConfirmationToken(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m)
	raw := r.GenerateConfirmationToken()
	if raw == "" {
		t.Fatal("expected a raw confirmation token")
	}
	if m.attrs[AttrConfirmationToken] == nil {
		t.Fatal("expected the enc digest to be stored")
	}
	if _, ok := m.attrs[AttrConfirmationSentAt].(time.Time); !ok {
		t.Fatal("expected confirmation_sent_at to be stamped")
	}
	if m.saves != 0 {
		t.Fatal("GenerateConfirmationToken should not save")
	}
}

func TestGenerateConfirmationTokenRetry(t *testing.T) {
	cfg := testConfig()
	cfg.Finder = countingTrueFinder(1)
	if r := New(cfg, newModel()).GenerateConfirmationToken(); r == "" {
		t.Fatal("expected a token after a retry")
	}
}

func TestSendConfirmationInstructions(t *testing.T) {
	var got string
	cfg := testConfig()
	cfg.SendConfirmationInstructions = func(_ *Record, raw string) { got = raw }
	m := newModel()
	r := New(cfg, m)
	raw, err := r.SendConfirmationInstructions()
	if err != nil {
		t.Fatalf("SendConfirmationInstructions: %v", err)
	}
	if got != raw || m.saves != 1 {
		t.Fatal("should save once and hand the raw token to the mailer")
	}
}

func TestSendConfirmationInstructionsSaveError(t *testing.T) {
	m := newModel()
	m.saveErr = errSave
	r := New(testConfig(), m)
	if _, err := r.SendConfirmationInstructions(); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestConfirmedAndConfirm(t *testing.T) {
	m := newModel(AttrConfirmationSentAt, baseTime)
	r := New(testConfig(), m)
	if r.Confirmed() {
		t.Fatal("a fresh record should be unconfirmed")
	}
	if err := r.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !r.Confirmed() {
		t.Fatal("Confirm should mark the record confirmed")
	}
	if m.attrs[AttrConfirmationToken] != nil {
		t.Fatal("Confirm should clear the confirmation token")
	}
}

func TestConfirmAlreadyConfirmed(t *testing.T) {
	r := New(testConfig(), newModel(AttrConfirmedAt, baseTime))
	if err := r.Confirm(); !errors.Is(err, ErrAlreadyConfirmed) {
		t.Fatalf("expected already-confirmed, got %v", err)
	}
}

func TestConfirmPeriodExpired(t *testing.T) {
	cfg := testConfig()
	within := 24 * time.Hour
	cfg.ConfirmWithin = &within
	m := newModel(AttrConfirmationSentAt, baseTime.Add(-48*time.Hour))
	if err := New(cfg, m).Confirm(); !errors.Is(err, ErrConfirmationPeriodExpired) {
		t.Fatalf("expected period-expired, got %v", err)
	}
}

func TestConfirmSaveError(t *testing.T) {
	m := newModel(AttrConfirmationSentAt, baseTime)
	m.saveErr = errSave
	if err := New(testConfig(), m).Confirm(); !errors.Is(err, errSave) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestConfirmationPeriodValid(t *testing.T) {
	// nil allow_unconfirmed_access_for -> always valid.
	if !New(testConfig(), newModel()).ConfirmationPeriodValid() {
		t.Fatal("nil grace window should always be valid")
	}

	cfg := testConfig()
	grace := 3 * 24 * time.Hour
	cfg.AllowUnconfirmedAccessFor = &grace

	// No sent-at -> invalid.
	if New(cfg, newModel()).ConfirmationPeriodValid() {
		t.Fatal("no confirmation_sent_at should be invalid within a finite grace")
	}
	// Within window.
	if !New(cfg, newModel(AttrConfirmationSentAt, baseTime.Add(-time.Hour))).ConfirmationPeriodValid() {
		t.Fatal("a recent sent-at should be within the grace window")
	}
	// Past window.
	if New(cfg, newModel(AttrConfirmationSentAt, baseTime.Add(-10*24*time.Hour))).ConfirmationPeriodValid() {
		t.Fatal("an old sent-at should be outside the grace window")
	}
}

func TestConfirmationPeriodExpired(t *testing.T) {
	// nil confirm_within -> never expired.
	if New(testConfig(), newModel(AttrConfirmationSentAt, baseTime.Add(-1000*time.Hour))).ConfirmationPeriodExpired() {
		t.Fatal("nil confirm_within should never expire")
	}

	cfg := testConfig()
	within := 24 * time.Hour
	cfg.ConfirmWithin = &within

	// No sent-at -> not expired.
	if New(cfg, newModel()).ConfirmationPeriodExpired() {
		t.Fatal("no sent-at should not be expired")
	}
	// Fresh -> not expired.
	if New(cfg, newModel(AttrConfirmationSentAt, baseTime.Add(-time.Hour))).ConfirmationPeriodExpired() {
		t.Fatal("a fresh token should not be expired")
	}
	// Old -> expired.
	if !New(cfg, newModel(AttrConfirmationSentAt, baseTime.Add(-48*time.Hour))).ConfirmationPeriodExpired() {
		t.Fatal("an old token should be expired")
	}
}

func TestActiveForAuthentication(t *testing.T) {
	// Confirmed -> active.
	if !New(testConfig(), newModel(AttrConfirmedAt, baseTime)).ActiveForAuthentication() {
		t.Fatal("a confirmed record should be active")
	}
	// Unconfirmed but within grace (nil grace) -> active.
	if !New(testConfig(), newModel()).ActiveForAuthentication() {
		t.Fatal("an unconfirmed record in an unlimited grace should be active")
	}
	// Unconfirmed and outside grace -> inactive.
	cfg := testConfig()
	grace := time.Hour
	cfg.AllowUnconfirmedAccessFor = &grace
	if New(cfg, newModel(AttrConfirmationSentAt, baseTime.Add(-2*time.Hour))).ActiveForAuthentication() {
		t.Fatal("an unconfirmed record past its grace should be inactive")
	}
}

func TestConfirmByToken(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrConfirmationSentAt, baseTime)
	r := New(cfg, m)
	raw := r.GenerateConfirmationToken()
	cfg.Finder = tableFinder(m)

	got, err := cfg.ConfirmByToken(raw)
	if err != nil {
		t.Fatalf("ConfirmByToken: %v", err)
	}
	if !got.Confirmed() {
		t.Fatal("the record should be confirmed")
	}
}

func TestConfirmByTokenNotFound(t *testing.T) {
	cfg := testConfig()
	if _, err := cfg.ConfirmByToken("bogus"); !errors.Is(err, ErrConfirmationTokenNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

func TestConfirmByTokenConfirmError(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrConfirmationSentAt, baseTime, AttrConfirmedAt, baseTime)
	r := New(cfg, m)
	raw := r.GenerateConfirmationToken()
	cfg.Finder = tableFinder(m)
	if _, err := cfg.ConfirmByToken(raw); !errors.Is(err, ErrAlreadyConfirmed) {
		t.Fatalf("expected already-confirmed from ConfirmByToken, got %v", err)
	}
}
