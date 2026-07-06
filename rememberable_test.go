// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"testing"
	"time"
)

func TestRememberMeSetsTokenAndTimestamp(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m)
	if err := r.RememberMe(); err != nil {
		t.Fatalf("RememberMe: %v", err)
	}
	if m.attrs[AttrRememberToken] == nil || m.attrs[AttrRememberToken] == "" {
		t.Fatal("remember_token should be set")
	}
	if _, ok := m.attrs[AttrRememberCreatedAt].(time.Time); !ok {
		t.Fatal("remember_created_at should be stamped")
	}
}

func TestRememberMeKeepsExisting(t *testing.T) {
	created := baseTime.Add(-time.Hour)
	m := newModel(AttrRememberToken, "existing", AttrRememberCreatedAt, created)
	r := New(testConfig(), m)
	if err := r.RememberMe(); err != nil {
		t.Fatalf("RememberMe: %v", err)
	}
	if m.attrs[AttrRememberToken] != "existing" {
		t.Fatal("an existing remember_token should be kept")
	}
	if m.attrs[AttrRememberCreatedAt] != created {
		t.Fatal("an existing remember_created_at should be kept")
	}
}

func TestRememberMeTokenRetry(t *testing.T) {
	cfg := testConfig()
	cfg.Finder = countingTrueFinder(1) // one token collision then free
	if err := New(cfg, newModel()).RememberMe(); err != nil {
		t.Fatalf("RememberMe: %v", err)
	}
}

func TestForgetMe(t *testing.T) {
	m := newModel(AttrRememberToken, "t", AttrRememberCreatedAt, baseTime)
	r := New(testConfig(), m) // ExpireAll default true
	if err := r.ForgetMe(); err != nil {
		t.Fatalf("ForgetMe: %v", err)
	}
	if m.attrs[AttrRememberToken] != nil {
		t.Fatal("remember_token should be cleared")
	}
	if m.attrs[AttrRememberCreatedAt] != nil {
		t.Fatal("remember_created_at should be cleared when expire-all is set")
	}
}

func TestForgetMeKeepsTimestamp(t *testing.T) {
	cfg := testConfig()
	cfg.ExpireAllRememberMeOnSignOut = false
	m := newModel(AttrRememberToken, "t", AttrRememberCreatedAt, baseTime)
	if err := New(cfg, m).ForgetMe(); err != nil {
		t.Fatalf("ForgetMe: %v", err)
	}
	if m.attrs[AttrRememberCreatedAt] != baseTime {
		t.Fatal("remember_created_at should be kept when expire-all is off")
	}
}

func TestRememberableValue(t *testing.T) {
	// With a token, it's the token.
	withTok := New(testConfig(), newModel(AttrRememberToken, "tok"))
	if withTok.RememberableValue() != "tok" {
		t.Fatal("value should be the remember_token when present")
	}
	// Without, it's the authenticatable salt.
	r := New(testConfig(), newModel())
	if err := r.SetPassword("pw12345"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if r.RememberableValue() != r.AuthenticatableSalt() {
		t.Fatal("value should fall back to the authenticatable salt")
	}
}

func TestRememberExpired(t *testing.T) {
	cfg := testConfig() // remember_for = 2 weeks, now = baseTime

	if !New(cfg, newModel()).RememberExpired() {
		t.Fatal("no created-at should be expired")
	}
	fresh := New(cfg, newModel(AttrRememberCreatedAt, baseTime.Add(-time.Hour)))
	if fresh.RememberExpired() {
		t.Fatal("a one-hour-old cookie should not be expired")
	}
	old := New(cfg, newModel(AttrRememberCreatedAt, baseTime.Add(-30*24*time.Hour)))
	if !old.RememberExpired() {
		t.Fatal("a 30-day-old cookie should be expired")
	}
}

func TestSerializeIntoCookie(t *testing.T) {
	got := SerializeIntoCookie("7", "val", "1700000000")
	if len(got) != 3 || got[0] != "7" || got[1] != "val" || got[2] != "1700000000" {
		t.Fatalf("unexpected cookie payload %v", got)
	}
}

func TestSerializeFromCookie(t *testing.T) {
	cfg := testConfig()
	m := newModel("id", "7", AttrRememberToken, "tok", AttrRememberCreatedAt, baseTime.Add(-time.Hour))
	cfg.Finder = tableFinder(m)

	r, err := cfg.SerializeFromCookie("7", "tok")
	if err != nil {
		t.Fatalf("SerializeFromCookie: %v", err)
	}
	if r.Model() != m {
		t.Fatal("should return the matched record")
	}
}

func TestSerializeFromCookieNotFound(t *testing.T) {
	cfg := testConfig() // no finder
	if _, err := cfg.SerializeFromCookie("7", "tok"); !errors.Is(err, ErrRememberCookieInvalid) {
		t.Fatalf("expected invalid-cookie, got %v", err)
	}
}

func TestSerializeFromCookieMismatch(t *testing.T) {
	cfg := testConfig()
	m := newModel("id", "7", AttrRememberToken, "tok", AttrRememberCreatedAt, baseTime.Add(-time.Hour))
	cfg.Finder = tableFinder(m)
	if _, err := cfg.SerializeFromCookie("7", "WRONG"); !errors.Is(err, ErrRememberCookieInvalid) {
		t.Fatalf("expected invalid-cookie on value mismatch, got %v", err)
	}
}

func TestSerializeFromCookieExpired(t *testing.T) {
	cfg := testConfig()
	m := newModel("id", "7", AttrRememberToken, "tok", AttrRememberCreatedAt, baseTime.Add(-60*24*time.Hour))
	cfg.Finder = tableFinder(m)
	if _, err := cfg.SerializeFromCookie("7", "tok"); !errors.Is(err, ErrRememberCookieInvalid) {
		t.Fatalf("expected invalid-cookie on expiry, got %v", err)
	}
}

func TestEncodeDecodeCookie(t *testing.T) {
	enc := EncodeCookie([]string{"7", "tok", "123"})
	if enc != "7/tok/123" {
		t.Fatalf("EncodeCookie = %q", enc)
	}
	dec := DecodeCookie(enc)
	if len(dec) != 3 || dec[0] != "7" {
		t.Fatalf("DecodeCookie = %v", dec)
	}
}
