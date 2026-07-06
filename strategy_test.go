// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"testing"
	"time"

	"github.com/go-ruby-rack/rack"
	"github.com/go-ruby-warden/warden"
)

// userWithPassword builds a model with an email and a bcrypt-hashed password.
func userWithPassword(t *testing.T, cfg *Config, email, password string) *fakeModel {
	t.Helper()
	m := newModel(AttrEmail, email)
	if err := New(cfg, m).SetPassword(password); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	return m
}

func TestStrategyValid(t *testing.T) {
	s := DatabaseAuthenticatableStrategy{Cfg: testConfig()}
	if s.Valid(map[string]any{AttrEmail: "a@b.co"}, "") {
		t.Fatal("empty password should be invalid")
	}
	if s.Valid(map[string]any{}, "pw") {
		t.Fatal("missing authentication key should be invalid")
	}
	if s.Valid(map[string]any{AttrEmail: ""}, "pw") {
		t.Fatal("empty authentication key should be invalid")
	}
	if !s.Valid(map[string]any{AttrEmail: "a@b.co"}, "pw") {
		t.Fatal("a full credential set should be valid")
	}
}

func TestStrategyRunSuccess(t *testing.T) {
	cfg := testConfig()
	m := userWithPassword(t, cfg, "a@b.co", "hunter2!")
	cfg.Finder = tableFinder(m)
	s := DatabaseAuthenticatableStrategy{Cfg: cfg}

	res := s.Run(map[string]any{AttrEmail: "a@b.co"}, "hunter2!")
	if res.Result != warden.ResultSuccess || res.User != m || !res.Halted {
		t.Fatalf("expected a halting success with the user, got %+v", res)
	}
}

func TestStrategyRunInvalidStrategy(t *testing.T) {
	s := DatabaseAuthenticatableStrategy{Cfg: testConfig()}
	res := s.Run(map[string]any{}, "")
	if res.Valid {
		t.Fatal("an invalid strategy should report Valid=false")
	}
}

func TestStrategyRunNotFound(t *testing.T) {
	cfg := testConfig() // no finder
	s := DatabaseAuthenticatableStrategy{Cfg: cfg}
	res := s.Run(map[string]any{AttrEmail: "missing@b.co"}, "pw")
	if res.Result != warden.ResultFailure || res.Message != "not_found_in_database" {
		t.Fatalf("expected not_found_in_database failure, got %+v", res)
	}
}

func TestStrategyRunWrongPassword(t *testing.T) {
	cfg := testConfig()
	m := userWithPassword(t, cfg, "a@b.co", "correct-horse")
	cfg.Finder = tableFinder(m)
	s := DatabaseAuthenticatableStrategy{Cfg: cfg}

	res := s.Run(map[string]any{AttrEmail: "a@b.co"}, "wrong")
	if res.Result != warden.ResultFailure || res.Message != "invalid" {
		t.Fatalf("expected invalid failure, got %+v", res)
	}
}

func TestStrategyRunInactive(t *testing.T) {
	cfg := testConfig()
	grace := time.Hour
	cfg.AllowUnconfirmedAccessFor = &grace
	m := userWithPassword(t, cfg, "a@b.co", "hunter2!")
	m.attrs[AttrConfirmationSentAt] = baseTime.Add(-2 * time.Hour) // past the grace, unconfirmed
	cfg.Finder = tableFinder(m)
	s := DatabaseAuthenticatableStrategy{Cfg: cfg}

	res := s.Run(map[string]any{AttrEmail: "a@b.co"}, "hunter2!")
	if res.Result != warden.ResultFailure || res.Message != "unconfirmed" {
		t.Fatalf("expected unconfirmed failure, got %+v", res)
	}
}

func TestInactiveMessageInactive(t *testing.T) {
	// A confirmed record reports the generic "inactive" reason.
	r := New(testConfig(), newModel(AttrConfirmedAt, baseTime))
	if r.InactiveMessage() != "inactive" {
		t.Fatalf("InactiveMessage = %q, want inactive", r.InactiveMessage())
	}
}

func TestDatabaseStrategyRunDefaultCredentials(t *testing.T) {
	cfg := testConfig()
	m := userWithPassword(t, cfg, "a@b.co", "hunter2!")
	cfg.Finder = tableFinder(m)
	run := cfg.DatabaseStrategyRun()

	env := rack.Env{
		"devise.credentials": map[string]any{AttrEmail: "a@b.co"},
		"devise.password":    "hunter2!",
	}
	res := run(StrategyDatabaseAuthenticatable, env)
	if res.Result != warden.ResultSuccess {
		t.Fatalf("expected success through the run seam, got %+v", res)
	}
}

func TestDatabaseStrategyRunWrongName(t *testing.T) {
	run := testConfig().DatabaseStrategyRun()
	if res := run("other_strategy", rack.Env{}); res.Valid {
		t.Fatal("a non-matching strategy name should report Valid=false")
	}
}

func TestDatabaseStrategyRunCustomCredentials(t *testing.T) {
	cfg := testConfig()
	m := userWithPassword(t, cfg, "a@b.co", "hunter2!")
	cfg.Finder = tableFinder(m)
	cfg.Credentials = func(env rack.Env) (map[string]any, string) {
		return map[string]any{AttrEmail: "a@b.co"}, "hunter2!"
	}
	run := cfg.DatabaseStrategyRun()
	res := run(StrategyDatabaseAuthenticatable, rack.Env{})
	if res.Result != warden.ResultSuccess {
		t.Fatalf("custom credentials seam should authenticate, got %+v", res)
	}
}

func TestDefaultCredentials(t *testing.T) {
	env := rack.Env{
		"devise.credentials": map[string]any{AttrEmail: "a@b.co"},
		"devise.password":    "pw",
	}
	authHash, pw := defaultCredentials(env)
	if authHash[AttrEmail] != "a@b.co" || pw != "pw" {
		t.Fatalf("defaultCredentials = %v,%q", authHash, pw)
	}
	// Missing keys degrade gracefully.
	authHash, pw = defaultCredentials(rack.Env{})
	if authHash != nil || pw != "" {
		t.Fatalf("empty env should yield nil,\"\" got %v,%q", authHash, pw)
	}
}
