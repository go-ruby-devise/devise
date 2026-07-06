// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "testing"

func TestNewNilConfigUsesDefault(t *testing.T) {
	r := New(nil, newModel())
	if r.Config() == nil {
		t.Fatal("nil config should fall back to DefaultConfig")
	}
	if r.Config().Stretches != 12 {
		t.Fatalf("default stretches = %d, want 12", r.Config().Stretches)
	}
}

func TestRecordAccessors(t *testing.T) {
	m := newModel()
	cfg := testConfig()
	r := New(cfg, m)
	if r.Model() != m {
		t.Fatal("Model() should return the wrapped model")
	}
	if r.Config() != cfg {
		t.Fatal("Config() should return the governing config")
	}
}

func TestGetters(t *testing.T) {
	m := newModel(
		AttrEmail, "a@b.co",
		AttrFailedAttempts, 3,
		AttrLockedAt, baseTime,
	)
	r := New(testConfig(), m)

	if r.getString(AttrEmail) != "a@b.co" {
		t.Fatal("getString should read a string attr")
	}
	if r.getString(AttrFailedAttempts) != "" { // non-string -> ""
		t.Fatal("getString of a non-string attr should be empty")
	}
	if r.getInt(AttrFailedAttempts) != 3 {
		t.Fatal("getInt should read an int attr")
	}
	if r.getInt(AttrEmail) != 0 { // non-int -> 0
		t.Fatal("getInt of a non-int attr should be 0")
	}
	if ts, ok := r.getTime(AttrLockedAt); !ok || !ts.Equal(baseTime) {
		t.Fatal("getTime should read a time attr")
	}
	if _, ok := r.getTime(AttrEmail); ok { // non-time -> !ok
		t.Fatal("getTime of a non-time attr should report absent")
	}
}

func TestDefaultConfigNow(t *testing.T) {
	c := DefaultConfig()
	if c.now().IsZero() {
		t.Fatal("default clock should return a real time")
	}
	// The pinned-clock path.
	c.Now = fixedNow(baseTime)
	if !c.now().Equal(baseTime) {
		t.Fatal("config clock should honour Now")
	}
	// The nil-Now fallback path.
	if (&Config{}).now().IsZero() {
		t.Fatal("nil Now should fall back to time.Now")
	}
}

func TestConfigTokenGeneratorFallback(t *testing.T) {
	if (&Config{}).tokenGenerator() == nil {
		t.Fatal("nil TokenGenerator should fall back to a default")
	}
	c := DefaultConfig()
	if c.tokenGenerator() != c.TokenGenerator {
		t.Fatal("configured TokenGenerator should be returned as-is")
	}
}

func TestConfigFindNoFinder(t *testing.T) {
	if _, ok := (&Config{}).find(map[string]any{"x": 1}); ok {
		t.Fatal("a nil Finder should report no match")
	}
	c := &Config{Finder: tableFinder(newModel(AttrEmail, "a@b.co"))}
	if _, ok := c.find(map[string]any{AttrEmail: "a@b.co"}); !ok {
		t.Fatal("configured Finder should find a match")
	}
}

func TestDefaultEmailRegexp(t *testing.T) {
	for _, ok := range []string{"a@b.co", "x.y+z@sub.domain.io"} {
		if !DefaultEmailRegexp.MatchString(ok) {
			t.Fatalf("%q should be a valid email", ok)
		}
	}
	for _, bad := range []string{"", "no-at", "a@b c", "a b@c"} {
		if DefaultEmailRegexp.MatchString(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}
