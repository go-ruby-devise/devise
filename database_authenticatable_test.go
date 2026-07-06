// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "testing"

func TestSetAndValidPassword(t *testing.T) {
	r := New(testConfig(), newModel())
	if err := r.SetPassword("hunter2!"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if r.getString(AttrEncryptedPassword) == "" {
		t.Fatal("SetPassword should populate encrypted_password")
	}
	if !r.ValidPassword("hunter2!") {
		t.Fatal("the set password should validate")
	}
	if r.ValidPassword("nope") {
		t.Fatal("a wrong password should not validate")
	}
}

func TestSetPasswordBlankIsNoop(t *testing.T) {
	m := newModel(AttrEncryptedPassword, "keep")
	r := New(testConfig(), m)
	if err := r.SetPassword(""); err != nil {
		t.Fatalf("SetPassword(\"\"): %v", err)
	}
	if m.attrs[AttrEncryptedPassword] != "keep" {
		t.Fatal("a blank password should leave the hash untouched")
	}
}

func TestSetPasswordDigestError(t *testing.T) {
	cfg := testConfig()
	cfg.Stretches = 99 // above bcrypt MaxCost -> Digest errors
	r := New(cfg, newModel())
	if err := r.SetPassword("pw"); err == nil {
		t.Fatal("an invalid cost should surface a Digest error")
	}
}

func TestValidPasswordNoHash(t *testing.T) {
	r := New(testConfig(), newModel())
	if r.ValidPassword("anything") {
		t.Fatal("a record without a hash should never validate")
	}
}

func TestAuthenticatableSalt(t *testing.T) {
	r := New(testConfig(), newModel())
	if r.AuthenticatableSalt() != "" {
		t.Fatal("no password -> empty salt")
	}
	if err := r.SetPassword("pw12345"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	salt := r.AuthenticatableSalt()
	if len(salt) != 29 {
		t.Fatalf("salt length = %d, want 29", len(salt))
	}
	// A short (sub-29) hash returns as-is.
	short := New(testConfig(), newModel(AttrEncryptedPassword, "abc"))
	if short.AuthenticatableSalt() != "abc" {
		t.Fatal("a short hash should return unchanged")
	}
}
