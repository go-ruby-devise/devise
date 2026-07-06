// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"strings"
	"testing"
)

// hasErr reports whether errs contains a (attribute, reason) failure.
func hasErr(errs []ValidationError, attr, reason string) bool {
	for _, e := range errs {
		if e.Attribute == attr && e.Reason == reason {
			return true
		}
	}
	return false
}

func TestValidatableValid(t *testing.T) {
	r := New(testConfig(), newModel(AttrEmail, "a@b.co"))
	errs := r.ValidatableErrors(ValidateParams{
		Password: "hunter2", PasswordConfirmation: "hunter2",
		PasswordProvided: true, EmailChanged: true,
	})
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
}

func TestValidatableEmailBlank(t *testing.T) {
	r := New(testConfig(), newModel())
	errs := r.ValidatableErrors(ValidateParams{EmailChanged: true})
	if !hasErr(errs, AttrEmail, "blank") {
		t.Fatalf("expected email blank, got %v", errs)
	}
}

func TestValidatableEmailFormat(t *testing.T) {
	r := New(testConfig(), newModel(AttrEmail, "not-an-email"))
	errs := r.ValidatableErrors(ValidateParams{EmailChanged: true})
	if !hasErr(errs, AttrEmail, "invalid") {
		t.Fatalf("expected email invalid, got %v", errs)
	}
}

func TestValidatableEmailFormatSkippedWhenNoRegexp(t *testing.T) {
	cfg := testConfig()
	cfg.EmailRegexp = nil
	r := New(cfg, newModel(AttrEmail, "not-an-email"))
	errs := r.ValidatableErrors(ValidateParams{EmailChanged: true})
	if hasErr(errs, AttrEmail, "invalid") {
		t.Fatal("a nil regexp should skip the format check")
	}
}

func TestValidatableEmailNotCheckedWhenUnchanged(t *testing.T) {
	r := New(testConfig(), newModel(AttrEmail, "not-an-email"))
	errs := r.ValidatableErrors(ValidateParams{EmailChanged: false})
	if hasErr(errs, AttrEmail, "invalid") {
		t.Fatal("format should not be checked when email is unchanged")
	}
}

func TestValidatableEmailUniqueness(t *testing.T) {
	existing := newModel(AttrEmail, "dup@b.co")
	cfg := testConfig()
	cfg.Finder = tableFinder(existing)

	// A different record with the same email is taken.
	r := New(cfg, newModel(AttrEmail, "dup@b.co"))
	errs := r.ValidatableErrors(ValidateParams{EmailChanged: true})
	if !hasErr(errs, AttrEmail, "taken") {
		t.Fatalf("expected email taken, got %v", errs)
	}

	// The same record (its own email) is not taken.
	self := New(cfg, existing)
	errs = self.ValidatableErrors(ValidateParams{EmailChanged: true})
	if hasErr(errs, AttrEmail, "taken") {
		t.Fatal("a record should not conflict with itself")
	}

	// A fresh email is free.
	free := New(cfg, newModel(AttrEmail, "free@b.co"))
	errs = free.ValidatableErrors(ValidateParams{EmailChanged: true})
	if hasErr(errs, AttrEmail, "taken") {
		t.Fatal("an unused email should not be taken")
	}
}

func TestValidatablePasswordRules(t *testing.T) {
	r := New(testConfig(), newModel(AttrEmail, "a@b.co"))

	// Blank + mismatch.
	errs := r.ValidatableErrors(ValidateParams{PasswordProvided: true, PasswordConfirmation: "x"})
	if !hasErr(errs, "password", "blank") || !hasErr(errs, "password", "confirmation") {
		t.Fatalf("expected blank + confirmation, got %v", errs)
	}

	// Too short.
	errs = r.ValidatableErrors(ValidateParams{Password: "abc", PasswordConfirmation: "abc", PasswordProvided: true})
	if !hasErr(errs, "password", "too_short") {
		t.Fatalf("expected too_short, got %v", errs)
	}

	// Too long.
	long := strings.Repeat("a", 200)
	errs = r.ValidatableErrors(ValidateParams{Password: long, PasswordConfirmation: long, PasswordProvided: true})
	if !hasErr(errs, "password", "too_long") {
		t.Fatalf("expected too_long, got %v", errs)
	}
}

func TestValidatablePasswordNotProvided(t *testing.T) {
	// When a password is not being set, its presence/confirmation are not
	// checked, but a supplied (virtual) password is still length-checked.
	r := New(testConfig(), newModel(AttrEmail, "a@b.co"))
	errs := r.ValidatableErrors(ValidateParams{Password: "abc", PasswordProvided: false})
	if hasErr(errs, "password", "blank") || hasErr(errs, "password", "confirmation") {
		t.Fatal("presence/confirmation should be skipped when password not provided")
	}
	if !hasErr(errs, "password", "too_short") {
		t.Fatal("length is still enforced on a non-blank password")
	}
}
