// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"testing"
	"time"
)

func TestUpdateTrackedFieldsFirstSignIn(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m)
	r.UpdateTrackedFields("10.0.0.1")

	if m.attrs[AttrCurrentSignInAt] != baseTime {
		t.Fatal("current_sign_in_at should be now")
	}
	// On the first sign-in, last seeds from current/now and IP from remote.
	if m.attrs[AttrLastSignInAt] != baseTime {
		t.Fatal("last_sign_in_at should seed from now on first sign-in")
	}
	if m.attrs[AttrCurrentSignInIP] != "10.0.0.1" || m.attrs[AttrLastSignInIP] != "10.0.0.1" {
		t.Fatal("IP fields should seed from the remote IP")
	}
	if m.attrs[AttrSignInCount] != 1 {
		t.Fatalf("sign_in_count = %v, want 1", m.attrs[AttrSignInCount])
	}
}

func TestUpdateTrackedFieldsSubsequent(t *testing.T) {
	prev := baseTime.Add(-24 * time.Hour)
	m := newModel(
		AttrCurrentSignInAt, prev,
		AttrCurrentSignInIP, "1.1.1.1",
		AttrSignInCount, 4,
	)
	r := New(testConfig(), m)
	r.UpdateTrackedFields("2.2.2.2")

	if m.attrs[AttrLastSignInAt] != prev {
		t.Fatal("last_sign_in_at should take the previous current value")
	}
	if m.attrs[AttrCurrentSignInAt] != baseTime {
		t.Fatal("current_sign_in_at should advance to now")
	}
	if m.attrs[AttrLastSignInIP] != "1.1.1.1" || m.attrs[AttrCurrentSignInIP] != "2.2.2.2" {
		t.Fatal("IP fields should shift current->last and record the new remote")
	}
	if m.attrs[AttrSignInCount] != 5 {
		t.Fatalf("sign_in_count = %v, want 5", m.attrs[AttrSignInCount])
	}
}

func TestUpdateTrackedFieldsAndSave(t *testing.T) {
	m := newModel()
	r := New(testConfig(), m)
	if err := r.UpdateTrackedFieldsAndSave("10.0.0.1"); err != nil {
		t.Fatalf("UpdateTrackedFieldsAndSave: %v", err)
	}
	if m.saves != 1 {
		t.Fatalf("saves = %d, want 1", m.saves)
	}
	if r.SignInCount() != 1 {
		t.Fatalf("SignInCount = %d, want 1", r.SignInCount())
	}
}
