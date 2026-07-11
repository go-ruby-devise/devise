// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "testing"

// destroyableModel is a fakeModel that can delete itself, for the
// DestroyWithPassword tests. destroyErr, when set, makes Destroy fail.
type destroyableModel struct {
	*fakeModel
	destroyed  bool
	destroyErr error
}

func newDestroyable(kv ...any) *destroyableModel {
	return &destroyableModel{fakeModel: newModel(kv...)}
}

func (m *destroyableModel) Destroy() error {
	if m.destroyErr != nil {
		return m.destroyErr
	}
	m.destroyed = true
	return nil
}

// withPassword returns a Record whose stored hash is for "current!!" plus a
// finder that sees the record itself (so uniqueness passes).
func withPassword(t *testing.T, cfg *Config, m *fakeModel) *Record {
	t.Helper()
	r := New(cfg, m)
	if err := r.SetPassword("current!!"); err != nil {
		t.Fatalf("seed SetPassword: %v", err)
	}
	return r
}

func TestNewWithSession(t *testing.T) {
	m := newModel()
	r := NewWithSession(testConfig(), m, map[string]any{AttrEmail: "a@b.co"}, map[string]any{"ignored": 1})
	if r.getString(AttrEmail) != "a@b.co" {
		t.Fatal("NewWithSession should assign the params onto the model")
	}
}

func TestUpdateWithPasswordCorrect(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	saved := m.saves
	errs, err := r.UpdateWithPassword(UpdateParams{
		Attributes:      map[string]any{AttrEmail: "new@b.co"},
		CurrentPassword: "current!!",
	})
	if err != nil || len(errs) != 0 {
		t.Fatalf("valid update: errs=%v err=%v", errs, err)
	}
	if m.attrs[AttrEmail] != "new@b.co" {
		t.Fatal("email should have been assigned")
	}
	if m.saves != saved+1 {
		t.Fatal("a successful update should save exactly once")
	}
}

func TestUpdateWithPasswordChangesPassword(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	errs, err := r.UpdateWithPassword(UpdateParams{
		Password:             "brandnew1",
		PasswordConfirmation: "brandnew1",
		CurrentPassword:      "current!!",
	})
	if err != nil || len(errs) != 0 {
		t.Fatalf("password change: errs=%v err=%v", errs, err)
	}
	if !r.ValidPassword("brandnew1") {
		t.Fatal("the new password should now validate")
	}
}

func TestUpdateWithPasswordWrongCurrent(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	saved := m.saves
	errs, err := r.UpdateWithPassword(UpdateParams{
		Attributes:      map[string]any{AttrEmail: "new@b.co"},
		CurrentPassword: "wrong",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !hasErr(errs, "current_password", "invalid") {
		t.Fatalf("want current_password invalid, got %v", errs)
	}
	if m.saves != saved {
		t.Fatal("a rejected update must not save")
	}
}

func TestUpdateWithPasswordBlankCurrent(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	errs, _ := r.UpdateWithPassword(UpdateParams{
		Attributes:      map[string]any{AttrEmail: "new@b.co"},
		CurrentPassword: "",
	})
	if !hasErr(errs, "current_password", "blank") {
		t.Fatalf("want current_password blank, got %v", errs)
	}
}

func TestUpdateWithPasswordBlankPasswordDropped(t *testing.T) {
	// A blank password with a matching current password changes only the email.
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	hashBefore := m.attrs[AttrEncryptedPassword]
	errs, err := r.UpdateWithPassword(UpdateParams{
		Attributes:      map[string]any{AttrEmail: "new@b.co"},
		Password:        "",
		CurrentPassword: "current!!",
	})
	if err != nil || len(errs) != 0 {
		t.Fatalf("email-only update: errs=%v err=%v", errs, err)
	}
	if m.attrs[AttrEncryptedPassword] != hashBefore {
		t.Fatal("a blank password must leave the hash untouched")
	}
}

func TestUpdateWithPasswordTooShort(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	errs, _ := r.UpdateWithPassword(UpdateParams{
		Password:             "x",
		PasswordConfirmation: "x",
		CurrentPassword:      "current!!",
	})
	if !hasErr(errs, "password", "too_short") {
		t.Fatalf("want password too_short, got %v", errs)
	}
}

func TestUpdateWithPasswordHashError(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	cfg.Stretches = 99 // above bcrypt MaxCost -> SetPassword errors
	if _, err := r.UpdateWithPassword(UpdateParams{
		Password:        "brandnew1",
		CurrentPassword: "current!!",
	}); err == nil {
		t.Fatal("an invalid cost should surface a hash error")
	}
}

func TestUpdateWithPasswordWrongCurrentHashError(t *testing.T) {
	// A hash failure while assigning the new password surfaces even on the
	// wrong-current-password (non-persisting) branch.
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := withPassword(t, cfg, m)
	cfg.Stretches = 99 // above bcrypt MaxCost -> SetPassword errors
	if _, err := r.UpdateWithPassword(UpdateParams{
		Password:        "brandnew1",
		CurrentPassword: "wrong",
	}); err == nil {
		t.Fatal("a hash error should surface even when the current password is wrong")
	}
}

func TestUpdateWithoutPassword(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co", AttrEncryptedPassword, "keep-hash")
	cfg.Finder = tableFinder(m)
	r := New(cfg, m)
	errs, err := r.UpdateWithoutPassword(UpdateParams{
		Attributes:           map[string]any{AttrEmail: "new@b.co"},
		Password:             "ignored99", // must be dropped, never applied
		PasswordConfirmation: "ignored99",
	})
	if err != nil || len(errs) != 0 {
		t.Fatalf("update without password: errs=%v err=%v", errs, err)
	}
	if m.attrs[AttrEmail] != "new@b.co" {
		t.Fatal("email should have changed")
	}
	if m.attrs[AttrEncryptedPassword] != "keep-hash" {
		t.Fatal("the password must never change without a password")
	}
}

func TestUpdateWithoutPasswordInvalidEmail(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	cfg.Finder = tableFinder(m)
	r := New(cfg, m)
	errs, _ := r.UpdateWithoutPassword(UpdateParams{
		Attributes: map[string]any{AttrEmail: "not-an-email"},
	})
	if !hasErr(errs, AttrEmail, "invalid") {
		t.Fatalf("want email invalid, got %v", errs)
	}
}

func TestUpdateWithoutPasswordSaveError(t *testing.T) {
	cfg := testConfig()
	m := newModel(AttrEmail, "old@b.co")
	m.saveErr = errSave
	cfg.Finder = tableFinder(m)
	r := New(cfg, m)
	if _, err := r.UpdateWithoutPassword(UpdateParams{
		Attributes: map[string]any{AttrEmail: "new@b.co"},
	}); err != errSave {
		t.Fatalf("save error should propagate, got %v", err)
	}
}

func TestDestroyWithPasswordCorrect(t *testing.T) {
	cfg := testConfig()
	m := newDestroyable()
	r := withPassword(t, cfg, m.fakeModel)
	r = New(cfg, m) // rebind to the destroyable so ValidPassword sees the seeded hash
	errs, err := r.DestroyWithPassword("current!!")
	if err != nil || len(errs) != 0 {
		t.Fatalf("destroy: errs=%v err=%v", errs, err)
	}
	if !m.destroyed {
		t.Fatal("a correct password should destroy the record")
	}
}

func TestDestroyWithPasswordWrong(t *testing.T) {
	cfg := testConfig()
	m := newDestroyable()
	_ = withPassword(t, cfg, m.fakeModel)
	r := New(cfg, m)
	errs, _ := r.DestroyWithPassword("nope")
	if !hasErr(errs, "current_password", "invalid") {
		t.Fatalf("want current_password invalid, got %v", errs)
	}
	if m.destroyed {
		t.Fatal("a wrong password must not destroy")
	}
}

func TestDestroyWithPasswordBlank(t *testing.T) {
	cfg := testConfig()
	m := newDestroyable()
	_ = withPassword(t, cfg, m.fakeModel)
	r := New(cfg, m)
	errs, _ := r.DestroyWithPassword("")
	if !hasErr(errs, "current_password", "blank") {
		t.Fatalf("want current_password blank, got %v", errs)
	}
}

func TestDestroyWithPasswordNotDestroyable(t *testing.T) {
	cfg := testConfig()
	m := newModel()
	r := withPassword(t, cfg, m)
	if _, err := r.DestroyWithPassword("current!!"); err != ErrNotDestroyable {
		t.Fatalf("a non-Destroyer model should yield ErrNotDestroyable, got %v", err)
	}
}

func TestDestroyWithPasswordDestroyError(t *testing.T) {
	cfg := testConfig()
	m := newDestroyable()
	m.destroyErr = errSave
	_ = withPassword(t, cfg, m.fakeModel)
	r := New(cfg, m)
	if _, err := r.DestroyWithPassword("current!!"); err != errSave {
		t.Fatalf("a destroy failure should propagate, got %v", err)
	}
}
