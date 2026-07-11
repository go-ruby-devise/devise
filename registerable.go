// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "errors"

// --- Registerable module ---
//
// Ports Devise::Models::Registerable together with the registration-flow methods
// Devise defines on DatabaseAuthenticatable (update_with_password,
// update_without_password, destroy_with_password). Registerable itself is almost
// empty at the model level — its class method new_with_session and the "sign up
// / edit registration" logic live here as framework-agnostic model logic; the
// controller, routes and views that drive them are the host's job (see the
// package Scope note).

// ErrNotDestroyable is returned by [Record.DestroyWithPassword] when the
// underlying [Model] does not implement [Destroyer], i.e. cannot delete itself.
var ErrNotDestroyable = errors.New("devise: model is not a Destroyer")

// Destroyer is the optional [Model] capability a record needs to delete itself,
// mirroring ActiveRecord#destroy. [Record.DestroyWithPassword] requires it; a
// binding wires it to the ORM's delete, tests to an in-memory tombstone.
type Destroyer interface {
	Destroy() error
}

// UpdateParams carries a registration edit, mirroring the params hash Devise's
// update_with_password / update_without_password receive. Attributes are the
// non-password column changes to assign; Password / PasswordConfirmation are the
// virtual password fields; CurrentPassword is the user's existing password,
// verified by [Record.UpdateWithPassword].
type UpdateParams struct {
	Attributes           map[string]any
	Password             string
	PasswordConfirmation string
	CurrentPassword      string
}

// NewWithSession initialises a resource from sign-up params, faithful to
// Registerable.new_with_session: by default it discards the session and assigns
// the params onto the model, returning the bound [Record]. An OAuth binding
// overrides the discard to seed attributes from the session.
func NewWithSession(cfg *Config, m Model, params map[string]any, _ map[string]any) *Record {
	r := New(cfg, m)
	for k, v := range params {
		m.Set(k, v)
	}
	return r
}

// UpdateWithPassword edits the record only when currentPassword matches, faithful
// to update_with_password. It first drops a blank password (and its blank
// confirmation) so a user may change their email without touching their password.
// When the current password verifies it assigns the attributes, stages any new
// password, validates and saves; otherwise it still assigns and validates the
// attributes (to surface their errors) and adds a current_password error
// ("blank" when currentPassword is empty, else "invalid"). It returns the
// validation failures (empty on success) and a separate error for a save/hash
// infrastructure failure.
func (r *Record) UpdateWithPassword(p UpdateParams) ([]ValidationError, error) {
	// A blank password is dropped so the user can change other attributes (their
	// email, say) without touching it; a lone non-blank confirmation still forces
	// a confirmation check (password_required?), matching update_with_password's
	// "delete password if blank; delete confirmation too if it is also blank".
	passwordProvided := p.Password != "" || p.PasswordConfirmation != ""

	if r.ValidPassword(p.CurrentPassword) {
		return r.applyUpdate(p, passwordProvided, true)
	}

	// Wrong / blank current password: assign + validate but never persist.
	errs, err := r.applyUpdate(p, passwordProvided, false)
	if err != nil {
		return errs, err
	}
	reason := "invalid"
	if p.CurrentPassword == "" {
		reason = "blank"
	}
	return append(errs, ValidationError{"current_password", reason}), nil
}

// UpdateWithoutPassword edits the record without asking for the current password,
// faithful to update_without_password: it never changes the password (both
// password fields are dropped), then assigns the remaining attributes, validates
// and saves. Returns the validation failures (empty on success) and a separate
// error for a save failure.
func (r *Record) UpdateWithoutPassword(p UpdateParams) ([]ValidationError, error) {
	p.Password = ""
	p.PasswordConfirmation = ""
	return r.applyUpdate(p, false, true)
}

// DestroyWithPassword deletes the record only when currentPassword matches,
// faithful to destroy_with_password. A blank or wrong current password yields a
// current_password validation error ("blank" / "invalid") and no deletion. On a
// match it calls the model's [Destroyer]; a model that is not a Destroyer yields
// [ErrNotDestroyable].
func (r *Record) DestroyWithPassword(currentPassword string) ([]ValidationError, error) {
	if !r.ValidPassword(currentPassword) {
		reason := "invalid"
		if currentPassword == "" {
			reason = "blank"
		}
		return []ValidationError{{"current_password", reason}}, nil
	}
	d, ok := r.m.(Destroyer)
	if !ok {
		return nil, ErrNotDestroyable
	}
	if err := d.Destroy(); err != nil {
		return nil, err
	}
	return nil, nil
}

// applyUpdate assigns the params' attributes and (when passwordProvided) the new
// password onto the model, runs the Validatable rules, and — only when persist is
// true and validation passed — saves. It is the shared core of the update flows,
// standing in for ActiveRecord's assign_attributes + valid? + (conditional)
// save.
func (r *Record) applyUpdate(p UpdateParams, passwordProvided, persist bool) ([]ValidationError, error) {
	emailChanged := false
	for k, v := range p.Attributes {
		if k == AttrEmail {
			if s, _ := v.(string); s != r.getString(AttrEmail) {
				emailChanged = true
			}
		}
		r.m.Set(k, v)
	}
	if passwordProvided {
		if err := r.SetPassword(p.Password); err != nil {
			return nil, err
		}
	}

	errs := r.ValidatableErrors(ValidateParams{
		Password:             p.Password,
		PasswordConfirmation: p.PasswordConfirmation,
		PasswordProvided:     passwordProvided,
		EmailChanged:         emailChanged,
	})
	if len(errs) > 0 {
		return errs, nil
	}
	if persist {
		if err := r.m.Save(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
