// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

// --- Validatable module ---
//
// Ports Devise::Models::Validatable's validations: email presence, format and
// uniqueness, and password presence, length and confirmation.

// ValidationError is a single validation failure, mirroring an entry Devise adds
// to the record's errors: the offending attribute and a symbolic reason matching
// ActiveModel's error keys (:blank, :invalid, :taken, :too_short, :too_long,
// :confirmation).
type ValidationError struct {
	Attribute string
	Reason    string
}

// ValidateParams carries the transient attributes Validatable needs that are not
// database columns: the plaintext password, its confirmation, and whether either
// the email or the password is being changed on this save. Devise reads these
// from the model (password / password_confirmation virtual attributes and the
// will_save_change_to_* dirty-tracking predicates); the host supplies them here.
type ValidateParams struct {
	// Password / PasswordConfirmation are the virtual password attributes.
	Password             string
	PasswordConfirmation string
	// PasswordProvided reports whether a password was set on this save
	// (Devise's password_required? core: !persisted? || password present).
	PasswordProvided bool
	// EmailChanged reports whether email is being created or modified, gating
	// the format and uniqueness checks (will_save_change_to_email?).
	EmailChanged bool
}

// ValidatableErrors runs Devise's Validatable checks against the record and the
// transient params, returning every failure in declaration order (empty when
// valid). Uniqueness is resolved through the [Config.Finder] seam: an email is
// "taken" when the finder returns a record whose id differs from this one — but
// because the model seam has no identity concept, any finder match on a
// different Model pointer counts as taken.
func (r *Record) ValidatableErrors(p ValidateParams) []ValidationError {
	var errs []ValidationError
	email := r.getString(AttrEmail)

	// validates_presence_of :email
	if email == "" {
		errs = append(errs, ValidationError{AttrEmail, "blank"})
	}

	// validates_format_of / validates_uniqueness_of :email, allow_blank: true,
	// if: will_save_change_to_email?
	if p.EmailChanged && email != "" {
		if r.cfg.EmailRegexp != nil && !r.cfg.EmailRegexp.MatchString(email) {
			errs = append(errs, ValidationError{AttrEmail, "invalid"})
		}
		if r.emailTaken(email) {
			errs = append(errs, ValidationError{AttrEmail, "taken"})
		}
	}

	// validates_presence_of :password, if: password_required?
	if p.PasswordProvided {
		if p.Password == "" {
			errs = append(errs, ValidationError{"password", "blank"})
		}
		// validates_confirmation_of :password
		if p.Password != p.PasswordConfirmation {
			errs = append(errs, ValidationError{"password", "confirmation"})
		}
	}

	// validates_length_of :password, within: password_length, allow_blank: true
	if p.Password != "" {
		switch n := len([]rune(p.Password)); {
		case n < r.cfg.PasswordLengthMin:
			errs = append(errs, ValidationError{"password", "too_short"})
		case n > r.cfg.PasswordLengthMax:
			errs = append(errs, ValidationError{"password", "too_long"})
		}
	}

	return errs
}

// emailTaken reports whether another record already owns email, via the finder.
func (r *Record) emailTaken(email string) bool {
	found, ok := r.cfg.find(map[string]any{AttrEmail: email})
	return ok && found != r.m
}
