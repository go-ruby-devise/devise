// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "errors"

// --- Confirmable module ---
//
// Ports Devise::Models::Confirmable: email confirmation token issuance,
// confirmation, and the access grace/expiry windows.

// Confirmable error reasons.
var (
	// ErrAlreadyConfirmed is returned by Confirm when the record is already
	// confirmed (Devise adds :already_confirmed on email).
	ErrAlreadyConfirmed = errors.New("devise: already confirmed")
	// ErrConfirmationPeriodExpired is returned by Confirm when the token is past
	// confirm_within (Devise adds :confirmation_period_expired on email).
	ErrConfirmationPeriodExpired = errors.New("devise: confirmation period expired")
	// ErrConfirmationTokenNotFound is returned by ConfirmByToken when no record
	// matches the token.
	ErrConfirmationTokenNotFound = errors.New("devise: confirmation token not found")
)

// GenerateConfirmationToken mints a confirmation token, faithful to
// generate_confirmation_token: it generates a (raw, enc) pair (unique via the
// finder), stores the enc digest and confirmation_sent_at, and returns the raw
// token. It does not save (Devise stages it before the record is persisted).
func (r *Record) GenerateConfirmationToken() string {
	gen := r.cfg.tokenGenerator()
	raw, enc := gen.Generate(AttrConfirmationToken, func(digest string) bool {
		_, ok := r.cfg.find(map[string]any{AttrConfirmationToken: digest})
		return ok
	})
	r.m.Set(AttrConfirmationToken, enc)
	r.m.Set(AttrConfirmationSentAt, r.cfg.now())
	return raw
}

// SendConfirmationInstructions mints a token, saves it, and invokes the mailer
// callback, faithful to send_confirmation_instructions. It returns the raw
// token.
func (r *Record) SendConfirmationInstructions() (string, error) {
	raw := r.GenerateConfirmationToken()
	if err := r.m.Save(); err != nil {
		return "", err
	}
	if r.cfg.SendConfirmationInstructions != nil {
		r.cfg.SendConfirmationInstructions(r, raw)
	}
	return raw, nil
}

// Confirmed reports whether the record has been confirmed, faithful to
// confirmed?: confirmed_at is set.
func (r *Record) Confirmed() bool {
	_, ok := r.getTime(AttrConfirmedAt)
	return ok
}

// Confirm marks the record confirmed, faithful to confirm: it fails with
// [ErrAlreadyConfirmed] when already confirmed and [ErrConfirmationPeriodExpired]
// when the token has expired, otherwise sets confirmed_at, clears
// confirmation_token, and saves.
func (r *Record) Confirm() error {
	if r.Confirmed() {
		return ErrAlreadyConfirmed
	}
	if r.ConfirmationPeriodExpired() {
		return ErrConfirmationPeriodExpired
	}
	r.m.Set(AttrConfirmedAt, r.cfg.now())
	r.m.Set(AttrConfirmationToken, nil)
	return r.m.Save()
}

// ConfirmationPeriodValid reports whether the record may still access resources
// while unconfirmed, faithful to confirmation_period_valid?: true when
// allow_unconfirmed_access_for is nil (unlimited), else confirmation_sent_at is
// within that window.
func (r *Record) ConfirmationPeriodValid() bool {
	if r.cfg.AllowUnconfirmedAccessFor == nil {
		return true
	}
	sentAt, ok := r.getTime(AttrConfirmationSentAt)
	if !ok {
		return false
	}
	return sentAt.After(r.cfg.now().Add(-*r.cfg.AllowUnconfirmedAccessFor))
}

// ConfirmationPeriodExpired reports whether the confirmation token has expired,
// faithful to confirmation_period_expired?: only when confirm_within is set and
// confirmation_sent_at is older than it.
func (r *Record) ConfirmationPeriodExpired() bool {
	if r.cfg.ConfirmWithin == nil {
		return false
	}
	sentAt, ok := r.getTime(AttrConfirmationSentAt)
	if !ok {
		return false
	}
	return r.cfg.now().After(sentAt.Add(*r.cfg.ConfirmWithin))
}

// ActiveForAuthentication reports whether an unconfirmed record may still sign
// in, faithful to Confirmable#active_for_authentication?: confirmed records are
// always active; unconfirmed ones are active only while
// [ConfirmationPeriodValid].
func (r *Record) ActiveForAuthentication() bool {
	return r.Confirmed() || r.ConfirmationPeriodValid()
}

// ConfirmByToken is the class-level confirmation flow, faithful to
// confirm_by_token: it digests the raw token, finds the record, and confirms it.
func (c *Config) ConfirmByToken(rawToken string) (*Record, error) {
	enc := c.tokenGenerator().Digest(AttrConfirmationToken, rawToken)
	m, ok := c.find(map[string]any{AttrConfirmationToken: enc})
	if !ok {
		return nil, ErrConfirmationTokenNotFound
	}
	r := New(c, m)
	if err := r.Confirm(); err != nil {
		return r, err
	}
	return r, nil
}
