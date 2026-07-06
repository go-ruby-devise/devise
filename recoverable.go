// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "errors"

// --- Recoverable module ---
//
// Ports Devise::Models::Recoverable: reset-password token issuance and
// consumption.

// Recoverable error reasons, mirroring the symbolic errors Devise adds to
// reset_password_token / password.
var (
	// ErrResetTokenNotFound is returned when no record matches the reset token
	// (Devise adds :not_found on the token, or :invalid).
	ErrResetTokenNotFound = errors.New("devise: reset password token not found")
	// ErrResetTokenExpired is returned when the token is past
	// reset_password_within (Devise adds :expired).
	ErrResetTokenExpired = errors.New("devise: reset password token expired")
)

// SetResetPasswordToken mints a reset token, faithful to
// set_reset_password_token: it generates a (raw, enc) pair via the token
// generator (unique against reset_password_token through the finder), stores the
// enc digest and the send timestamp, saves without validation, and returns the
// raw token to be mailed.
func (r *Record) SetResetPasswordToken() (string, error) {
	gen := r.cfg.tokenGenerator()
	raw, enc := gen.Generate(AttrResetPasswordToken, func(digest string) bool {
		_, ok := r.cfg.find(map[string]any{AttrResetPasswordToken: digest})
		return ok
	})
	r.m.Set(AttrResetPasswordToken, enc)
	r.m.Set(AttrResetPasswordSentAt, r.cfg.now())
	if err := r.m.Save(); err != nil {
		return "", err
	}
	return raw, nil
}

// SendResetPasswordInstructions mints a reset token and invokes the configured
// mailer callback, faithful to send_reset_password_instructions. It returns the
// raw token (Devise returns it too, for tests).
func (r *Record) SendResetPasswordInstructions() (string, error) {
	raw, err := r.SetResetPasswordToken()
	if err != nil {
		return "", err
	}
	if r.cfg.SendResetPasswordInstructions != nil {
		r.cfg.SendResetPasswordInstructions(r, raw)
	}
	return raw, nil
}

// ResetPasswordPeriodValid reports whether the stored reset token is still
// within reset_password_within, faithful to reset_password_period_valid?: false
// when no token was ever sent.
func (r *Record) ResetPasswordPeriodValid() bool {
	sentAt, ok := r.getTime(AttrResetPasswordSentAt)
	if !ok {
		return false
	}
	return sentAt.After(r.cfg.now().Add(-r.cfg.ResetPasswordWithin))
}

// ResetPassword sets a new password and clears the reset token, faithful to
// reset_password: it stages the hashed password, clears reset_password_token,
// and saves. It does not itself check the confirmation or period — the class
// method [Config.ResetPasswordByToken] orchestrates those, mirroring Devise.
func (r *Record) ResetPassword(newPassword string) error {
	if err := r.SetPassword(newPassword); err != nil {
		return err
	}
	r.m.Set(AttrResetPasswordToken, nil)
	return r.m.Save()
}

// ResetPasswordByToken is the class-level reset flow, faithful to
// reset_password_by_token: it digests the raw token, finds the record, checks
// the token has not expired, and resets the password. It returns the updated
// record, or an error ([ErrResetTokenNotFound] / [ErrResetTokenExpired]) plus
// any validation failures from the password rules.
func (c *Config) ResetPasswordByToken(rawToken, newPassword, newPasswordConfirmation string) (*Record, error) {
	enc := c.tokenGenerator().Digest(AttrResetPasswordToken, rawToken)
	m, ok := c.find(map[string]any{AttrResetPasswordToken: enc})
	if !ok {
		return nil, ErrResetTokenNotFound
	}
	r := New(c, m)
	if !r.ResetPasswordPeriodValid() {
		return r, ErrResetTokenExpired
	}
	if newPassword != newPasswordConfirmation {
		return r, ValidationError{"password", "confirmation"}
	}
	if err := r.ResetPassword(newPassword); err != nil {
		return r, err
	}
	return r, nil
}

// Error makes [ValidationError] usable as an error, so ResetPasswordByToken can
// surface a confirmation mismatch through the error return.
func (e ValidationError) Error() string {
	return "devise: " + e.Attribute + " " + e.Reason
}
