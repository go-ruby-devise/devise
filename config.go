// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"regexp"
	"time"

	"github.com/go-ruby-bcrypt/bcrypt"
)

// UnlockStrategy selects how a locked account may be unlocked, mirroring
// Devise.unlock_strategy.
type UnlockStrategy string

const (
	// UnlockTime unlocks automatically after Config.UnlockIn elapses.
	UnlockTime UnlockStrategy = "time"
	// UnlockEmail unlocks via an emailed unlock token.
	UnlockEmail UnlockStrategy = "email"
	// UnlockBoth enables both time and email unlocking (Devise's default).
	UnlockBoth UnlockStrategy = "both"
	// UnlockNone disables automatic unlocking.
	UnlockNone UnlockStrategy = "none"
)

// LockStrategy selects what triggers a lock, mirroring Devise.lock_strategy.
type LockStrategy string

const (
	// LockFailedAttempts locks after too many failed sign-ins (Devise's default).
	LockFailedAttempts LockStrategy = "failed_attempts"
	// LockNone disables automatic locking (locks only via lock_access!).
	LockNone LockStrategy = "none"
)

// Config carries the per-resource Devise settings (the knobs Devise exposes via
// the initializer and per-model devise :... declarations) together with the
// injectable seams a pure-Go core needs: the record lookup [Finder], the
// [TokenGenerator], and a clock. Build one with [DefaultConfig] and override
// fields, mirroring how a Rails app tweaks config.to_prepare / model options.
type Config struct {
	// --- Encryption (Database Authenticatable) ---

	// Stretches is the bcrypt cost (Devise.stretches). Devise defaults to 12,
	// and to 1 in the test environment.
	Stretches int
	// Pepper is appended to passwords before hashing (Devise.pepper). Empty
	// means no pepper.
	Pepper string

	// --- Validatable ---

	// EmailRegexp validates email format (Devise.email_regexp).
	EmailRegexp *regexp.Regexp
	// PasswordLengthMin / PasswordLengthMax bound password length
	// (Devise.password_length, default 6..128).
	PasswordLengthMin int
	PasswordLengthMax int

	// --- Recoverable ---

	// ResetPasswordWithin is how long a reset token stays valid
	// (Devise.reset_password_within, default 6 hours).
	ResetPasswordWithin time.Duration

	// --- Rememberable ---

	// RememberFor is how long a remember-me cookie lasts (Devise.remember_for,
	// default 2 weeks).
	RememberFor time.Duration
	// ExpireAllRememberMeOnSignOut clears remember_created_at on sign-out
	// (Devise.expire_all_remember_me_on_sign_out, default true).
	ExpireAllRememberMeOnSignOut bool

	// --- Confirmable ---

	// AllowUnconfirmedAccessFor is the grace window during which an unconfirmed
	// account may still sign in (Devise.allow_unconfirmed_access_for). A nil
	// pointer means "unlimited" (never expires); a zero duration means no grace.
	AllowUnconfirmedAccessFor *time.Duration
	// ConfirmWithin is how long a confirmation token stays valid
	// (Devise.confirm_within). A nil pointer means tokens never expire.
	ConfirmWithin *time.Duration

	// --- Lockable ---

	// MaximumAttempts is the failed-attempt threshold that triggers a lock
	// (Devise.maximum_attempts, default 20).
	MaximumAttempts int
	// UnlockIn is the auto-unlock window for the time strategy
	// (Devise.unlock_in, default 1 hour).
	UnlockIn time.Duration
	// UnlockStrategy and LockStrategy select the lock/unlock behaviour.
	UnlockStrategy UnlockStrategy
	LockStrategy   LockStrategy

	// --- Timeoutable ---

	// TimeoutIn is the idle window after which a session times out
	// (Devise.timeout_in). A nil pointer disables timeout.
	TimeoutIn *time.Duration

	// --- Authentication ---

	// AuthenticationKeys are the columns used to find a record for
	// authentication (Devise.authentication_keys, default ["email"]).
	AuthenticationKeys []string
	// FriendlyTokenLength is the default length of a [FriendlyToken]
	// (Devise's friendly_token default is 20).
	FriendlyTokenLength int

	// --- Seams ---

	// Finder performs class-level record lookups. Required by uniqueness
	// validation, reset-by-token, remember-cookie deserialisation and the
	// database strategy; a nil Finder makes those treat "no match" as the
	// result.
	Finder Finder
	// TokenGenerator produces and digests the raw tokens Recoverable and
	// Confirmable store. Defaults to a [TokenGenerator] with a zero key; wire a
	// real [KeyGenerator] in production.
	TokenGenerator *TokenGenerator
	// Now is the clock (defaults to time.Now().UTC()). Devise stores all
	// timestamps in UTC.
	Now func() time.Time
	// Credentials extracts the authentication hash and password from a Rack env
	// for the database strategy. Defaults to reading env["devise.credentials"]
	// and env["devise.password"]; a binding overrides it to parse Rack params.
	Credentials Credentials

	// --- Notification callbacks (mailer seams) ---

	// SendResetPasswordInstructions is invoked with the raw reset token after it
	// is set, standing in for the Recoverable mailer. Optional.
	SendResetPasswordInstructions func(r *Record, rawToken string)
	// SendConfirmationInstructions is invoked with the raw confirmation token,
	// standing in for the Confirmable mailer. Optional.
	SendConfirmationInstructions func(r *Record, rawToken string)
	// SendUnlockInstructions is invoked with the raw unlock token, standing in
	// for the Lockable mailer. Optional.
	SendUnlockInstructions func(r *Record, rawToken string)
}

// DefaultConfig returns a Config populated with Devise's out-of-the-box
// defaults. Callers override individual fields (Stretches, Pepper, Finder,
// TokenGenerator, ...) as a Rails app would in its initializer.
func DefaultConfig() *Config {
	return &Config{
		Stretches:                    bcrypt.DefaultCost,
		Pepper:                       "",
		EmailRegexp:                  DefaultEmailRegexp,
		PasswordLengthMin:            6,
		PasswordLengthMax:            128,
		ResetPasswordWithin:          6 * time.Hour,
		RememberFor:                  2 * 7 * 24 * time.Hour,
		ExpireAllRememberMeOnSignOut: true,
		AllowUnconfirmedAccessFor:    nil,
		ConfirmWithin:                nil,
		MaximumAttempts:              20,
		UnlockIn:                     1 * time.Hour,
		UnlockStrategy:               UnlockBoth,
		LockStrategy:                 LockFailedAttempts,
		TimeoutIn:                    nil,
		AuthenticationKeys:           []string{AttrEmail},
		FriendlyTokenLength:          20,
		TokenGenerator:               NewTokenGenerator(nil),
		Now:                          func() time.Time { return time.Now().UTC() },
	}
}

// now returns the current time from the config clock, defaulting to UTC now.
func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// tokenGenerator returns the config's generator, defaulting to a zero-key one.
func (c *Config) tokenGenerator() *TokenGenerator {
	if c.TokenGenerator != nil {
		return c.TokenGenerator
	}
	return NewTokenGenerator(nil)
}

// find runs the Finder, returning (nil, false) when no Finder is configured.
func (c *Config) find(attrs map[string]any) (Model, bool) {
	if c.Finder == nil {
		return nil, false
	}
	return c.Finder(attrs)
}

// DefaultEmailRegexp is Devise.email_regexp: a non-empty local part, an @, and a
// non-empty domain part, neither containing whitespace or a further @.
var DefaultEmailRegexp = regexp.MustCompile(`\A[^@\s]+@[^@\s]+\z`)
