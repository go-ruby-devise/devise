// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "time"

// Model is the persistence seam Devise operates on: a single authenticatable
// resource (a User row in Rails). It is the minimal surface every Devise module
// needs — read an attribute, write an attribute, and persist. The host wires it
// to ActiveRecord (in Rails) or to go-embedded-ruby's object model (under rbgo).
//
// Get returns the current value of a database column by its Devise attribute
// name (see the Attr* constants); a missing / SQL-NULL value is nil. Set stages
// a new value. Save persists the staged values, mirroring ActiveRecord's
// save(validate: false) that Devise uses throughout (validation is a separate
// concern handled by [Record.ValidatableErrors]).
type Model interface {
	Get(attr string) any
	Set(attr string, val any)
	Save() error
}

// Finder is the class-level lookup seam, standing in for ActiveRecord's
// to_adapter.find_first / find_for_database_authentication. It returns the first
// record matching every attribute in attrs, and false when none matches. The
// binding wires it to a real query; tests wire it to an in-memory table.
type Finder func(attrs map[string]any) (Model, bool)

// Devise attribute names — the database columns Devise's modules read and write.
// They match the column names Devise's generators create so a binding can map
// them straight onto ActiveRecord attributes.
const (
	AttrEmail             = "email"
	AttrEncryptedPassword = "encrypted_password"

	AttrResetPasswordToken  = "reset_password_token"
	AttrResetPasswordSentAt = "reset_password_sent_at"

	AttrRememberToken     = "remember_token"
	AttrRememberCreatedAt = "remember_created_at"

	AttrConfirmationToken  = "confirmation_token"
	AttrConfirmedAt        = "confirmed_at"
	AttrConfirmationSentAt = "confirmation_sent_at"
	AttrUnconfirmedEmail   = "unconfirmed_email"

	AttrFailedAttempts = "failed_attempts"
	AttrUnlockToken    = "unlock_token"
	AttrLockedAt       = "locked_at"

	AttrSignInCount     = "sign_in_count"
	AttrCurrentSignInAt = "current_sign_in_at"
	AttrLastSignInAt    = "last_sign_in_at"
	AttrCurrentSignInIP = "current_sign_in_ip"
	AttrLastSignInIP    = "last_sign_in_ip"
)

// Record is a Devise resource: a [Model] bound to the [Config] that governs it,
// the equivalent of an ActiveRecord instance whose self.class carries the Devise
// settings. All module logic hangs off methods on *Record.
type Record struct {
	m   Model
	cfg *Config
}

// New binds a model to a config, yielding the resource the module methods act
// on. A nil cfg uses [DefaultConfig].
func New(cfg *Config, m Model) *Record {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Record{m: m, cfg: cfg}
}

// Model returns the underlying model.
func (r *Record) Model() Model { return r.m }

// Config returns the governing config.
func (r *Record) Config() *Config { return r.cfg }

// getString reads a string attribute, treating nil as "".
func (r *Record) getString(attr string) string {
	if s, ok := r.m.Get(attr).(string); ok {
		return s
	}
	return ""
}

// getInt reads an integer attribute, treating nil / non-int as 0.
func (r *Record) getInt(attr string) int {
	if n, ok := r.m.Get(attr).(int); ok {
		return n
	}
	return 0
}

// getTime reads a time attribute. The second result is false when the column is
// nil (SQL NULL), matching Ruby's nil timestamp.
func (r *Record) getTime(attr string) (time.Time, bool) {
	if t, ok := r.m.Get(attr).(time.Time); ok {
		return t, true
	}
	return time.Time{}, false
}
