// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"github.com/go-ruby-rack/rack"
	"github.com/go-ruby-warden/warden"
)

// --- Warden strategies ---
//
// Ports Devise::Strategies::Authenticatable and
// Devise::Strategies::DatabaseAuthenticatable onto go-ruby-warden's
// [warden.StrategyResult]. The strategy is the bridge between Warden's
// authentication chain and the DatabaseAuthenticatable / Lockable / Confirmable
// module logic above.

// StrategyDatabaseAuthenticatable is the Warden label of the database strategy,
// matching Devise's :database_authenticatable.
const StrategyDatabaseAuthenticatable = "database_authenticatable"

// DatabaseAuthenticatableStrategy is Devise's password strategy: it looks a
// record up by the authentication keys and verifies its password, gated by
// Lockable's valid_for_authentication? and Confirmable's
// active_for_authentication?.
type DatabaseAuthenticatableStrategy struct {
	Cfg *Config
}

// Valid reports the strategy's valid? predicate (valid_for_params_auth?): a
// password must be present and every configured authentication key must be
// present and non-empty in authHash.
func (s DatabaseAuthenticatableStrategy) Valid(authHash map[string]any, password string) bool {
	if password == "" {
		return false
	}
	for _, k := range s.Cfg.AuthenticationKeys {
		v, ok := authHash[k]
		if !ok {
			return false
		}
		if str, isStr := v.(string); isStr && str == "" {
			return false
		}
	}
	return true
}

// Run executes the strategy, returning a [warden.StrategyResult] faithful to
// Devise's authenticate!: an invalid strategy is skipped (Valid=false); an
// unknown record fails with "not_found_in_database"; a record whose password
// fails or whose account is locked fails with "invalid"; an inactive
// (unconfirmed) record fails with its inactive message; otherwise the record is
// returned as the authenticated user.
func (s DatabaseAuthenticatableStrategy) Run(authHash map[string]any, password string) warden.StrategyResult {
	if !s.Valid(authHash, password) {
		return warden.StrategyResult{Valid: false}
	}

	keys := map[string]any{}
	for _, k := range s.Cfg.AuthenticationKeys {
		keys[k] = authHash[k]
	}

	m, ok := s.Cfg.find(keys)
	if !ok {
		return failure("not_found_in_database")
	}
	r := New(s.Cfg, m)

	if !r.ValidForAuthentication(func() bool { return r.ValidPassword(password) }) {
		return failure("invalid")
	}
	if !r.ActiveForAuthentication() {
		return failure(r.InactiveMessage())
	}
	return warden.StrategyResult{
		Valid:  true,
		Result: warden.ResultSuccess,
		User:   m,
		Halted: true,
	}
}

// failure builds a halting failure StrategyResult with a message.
func failure(msg string) warden.StrategyResult {
	return warden.StrategyResult{
		Valid:   true,
		Result:  warden.ResultFailure,
		Halted:  true,
		Message: msg,
	}
}

// InactiveMessage returns the reason an authenticated-but-inactive record is
// rejected, faithful to inactive_message: "unconfirmed" for a record outside its
// confirmation grace window, else "inactive".
func (r *Record) InactiveMessage() string {
	if !r.Confirmed() && !r.ConfirmationPeriodValid() {
		return "unconfirmed"
	}
	return "inactive"
}

// Credentials is the seam that extracts the authentication hash and password
// from a Rack env, standing in for Warden's params parsing. The default reads
// env["devise.credentials"] (a map[string]any of authentication keys) and
// env["devise.password"] (a string); a binding overrides [Config.Credentials]
// to parse real Rack params.
type Credentials func(env rack.Env) (authHash map[string]any, password string)

// defaultCredentials reads the credentials a binding stashed under the
// well-known env keys.
func defaultCredentials(env rack.Env) (map[string]any, string) {
	authHash, _ := env["devise.credentials"].(map[string]any)
	password, _ := env["devise.password"].(string)
	return authHash, password
}

// DatabaseStrategyRun returns a [warden.StrategyRun] that dispatches the
// database_authenticatable label to this config's strategy, reading credentials
// via [Config.Credentials]. Plug it into a Manager with
// warden.WithStrategyRun(cfg.DatabaseStrategyRun()).
func (c *Config) DatabaseStrategyRun() warden.StrategyRun {
	s := DatabaseAuthenticatableStrategy{Cfg: c}
	extract := c.Credentials
	if extract == nil {
		extract = defaultCredentials
	}
	return func(name string, env rack.Env) warden.StrategyResult {
		if name != StrategyDatabaseAuthenticatable {
			return warden.StrategyResult{Valid: false}
		}
		authHash, password := extract(env)
		return s.Run(authHash, password)
	}
}
