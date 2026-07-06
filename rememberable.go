// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"strings"
)

// --- Rememberable module ---
//
// Ports Devise::Models::Rememberable: the remember-me token lifecycle and the
// cookie serialise/deserialise pair.

// ErrRememberCookieInvalid is returned by [Config.SerializeFromCookie] when the
// cookie is malformed or does not authenticate a record.
var ErrRememberCookieInvalid = errors.New("devise: invalid remember cookie")

// RememberMe issues a remember token, faithful to remember_me!: it sets
// remember_token (unique via the finder) if unset, sets remember_created_at if
// unset, and saves. Devise only saves when the record changed; here it always
// saves after staging, which is observationally equivalent for a fresh token.
func (r *Record) RememberMe() error {
	if r.getString(AttrRememberToken) == "" {
		r.m.Set(AttrRememberToken, r.newRememberToken())
	}
	if _, ok := r.getTime(AttrRememberCreatedAt); !ok {
		r.m.Set(AttrRememberCreatedAt, r.cfg.now())
	}
	return r.m.Save()
}

// ForgetMe clears the remember state, faithful to forget_me!: it clears
// remember_token, clears remember_created_at when
// expire_all_remember_me_on_sign_out is set, and saves.
func (r *Record) ForgetMe() error {
	r.m.Set(AttrRememberToken, nil)
	if r.cfg.ExpireAllRememberMeOnSignOut {
		r.m.Set(AttrRememberCreatedAt, nil)
	}
	return r.m.Save()
}

// RememberableValue is the value stored in the cookie to re-identify the record,
// faithful to rememberable_value: the remember_token when present, else the
// authenticatable salt. It is "" only when neither is available.
func (r *Record) RememberableValue() string {
	if tok := r.getString(AttrRememberToken); tok != "" {
		return tok
	}
	return r.AuthenticatableSalt()
}

// RememberExpired reports whether the remember cookie has expired, faithful to
// remember_expired?: true when remember_created_at is nil or older than
// remember_for.
func (r *Record) RememberExpired() bool {
	created, ok := r.getTime(AttrRememberCreatedAt)
	if !ok {
		return true
	}
	return !r.cfg.now().Before(created.Add(r.cfg.RememberFor))
}

// newRememberToken draws a friendly token unique against remember_token.
func (r *Record) newRememberToken() string {
	for {
		tok := FriendlyToken(r.cfg.FriendlyTokenLength)
		if _, ok := r.cfg.find(map[string]any{AttrRememberToken: tok}); !ok {
			return tok
		}
	}
}

// SerializeIntoCookie returns the cookie payload for a record, faithful to
// serialize_into_cookie: [id, rememberable_value, timestamp]. The id and
// timestamp are supplied by the caller (the model's to_key and Time.now.to_f in
// Devise), keeping this free of a persistence-identity assumption.
func SerializeIntoCookie(id, rememberableValue, timestamp string) []string {
	return []string{id, rememberableValue, timestamp}
}

// SerializeFromCookie re-identifies a record from a cookie payload, faithful to
// serialize_from_cookie: it finds the record by id, then confirms it is not
// expired and its rememberable value matches the cookie's, via [SecureCompare].
// A mismatch, an expired cookie, or a missing record yields
// [ErrRememberCookieInvalid].
func (c *Config) SerializeFromCookie(id, rememberableValue string) (*Record, error) {
	m, ok := c.find(map[string]any{"id": id})
	if !ok {
		return nil, ErrRememberCookieInvalid
	}
	r := New(c, m)
	if r.RememberExpired() || !SecureCompare(r.RememberableValue(), rememberableValue) {
		return nil, ErrRememberCookieInvalid
	}
	return r, nil
}

// EncodeCookie joins a cookie payload with "/" the way Devise's cookie
// serializer does before signing. Provided as a convenience for a binding that
// stores the payload as a single string.
func EncodeCookie(parts []string) string { return strings.Join(parts, "/") }

// DecodeCookie splits an [EncodeCookie] payload back into its parts.
func DecodeCookie(s string) []string { return strings.Split(s, "/") }
