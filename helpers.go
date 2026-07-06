// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// randRead is indirected so tests can drive token generation deterministically
// and exercise the read-error branch. It mirrors SecureRandom's entropy source.
var randRead = rand.Read

// FriendlyToken returns a URL-safe random token, faithful to
// Devise.friendly_token: it draws (length*3)/4 random bytes, URL-safe-base64
// encodes them without padding, then maps the ambiguous characters l, I, O and 0
// to s, x, y and z. With the default length of 20 it yields a 20-character
// token. A non-positive length yields the empty string (no entropy requested).
func FriendlyToken(length int) string {
	rlength := (length * 3) / 4
	if rlength <= 0 {
		return ""
	}
	b := make([]byte, rlength)
	if _, err := randRead(b); err != nil {
		// SecureRandom cannot fail in practice; surface an empty token rather
		// than a partially-random one.
		return ""
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	return friendlyTr.Replace(s)
}

// friendlyTr is Devise's tr('lIO0', 'sxyz'): the substitution that removes
// visually ambiguous characters from a friendly token.
var friendlyTr = strings.NewReplacer("l", "s", "I", "x", "O", "y", "0", "z")

// SecureCompare compares two strings in constant time, faithful to
// Devise.secure_compare (ActiveSupport::SecurityUtils.secure_compare): it
// returns false immediately when the byte lengths differ, and otherwise performs
// a fixed-length, timing-safe comparison. Two empty strings are equal.
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
