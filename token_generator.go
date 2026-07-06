// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// KeyGenerator derives a per-column signing key from a secret, mirroring the
// ActiveSupport::KeyGenerator that Devise::TokenGenerator is built on. Devise
// calls key_generator.generate_key("Devise <column>") to obtain the HMAC key for
// each tokenised column, so that the same raw token digests differently per
// column.
//
// The default [HMACKeyGenerator] derives the key with HMAC-SHA256; a production
// binding may instead plug Rails' PBKDF2-based ActiveSupport::KeyGenerator here.
// Either way the resulting digests are HMAC-SHA256 hexdigests, exactly Devise's
// token shape.
type KeyGenerator interface {
	GenerateKey(salt string) []byte
}

// HMACKeyGenerator derives keys as HMAC-SHA256(Secret, salt). It is the default
// [KeyGenerator]; a zero-value (empty Secret) is valid and deterministic, which
// is why the token generator works out of the box in tests.
type HMACKeyGenerator struct {
	Secret []byte
}

// GenerateKey returns HMAC-SHA256(Secret, salt).
func (g HMACKeyGenerator) GenerateKey(salt string) []byte {
	mac := hmac.New(sha256.New, g.Secret)
	mac.Write([]byte(salt))
	return mac.Sum(nil)
}

// TokenGenerator mints and digests the raw tokens Recoverable and Confirmable
// persist, faithful to Devise::TokenGenerator. Generate returns a [raw, enc]
// pair — the raw token is mailed to the user, the enc digest is stored in the
// database — and Digest reproduces enc from a raw token to look the record up.
type TokenGenerator struct {
	keyGen KeyGenerator
	digest func() hash.Hash
	// FriendlyLength is the length passed to [FriendlyToken] for the raw token
	// (Devise uses the default 20).
	FriendlyLength int
}

// NewTokenGenerator builds a token generator over keyGen (defaulting to a
// zero-key [HMACKeyGenerator]) using HMAC-SHA256 digests, as Devise does.
func NewTokenGenerator(keyGen KeyGenerator) *TokenGenerator {
	if keyGen == nil {
		keyGen = HMACKeyGenerator{}
	}
	return &TokenGenerator{keyGen: keyGen, digest: sha256.New, FriendlyLength: 20}
}

// keyFor returns the HMAC key for a column, matching
// generate_key("Devise <column>").
func (t *TokenGenerator) keyFor(column string) []byte {
	return t.keyGen.GenerateKey("Devise " + column)
}

// Digest reproduces the stored digest for a raw token value, faithful to
// Devise::TokenGenerator#digest: an empty value yields "" (Devise returns nil),
// otherwise the HMAC-SHA256 hexdigest of value under the column key.
func (t *TokenGenerator) Digest(column, value string) string {
	if value == "" {
		return ""
	}
	mac := hmac.New(t.digest, t.keyFor(column))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// Generate returns a fresh (raw, enc) token pair for a column, faithful to
// Devise::TokenGenerator#generate: it draws a [FriendlyToken] and digests it,
// retrying while exists reports the digest is already taken (the uniqueness loop
// against the column). A nil exists never collides.
func (t *TokenGenerator) Generate(column string, exists func(enc string) bool) (raw, enc string) {
	for {
		raw = FriendlyToken(t.FriendlyLength)
		enc = t.Digest(column, raw)
		if exists == nil || !exists(enc) {
			return raw, enc
		}
	}
}
