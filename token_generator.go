// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
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

// KeyGeneratorIterations is the PBKDF2 iteration count ActiveSupport::KeyGenerator
// uses by default (2**16), and thus what Devise's token generator uses.
const KeyGeneratorIterations = 1 << 16

// KeyGeneratorKeySize is the default derived-key length in bytes
// (ActiveSupport::KeyGenerator#generate_key's key_size default of 64, chosen to
// match OpenSSL::Digest::SHA1#block_length).
const KeyGeneratorKeySize = 64

// pbkdf2Key is indirected so a test can drive PBKDF2's (otherwise unreachable
// with valid parameters) error branch in [PBKDF2KeyGenerator.GenerateKey]. It
// mirrors OpenSSL::PKCS5.pbkdf2_hmac.
var pbkdf2Key = func(h func() hash.Hash, password string, salt []byte, iter, keyLength int) ([]byte, error) {
	return pbkdf2.Key(h, password, salt, iter, keyLength)
}

// PBKDF2KeyGenerator is the byte-faithful port of Rails'
// ActiveSupport::KeyGenerator: it derives per-salt keys with PBKDF2-HMAC-SHA1
// over a shared Secret (Devise.secret_key / the app's secret_key_base). This is
// the key generator Devise actually wires into Devise::TokenGenerator, so a
// generator built with the same Secret digests raw tokens to the exact bytes MRI
// Devise stores — the reset/confirm/unlock digest oracle.
//
// The zero value is not usable (an empty Secret would derive from nothing); build
// one with [NewPBKDF2KeyGenerator]. Iterations, KeySize and the HMAC hash are
// exposed for the rare app that overrides ActiveSupport's defaults, but the
// defaults (2**16 iterations, 64-byte keys, SHA1) match a stock Rails app.
type PBKDF2KeyGenerator struct {
	Secret     []byte
	Iterations int
	KeySize    int
	Hash       func() hash.Hash
}

// NewPBKDF2KeyGenerator builds a [PBKDF2KeyGenerator] over secret with
// ActiveSupport's defaults (2**16 iterations, 64-byte keys, HMAC-SHA1), matching
// ActiveSupport::KeyGenerator.new(secret).
func NewPBKDF2KeyGenerator(secret []byte) PBKDF2KeyGenerator {
	return PBKDF2KeyGenerator{
		Secret:     secret,
		Iterations: KeyGeneratorIterations,
		KeySize:    KeyGeneratorKeySize,
		Hash:       sha1.New,
	}
}

// GenerateKey returns PBKDF2-HMAC(Secret, salt, Iterations, KeySize), faithful to
// ActiveSupport::KeyGenerator#generate_key(salt). Unset Iterations/KeySize/Hash
// fall back to ActiveSupport's defaults so a bare PBKDF2KeyGenerator{Secret: s}
// still behaves like the stock generator.
func (g PBKDF2KeyGenerator) GenerateKey(salt string) []byte {
	iter := g.Iterations
	if iter == 0 {
		iter = KeyGeneratorIterations
	}
	size := g.KeySize
	if size == 0 {
		size = KeyGeneratorKeySize
	}
	h := g.Hash
	if h == nil {
		h = sha1.New
	}
	key, err := pbkdf2Key(h, string(g.Secret), []byte(salt), iter, size)
	if err != nil {
		// PBKDF2 only fails on absurd parameters (e.g. a key length that
		// overflows); surface no key rather than a truncated one.
		return nil
	}
	return key
}

// CachingKeyGenerator memoises another [KeyGenerator] by salt, the port of
// ActiveSupport::CachingKeyGenerator. PBKDF2 at 2**16 iterations is deliberately
// slow, and Devise re-derives the same per-column key on every token operation,
// so Devise wraps its KeyGenerator in a caching one; [NewDeviseTokenGenerator]
// does the same. It is safe for the sequential use a request makes; wrap access
// externally if you share one across goroutines.
type CachingKeyGenerator struct {
	inner KeyGenerator
	cache map[string][]byte
}

// NewCachingKeyGenerator wraps inner so repeated GenerateKey(salt) calls with the
// same salt reuse the first derivation.
func NewCachingKeyGenerator(inner KeyGenerator) *CachingKeyGenerator {
	return &CachingKeyGenerator{inner: inner, cache: map[string][]byte{}}
}

// GenerateKey returns the cached key for salt, deriving and caching it on first
// use, faithful to ActiveSupport::CachingKeyGenerator#generate_key.
func (g *CachingKeyGenerator) GenerateKey(salt string) []byte {
	if k, ok := g.cache[salt]; ok {
		return k
	}
	k := g.inner.GenerateKey(salt)
	g.cache[salt] = k
	return k
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

// NewDeviseTokenGenerator builds the byte-faithful equivalent of
// Devise.token_generator for a given secret: a [TokenGenerator] over a
// [CachingKeyGenerator] wrapping a [PBKDF2KeyGenerator], with HMAC-SHA256
// digests. Pass the app's Devise.secret_key (its secret_key_base). The resulting
// digests are byte-identical to MRI Devise's, so a reset/confirm/unlock digest
// stored by this library verifies a raw token issued by the gem and vice-versa.
func NewDeviseTokenGenerator(secret []byte) *TokenGenerator {
	return NewTokenGenerator(NewCachingKeyGenerator(NewPBKDF2KeyGenerator(secret)))
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
