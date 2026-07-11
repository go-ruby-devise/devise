// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"hash"
	"testing"
)

func TestPBKDF2KeyGeneratorDefaults(t *testing.T) {
	g := NewPBKDF2KeyGenerator([]byte("secret"))
	if g.Iterations != KeyGeneratorIterations || g.KeySize != KeyGeneratorKeySize {
		t.Fatalf("defaults = (%d,%d), want (%d,%d)", g.Iterations, g.KeySize, KeyGeneratorIterations, KeyGeneratorKeySize)
	}
	k := g.GenerateKey("Devise reset_password_token")
	if len(k) != 64 {
		t.Fatalf("key length = %d, want 64", len(k))
	}
	// Determinism + per-salt divergence.
	if string(k) != string(g.GenerateKey("Devise reset_password_token")) {
		t.Fatal("same salt should derive the same key")
	}
	if string(k) == string(g.GenerateKey("Devise confirmation_token")) {
		t.Fatal("different salts should derive different keys")
	}
}

func TestPBKDF2KeyGeneratorBareStructDefaults(t *testing.T) {
	// A bare struct with only Secret set must fall back to ActiveSupport's
	// defaults, matching NewPBKDF2KeyGenerator.
	bare := PBKDF2KeyGenerator{Secret: []byte("secret")}
	full := NewPBKDF2KeyGenerator([]byte("secret"))
	if string(bare.GenerateKey("Devise unlock_token")) != string(full.GenerateKey("Devise unlock_token")) {
		t.Fatal("a bare PBKDF2KeyGenerator should default like NewPBKDF2KeyGenerator")
	}
}

func TestPBKDF2KeyGeneratorError(t *testing.T) {
	orig := pbkdf2Key
	pbkdf2Key = func(func() hash.Hash, string, []byte, int, int) ([]byte, error) {
		return nil, errors.New("boom")
	}
	defer func() { pbkdf2Key = orig }()
	if k := NewPBKDF2KeyGenerator([]byte("s")).GenerateKey("Devise x"); k != nil {
		t.Fatalf("on PBKDF2 error GenerateKey = %x, want nil", k)
	}
}

func TestCachingKeyGenerator(t *testing.T) {
	calls := 0
	inner := funcKeyGen(func(salt string) []byte {
		calls++
		return []byte(salt)
	})
	g := NewCachingKeyGenerator(inner)
	a := g.GenerateKey("Devise reset_password_token")
	b := g.GenerateKey("Devise reset_password_token") // cache hit
	if string(a) != string(b) {
		t.Fatal("cache hit should return the same key")
	}
	if calls != 1 {
		t.Fatalf("inner called %d times, want 1 (second is cached)", calls)
	}
	_ = g.GenerateKey("Devise confirmation_token") // cache miss
	if calls != 2 {
		t.Fatalf("inner called %d times, want 2 after a miss", calls)
	}
}

func TestNewDeviseTokenGeneratorNonEmpty(t *testing.T) {
	tg := NewDeviseTokenGenerator([]byte("secret_key_base"))
	if d := tg.Digest("reset_password_token", "raw"); d == "" {
		t.Fatal("Devise token generator should digest a non-empty value")
	}
}

// funcKeyGen adapts a function to the KeyGenerator interface for the caching test.
type funcKeyGen func(salt string) []byte

func (f funcKeyGen) GenerateKey(salt string) []byte { return f(salt) }

func TestHMACKeyGeneratorDeterministic(t *testing.T) {
	g := HMACKeyGenerator{Secret: []byte("secret")}
	a := g.GenerateKey("Devise reset_password_token")
	b := g.GenerateKey("Devise reset_password_token")
	c := g.GenerateKey("Devise confirmation_token")
	if string(a) != string(b) {
		t.Fatal("same salt should derive the same key")
	}
	if string(a) == string(c) {
		t.Fatal("different salts should derive different keys")
	}
	if len(a) != 32 {
		t.Fatalf("HMAC-SHA256 key length = %d, want 32", len(a))
	}
}

func TestNewTokenGeneratorDefaultKeyGen(t *testing.T) {
	tg := NewTokenGenerator(nil) // zero-key HMAC
	if d := tg.Digest("reset_password_token", "raw"); d == "" {
		t.Fatal("digest of a non-empty value should be non-empty")
	}
}

func TestTokenGeneratorDigestEmpty(t *testing.T) {
	tg := NewTokenGenerator(HMACKeyGenerator{Secret: []byte("k")})
	if d := tg.Digest("reset_password_token", ""); d != "" {
		t.Fatalf("digest of empty value = %q, want empty", d)
	}
}

func TestTokenGeneratorDigestPerColumn(t *testing.T) {
	tg := NewTokenGenerator(HMACKeyGenerator{Secret: []byte("k")})
	if tg.Digest("reset_password_token", "x") == tg.Digest("confirmation_token", "x") {
		t.Fatal("same raw token should digest differently per column")
	}
}

func TestTokenGeneratorGenerateNilExists(t *testing.T) {
	tg := NewTokenGenerator(nil)
	raw, enc := tg.Generate("reset_password_token", nil)
	if raw == "" || enc == "" {
		t.Fatal("generate should return a non-empty pair")
	}
	if enc != tg.Digest("reset_password_token", raw) {
		t.Fatal("enc should be the digest of raw")
	}
}

func TestTokenGeneratorGenerateRetries(t *testing.T) {
	tg := NewTokenGenerator(nil)
	calls := 0
	exists := func(string) bool {
		calls++
		return calls == 1 // collide once, then succeed
	}
	raw, enc := tg.Generate("reset_password_token", exists)
	if calls != 2 {
		t.Fatalf("exists called %d times, want 2 (one collision + one success)", calls)
	}
	if raw == "" || enc == "" {
		t.Fatal("generate should still return a pair after a retry")
	}
}
