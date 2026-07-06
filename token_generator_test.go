// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "testing"

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
