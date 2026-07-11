// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

// Differential oracle tests against MRI Ruby. This file's oracles need only
// Ruby's standard library (openssl, base64) — no gems — so they run on any lane
// that has a ruby binary (the CI ubuntu/macos lanes install ruby 4.0.5). They
// prove the two byte-exact surfaces the rest of Devise's token machinery is built
// on: the reset/confirm/unlock digest (Devise::TokenGenerator's
// ActiveSupport::KeyGenerator-derived HMAC-SHA256) and Devise.friendly_token's
// url-safe-base64 + tr('lIO0','sxyz') encoding. The deterministic Go tests keep
// coverage at 100% on their own, so lanes without ruby (e.g. windows, qemu)
// simply skip these.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

// runRuby executes a Ruby one-liner script with args, returning its trimmed
// stdout. It skips the calling test when no ruby binary is present (Windows / no
// ruby lanes), so these differential checks are additive over the deterministic
// suite rather than a hard gate.
func runRuby(t *testing.T, script string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not available; skipping MRI differential oracle")
	}
	cmd := exec.Command("ruby", append([]string{"-e", script}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby oracle failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestOracleTokenDigestByteParity is the headline differential test: the digest
// this library stores for a raw reset/confirm/unlock token must equal, byte for
// byte, the digest MRI Devise stores — because a digest issued by either side has
// to verify a raw token issued by the other. Devise's scheme is
// OpenSSL::HMAC.hexdigest("SHA256", key, raw) where key comes from
// ActiveSupport::KeyGenerator (PBKDF2-HMAC-SHA1, 2**16 iterations, 64-byte key,
// salt "Devise <column>"). We compute both digests from the same secret and
// assert equality.
func TestOracleTokenDigestByteParity(t *testing.T) {
	const secret = "my-secret-key-base-0123456789abcdef0123456789abcdef"
	const raw = "swap-me-in-a-real-reset-link"

	tg := NewDeviseTokenGenerator([]byte(secret))

	const rb = `
require 'openssl'
secret, column, raw = ARGV
key = OpenSSL::PKCS5.pbkdf2_hmac(secret, "Devise #{column}", 65536, 64, OpenSSL::Digest::SHA1.new)
print OpenSSL::HMAC.hexdigest("SHA256", key, raw)
`
	for _, col := range []string{
		AttrResetPasswordToken, AttrConfirmationToken, AttrUnlockToken,
	} {
		got := tg.Digest(col, raw)
		want := runRuby(t, rb, secret, col, raw)
		if got != want {
			t.Fatalf("digest[%s]\n go   = %s\n ruby = %s", col, got, want)
		}
	}
}

// TestOracleTokenDigestRoundTripBothDirections proves the practical property the
// digest parity guarantees: a raw token minted by the gem digests (under this
// library) to the value the gem would store, and a raw token minted here digests
// (under the gem) to the same value — so a record written by one verifies under
// the other.
func TestOracleTokenDigestRoundTripBothDirections(t *testing.T) {
	const secret = "another-secret-key-base-zzzz-1111-2222-3333"
	tg := NewDeviseTokenGenerator([]byte(secret))

	// Direction 1: a raw token the gem would mint, digested here.
	gemRaw := runRuby(t, `require 'securerandom'; print SecureRandom.urlsafe_base64(15).tr('lIO0','sxyz')`)
	goEnc := tg.Digest(AttrResetPasswordToken, gemRaw)
	rbEnc := runRuby(t, `
require 'openssl'
secret, raw = ARGV
key = OpenSSL::PKCS5.pbkdf2_hmac(secret, "Devise reset_password_token", 65536, 64, OpenSSL::Digest::SHA1.new)
print OpenSSL::HMAC.hexdigest("SHA256", key, raw)
`, secret, gemRaw)
	if goEnc != rbEnc {
		t.Fatalf("gem-issued raw token digested differently:\n go=%s\n rb=%s", goEnc, rbEnc)
	}

	// Direction 2: a raw token this library mints, digested by the gem.
	goRaw, _ := tg.Generate(AttrConfirmationToken, nil)
	rbEnc2 := runRuby(t, `
require 'openssl'
secret, raw = ARGV
key = OpenSSL::PKCS5.pbkdf2_hmac(secret, "Devise confirmation_token", 65536, 64, OpenSSL::Digest::SHA1.new)
print OpenSSL::HMAC.hexdigest("SHA256", key, raw)
`, secret, goRaw)
	if goEnc2 := tg.Digest(AttrConfirmationToken, goRaw); goEnc2 != rbEnc2 {
		t.Fatalf("our raw token digested differently by the gem:\n go=%s\n rb=%s", goEnc2, rbEnc2)
	}
}

// TestOracleFriendlyTokenEncoding proves Devise.friendly_token's encoding matches
// byte for byte: fed identical entropy, Go's url-safe-base64 + tr('lIO0','sxyz')
// produces the exact string MRI's SecureRandom.urlsafe_base64(...).tr(...) does.
// (The tokens themselves are random, so we inject the same bytes into both.)
func TestOracleFriendlyTokenEncoding(t *testing.T) {
	b := make([]byte, 15) // (20*3)/4, the default friendly_token entropy
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	goTok := friendlyTr.Replace(base64.RawURLEncoding.EncodeToString(b))

	// Reproduce SecureRandom.urlsafe_base64's algorithm over the same bytes:
	// standard base64, "+/"->"-_", strip "=", then Devise's tr('lIO0','sxyz').
	const rb = `
bytes = [ARGV[0]].pack('H*')
s = [bytes].pack('m0').tr('+/', '-_').delete('=').tr('lIO0', 'sxyz')
print s
`
	rbTok := runRuby(t, rb, hex.EncodeToString(b))
	if goTok != rbTok {
		t.Fatalf("friendly_token encoding differs:\n go = %s\n rb = %s", goTok, rbTok)
	}
}

// TestOracleFriendlyTokenTr checks the tr('lIO0','sxyz') substitution alone
// against MRI, independent of the base64 step.
func TestOracleFriendlyTokenTr(t *testing.T) {
	const in = "lIO0-abc-lIO0-XYZ"
	got := friendlyTr.Replace(in)
	want := runRuby(t, `print ARGV[0].tr('lIO0','sxyz')`, in)
	if got != want {
		t.Fatalf("tr differs: go=%q ruby=%q", got, want)
	}
}
