// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

// Differential oracle tests that drive the *actual* Devise gem classes
// (Devise::Encryptor, Devise::TokenGenerator, Devise.secure_compare) rather than
// re-deriving their algorithms from Ruby stdlib. They need the devise + bcrypt
// gems installed, so they skip-gate on the gems being requireable (they are not
// on the stock CI lanes; run them locally with the gems on GEM_PATH). This is the
// strongest form of the parity claim: bytes produced here are checked against the
// gem's own code path.

import (
	"os/exec"
	"strings"
	"testing"
)

// runRubyGems runs a Ruby script that requires devise + bcrypt, skipping the test
// unless both gems can be loaded. On the CI lanes without the gems (and on
// Windows / no-ruby lanes) it simply skips; the deterministic and stdlib-oracle
// tests already cover these surfaces.
func runRubyGems(t *testing.T, script string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not available; skipping gem differential oracle")
	}
	probe := exec.Command("ruby", "-e", "require 'devise'; require 'bcrypt'")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("devise/bcrypt gems not available; skipping gem oracle\n%s", out)
	}
	cmd := exec.Command("ruby", append([]string{"-e", script}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby gem oracle failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// klassScript builds the Struct-based `klass` Devise::Encryptor expects (it reads
// klass.pepper and klass.stretches), for prepending to an encryptor script.
const klassScript = `
require 'devise'
Klass = Struct.new(:pepper, :stretches) unless defined?(Klass)
`

// TestOracleEncryptorGemHashVerifiesHere proves a hash minted by the gem's
// Devise::Encryptor.digest verifies under this library's Encryptor.Compare — the
// direction that matters when reading an existing Devise database.
func TestOracleEncryptorGemHashVerifiesHere(t *testing.T) {
	const password = "s3cret-pa55!"
	for _, pepper := range []string{"", "a-long-pepper-value-0123456789"} {
		hash := runRubyGems(t, klassScript+`
pepper, cost, password = ARGV
print Devise::Encryptor.digest(Klass.new(pepper, cost.to_i), password)
`, pepper, "5", password)

		if !(Encryptor{}).Compare(hash, password, pepper) {
			t.Fatalf("gem hash (pepper=%q) did not verify here: %s", pepper, hash)
		}
		if (Encryptor{}).Compare(hash, "wrong", pepper) {
			t.Fatalf("wrong password must not verify against gem hash (pepper=%q)", pepper)
		}
	}
}

// TestOracleEncryptorOurHashVerifiesInGem proves a hash minted here verifies under
// the gem's Devise::Encryptor.compare — the direction that matters when a Devise
// app reads a password this library wrote.
func TestOracleEncryptorOurHashVerifiesInGem(t *testing.T) {
	const password = "s3cret-pa55!"
	for _, pepper := range []string{"", "a-long-pepper-value-0123456789"} {
		hash, err := (Encryptor{}).Digest(password, pepper, 5)
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		good := runRubyGems(t, klassScript+`
pepper, hash, password = ARGV
print Devise::Encryptor.compare(Klass.new(pepper, 5), hash, password)
`, pepper, hash, password)
		if good != "true" {
			t.Fatalf("our hash (pepper=%q) did not verify in the gem: %q", pepper, good)
		}
		bad := runRubyGems(t, klassScript+`
pepper, hash = ARGV
print Devise::Encryptor.compare(Klass.new(pepper, 5), hash, "wrong")
`, pepper, hash)
		if bad != "false" {
			t.Fatalf("wrong password unexpectedly verified in the gem (pepper=%q): %q", pepper, bad)
		}
	}
}

// TestOracleTokenGeneratorGemClass drives the gem's own
// Devise::TokenGenerator#digest (over a real ActiveSupport::KeyGenerator) and
// asserts byte-equality with NewDeviseTokenGenerator — checking the actual gem
// class, not just its algorithm.
func TestOracleTokenGeneratorGemClass(t *testing.T) {
	const secret = "gem-class-secret-key-base-abcdef0123456789"
	const raw = "raw-token-abcdefg"
	tg := NewDeviseTokenGenerator([]byte(secret))

	for _, col := range []string{AttrResetPasswordToken, AttrConfirmationToken, AttrUnlockToken} {
		want := runRubyGems(t, `
require 'devise'
require 'active_support/key_generator'
secret, column, raw = ARGV
gen = Devise::TokenGenerator.new(ActiveSupport::KeyGenerator.new(secret))
print gen.digest(nil, column, raw)
`, secret, col, raw)
		if got := tg.Digest(col, raw); got != want {
			t.Fatalf("Devise::TokenGenerator digest[%s]\n go = %s\n rb = %s", col, got, want)
		}
	}
}

// TestOracleSecureCompareGem checks SecureCompare against Devise.secure_compare
// (ActiveSupport::SecurityUtils.secure_compare) across equal, differing and
// unequal-length pairs.
func TestOracleSecureCompareGem(t *testing.T) {
	cases := [][2]string{
		{"abcdef", "abcdef"},
		{"abcdef", "abcdeg"},
		{"abc", "abcdef"},
	}
	for _, c := range cases {
		got := (SecureCompare(c[0], c[1]))
		want := runRubyGems(t, `require 'devise'; print Devise.secure_compare(ARGV[0], ARGV[1])`, c[0], c[1]) == "true"
		if got != want {
			t.Fatalf("secure_compare(%q,%q): go=%v ruby=%v", c[0], c[1], got, want)
		}
	}
}
