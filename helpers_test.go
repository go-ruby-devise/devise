// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"strings"
	"testing"
)

func TestFriendlyTokenLengthAndAlphabet(t *testing.T) {
	tok := FriendlyToken(20)
	if len(tok) != 20 {
		t.Fatalf("length = %d, want 20", len(tok))
	}
	if strings.ContainsAny(tok, "lIO0") {
		t.Fatalf("token %q contains an ambiguous character", tok)
	}
}

func TestFriendlyTokenNonPositive(t *testing.T) {
	if got := FriendlyToken(0); got != "" {
		t.Fatalf("FriendlyToken(0) = %q, want empty", got)
	}
	if got := FriendlyToken(1); got != "" { // (1*3)/4 == 0 bytes
		t.Fatalf("FriendlyToken(1) = %q, want empty", got)
	}
}

func TestFriendlyTokenTr(t *testing.T) {
	// Force base64 output to contain each ambiguous char and confirm the mapping.
	// "l" "I" "O" and digit "0" appear in the base64 of these bytes; we assert the
	// replacer output directly.
	if got := friendlyTr.Replace("lIO0abc"); got != "sxyzabc" {
		t.Fatalf("tr = %q, want sxyzabc", got)
	}
}

func TestFriendlyTokenRandError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("boom") }
	defer func() { randRead = orig }()
	if got := FriendlyToken(20); got != "" {
		t.Fatalf("on rand error FriendlyToken = %q, want empty", got)
	}
}

func TestSecureCompare(t *testing.T) {
	if !SecureCompare("abc", "abc") {
		t.Fatal("equal strings should compare equal")
	}
	if SecureCompare("abc", "abd") {
		t.Fatal("different equal-length strings should not match")
	}
	if SecureCompare("abc", "abcd") {
		t.Fatal("different-length strings should not match")
	}
	if !SecureCompare("", "") {
		t.Fatal("empty strings should match")
	}
}
