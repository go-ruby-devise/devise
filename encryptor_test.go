// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"testing"

	"github.com/go-ruby-bcrypt/bcrypt"
)

func TestEncryptorDigestAndCompare(t *testing.T) {
	e := Encryptor{}
	hash, err := e.Digest("s3cret!!", "", 4)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !bcrypt.ValidHash(hash) {
		t.Fatalf("Digest produced a non-bcrypt hash: %q", hash)
	}
	if !e.Compare(hash, "s3cret!!", "") {
		t.Fatal("correct password should compare equal")
	}
	if e.Compare(hash, "wrong", "") {
		t.Fatal("wrong password should not compare equal")
	}
}

func TestEncryptorPepper(t *testing.T) {
	e := Encryptor{}
	hash, err := e.Digest("pw", "PEP", 4)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !e.Compare(hash, "pw", "PEP") {
		t.Fatal("password with matching pepper should compare equal")
	}
	if e.Compare(hash, "pw", "") {
		t.Fatal("password without the pepper should not match a peppered hash")
	}
}

func TestEncryptorDigestCostTooHigh(t *testing.T) {
	if _, err := (Encryptor{}).Digest("pw", "", bcrypt.MaxCost+1); err == nil {
		t.Fatal("cost above MaxCost should error")
	}
}

func TestEncryptorCompareBlankHash(t *testing.T) {
	if (Encryptor{}).Compare("", "pw", "") {
		t.Fatal("blank stored hash should never match")
	}
}

func TestEncryptorCompareInvalidHash(t *testing.T) {
	if (Encryptor{}).Compare("not-a-bcrypt-hash", "pw", "") {
		t.Fatal("unparseable stored hash should not match")
	}
}

func TestEncryptorCompareHashSecretError(t *testing.T) {
	hash, err := (Encryptor{}).Digest("pw", "", 4)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	orig := bcryptHashSecret
	bcryptHashSecret = func([]byte, string) (string, error) { return "", errors.New("boom") }
	defer func() { bcryptHashSecret = orig }()
	if (Encryptor{}).Compare(hash, "pw", "") {
		t.Fatal("a HashSecret failure should yield no match")
	}
}
