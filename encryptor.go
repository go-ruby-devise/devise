// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import "github.com/go-ruby-bcrypt/bcrypt"

// bcryptHashSecret is indirected so a test can drive the (otherwise unreachable,
// since the salt comes from a validated hash) HashSecret error branch in
// Compare. It mirrors BCrypt::Engine.hash_secret.
var bcryptHashSecret = bcrypt.HashSecret

// Encryptor is Devise::Encryptor: the bcrypt-backed password hasher. Digest
// hashes a password at a cost, applying the pepper; Compare checks a candidate
// password against a stored hash in constant time. Both mirror the gem exactly,
// delegating the crypto to go-ruby-bcrypt.
type Encryptor struct{}

// Digest hashes password with the pepper applied, at the given bcrypt cost,
// faithful to Devise::Encryptor.digest: when pepper is non-empty it is appended
// to the password before hashing, then BCrypt::Password.create(..., cost:) runs.
// The returned string is the "$2a$NN$...."-form hash to store in
// encrypted_password.
func (Encryptor) Digest(password, pepper string, cost int) (string, error) {
	if pepper != "" {
		password += pepper
	}
	p, err := bcrypt.CreateString(password, bcrypt.WithCost(cost))
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

// Compare reports whether password matches hashedPassword, faithful to
// Devise::Encryptor.compare: a blank stored hash is never a match; otherwise the
// candidate (with pepper applied) is hashed against the stored salt and the
// result is compared to the stored hash with [SecureCompare]. An unparseable
// stored hash is treated as no match.
func (Encryptor) Compare(hashedPassword, password, pepper string) bool {
	if hashedPassword == "" {
		return false
	}
	parsed, err := bcrypt.NewPassword(hashedPassword)
	if err != nil {
		return false
	}
	if pepper != "" {
		password += pepper
	}
	candidate, err := bcryptHashSecret([]byte(password), parsed.Salt())
	if err != nil {
		return false
	}
	return SecureCompare(candidate, hashedPassword)
}
