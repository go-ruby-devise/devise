// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

// --- DatabaseAuthenticatable module ---
//
// Ports Devise::Models::DatabaseAuthenticatable: password storage and
// verification on top of [Encryptor].

// ValidPassword reports whether password matches the record's stored
// encrypted_password, faithful to valid_password?: it delegates to
// [Encryptor.Compare] with the config's pepper. A record without an
// encrypted_password never validates.
func (r *Record) ValidPassword(password string) bool {
	return Encryptor{}.Compare(r.getString(AttrEncryptedPassword), password, r.cfg.Pepper)
}

// SetPassword hashes new_password and stages it into encrypted_password,
// faithful to password=: a blank password is ignored (leaves the current hash
// untouched, as Devise does with "self.encrypted_password = ... if
// @password.present?"). It does not save; the caller persists, mirroring
// ActiveRecord.
func (r *Record) SetPassword(newPassword string) error {
	if newPassword == "" {
		return nil
	}
	digest, err := Encryptor{}.Digest(newPassword, r.cfg.Pepper, r.cfg.Stretches)
	if err != nil {
		return err
	}
	r.m.Set(AttrEncryptedPassword, digest)
	return nil
}

// AuthenticatableSalt returns the salt portion of the stored hash — its first 29
// characters — faithful to authenticatable_salt. It is "" when no password is
// set, and feeds Rememberable's cookie value and session invalidation.
func (r *Record) AuthenticatableSalt() string {
	h := r.getString(AttrEncryptedPassword)
	if len(h) < 29 {
		return h
	}
	return h[:29]
}
