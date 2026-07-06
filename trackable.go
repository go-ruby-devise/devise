// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

// --- Trackable module ---
//
// Ports Devise::Models::Trackable: recording sign-in counts, timestamps and IPs.

// UpdateTrackedFields records a sign-in, faithful to update_tracked_fields: it
// shifts current_sign_in_at into last_sign_in_at (seeding last from current on
// the first sign-in), sets current_sign_in_at to now, does the same for the IP
// pair with remoteIP, and increments sign_in_count. It stages the changes
// without saving, exactly like Devise (the caller saves via
// [Record.UpdateTrackedFieldsAndSave] or its own save).
func (r *Record) UpdateTrackedFields(remoteIP string) {
	now := r.cfg.now()

	oldCurrent, ok := r.getTime(AttrCurrentSignInAt)
	if ok {
		r.m.Set(AttrLastSignInAt, oldCurrent)
	} else {
		r.m.Set(AttrLastSignInAt, now)
	}
	r.m.Set(AttrCurrentSignInAt, now)

	oldIP := r.getString(AttrCurrentSignInIP)
	if oldIP != "" {
		r.m.Set(AttrLastSignInIP, oldIP)
	} else {
		r.m.Set(AttrLastSignInIP, remoteIP)
	}
	r.m.Set(AttrCurrentSignInIP, remoteIP)

	r.m.Set(AttrSignInCount, r.getInt(AttrSignInCount)+1)
}

// UpdateTrackedFieldsAndSave records a sign-in and persists it, faithful to
// update_tracked_fields! (save(validate: false)).
func (r *Record) UpdateTrackedFieldsAndSave(remoteIP string) error {
	r.UpdateTrackedFields(remoteIP)
	return r.m.Save()
}

// SignInCount returns the number of recorded sign-ins (sign_in_count).
func (r *Record) SignInCount() int { return r.getInt(AttrSignInCount) }
