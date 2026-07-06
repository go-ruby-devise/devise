// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package devise is a pure-Go (no cgo) reimplementation of the module logic of
// Ruby's [Devise] authentication framework, faithful to MRI Devise on Ruby
// 4.0.5.
//
// # Scope
//
// This is the v0.1 module-core foundation. It ports the behavioural heart of
// Devise's authentication modules — the credential, token, lock, remember,
// confirm and tracking state machines — as plain Go operating on an injectable
// model, together with the Warden strategy that drives database
// authentication. It deliberately has no dependency on a Ruby runtime and is a
// sibling of the other go-ruby-* stdlib/gem ports.
//
// Persistence (ActiveRecord), controllers, routes, views, mailers and the Rails
// engine are NOT reimplemented here — they are seams (see [Model], [Finder] and
// the notification callbacks on [Config]) or roadmap items. A later
// go-embedded-ruby binding wires those seams to the host.
//
// # Model seam
//
// Every module operates on a [Record] — a [Model] paired with a [Config]. The
// Model interface is the whole persistence surface Devise needs: read an
// attribute, write an attribute, and save. The host (ActiveRecord in Rails,
// go-embedded-ruby's object model under rbgo) supplies it. Class-level lookups
// (uniqueness, find-by-token, cookie deserialisation) go through the [Finder]
// seam on [Config].
//
// [Devise]: https://github.com/heartcombo/devise
package devise
