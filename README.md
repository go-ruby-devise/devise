<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-devise/brand/main/social/go-ruby-devise-devise.png" alt="go-ruby-devise/devise" width="720"></p>

# devise — go-ruby-devise

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-devise.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the module logic of Ruby's
[Devise](https://github.com/heartcombo/devise) authentication framework**, faithful
to MRI Devise on Ruby 4.0.5. It ports the behavioural heart of Devise's
authentication modules — the credential, token, lock, remember, confirm and
tracking state machines — as plain Go operating on an injectable model, together
with the [Warden](https://github.com/go-ruby-warden/warden) strategy that drives
database authentication. **No Ruby runtime required.**

It is designed to be the Devise backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby) under a later `rbgo`
binding, but is a **standalone, reusable** module. It reuses two sibling gem
ports as real dependencies:

- [`go-ruby-bcrypt/bcrypt`](https://github.com/go-ruby-bcrypt/bcrypt) — the
  password hashing under `Devise::Encryptor`.
- [`go-ruby-warden/warden`](https://github.com/go-ruby-warden/warden) — the
  `Warden::StrategyResult` the database strategy produces.

> **v0.1 — module cores.** This first release ships the *logic* of Devise's
> modules and the database Warden strategy. Persistence (ActiveRecord),
> controllers, routes, views, mailers and the Rails engine are **seams or
> roadmap** (see [Scope](#scope--roadmap)), because they are the host's job — a
> Rails app, or the rbgo binding, wires them in.

## The model & finder seams

Devise's modules are mixed into an ActiveRecord model. This library keeps that
shape but abstracts persistence behind two seams, so the same logic runs under
Rails, under rbgo, or against an in-memory table in tests:

```go
// A single authenticatable resource (a User row).
type Model interface {
    Get(attr string) any      // read a column by its Devise attribute name
    Set(attr string, val any) // stage a new value
    Save() error              // persist (Devise's save(validate: false))
}

// The class-level lookup (ActiveRecord's find_first / find_for_database_authentication).
type Finder func(attrs map[string]any) (Model, bool)
```

A [`Record`](model.go) binds a `Model` to a [`Config`](config.go) — the analogue
of an ActiveRecord instance whose `self.class` carries the Devise settings. Every
module method hangs off `*Record`; class-level flows (reset-by-token,
confirm-by-token, cookie deserialisation) hang off `*Config` and use its
`Finder`. Mailers are optional callbacks on `Config`
(`SendResetPasswordInstructions`, `SendConfirmationInstructions`,
`SendUnlockInstructions`).

## Install

```sh
go get github.com/go-ruby-devise/devise
```

## Usage

```go
cfg := devise.DefaultConfig()      // Devise's out-of-the-box defaults
cfg.Stretches = 12                 // bcrypt cost
cfg.Finder = myUserTableFinder     // wire persistence

// Database Authenticatable
r := devise.New(cfg, user)
_ = r.SetPassword("s3cret!!")      // password=  (hash + pepper + cost)
ok := r.ValidPassword("s3cret!!")  // valid_password?

// Recoverable
raw, _ := r.SendResetPasswordInstructions()          // returns the mailed token
rec, err := cfg.ResetPasswordByToken(raw, "new", "new")

// Warden strategy (database_authenticatable)
res := devise.DatabaseAuthenticatableStrategy{Cfg: cfg}.
    Run(map[string]any{"email": "a@b.co"}, "s3cret!!")
// res is a warden.StrategyResult: Success carries res.User.
```

## Modules shipped (v0.1)

| Devise module | Ported surface |
| --- | --- |
| **DatabaseAuthenticatable** | `valid_password?`, `password=`, `authenticatable_salt`, `Devise::Encryptor` (digest/compare via go-ruby-bcrypt) |
| **Validatable** | email presence/format/uniqueness, password presence/length/confirmation |
| **Recoverable** | `set_reset_password_token`, `send_reset_password_instructions`, `reset_password_by_token`, period validity |
| **Rememberable** | `remember_me!` / `forget_me!`, `rememberable_value`, `remember_expired?`, cookie serialise/deserialise |
| **Confirmable** | `generate_confirmation_token`, `confirm`, `confirmed?`, confirmation period valid/expired, `active_for_authentication?` |
| **Lockable** | `lock_access!` / `unlock_access!`, `failed_attempts`, `valid_for_authentication?` lock gate, `unlock_in` / `maximum_attempts`, unlock-by-token |
| **Trackable** | `update_tracked_fields` (sign-in count, current/last at + IP) |
| **Timeoutable** | `timedout?`, `timeout_in` |
| **Registerable** | `new_with_session`, `update_with_password`, `update_without_password`, `destroy_with_password` (the model-level sign-up/edit flows) |
| **Devise helpers** | `friendly_token`, `secure_compare`, `TokenGenerator` (HMAC-SHA256 digest over a byte-faithful PBKDF2 `KeyGenerator`), `email_regexp`, encryptor selection |
| **Warden strategies** | `Authenticatable` / `DatabaseAuthenticatable` on `warden.StrategyResult`, plus a `StrategyRun` seam |

## Scope & roadmap

**Deferred** (host/roadmap — not this release):

- The Rails **controllers, routes, views and helpers** (`SessionsController`,
  `RegistrationsController`, `PasswordsController`, ...) — the HTTP glue. The
  model-level flows they drive (sign in, register, edit, reset, confirm, unlock)
  are all here; a Rails app or the rbgo binding wires the request cycle.
- The Rails **engine, mailers and their templates** — only the notification
  **callbacks** are wired here (`SendResetPasswordInstructions`, ...).
- `Omniauthable` (OAuth), the Devise **generators** and **i18n**.

## Fidelity notes

The crypto and token surfaces are byte-faithful to Devise on MRI 4.0.5:

- **Passwords** flow through `go-ruby-bcrypt`, itself validated byte-for-byte
  against Ruby's `bcrypt` gem, so a hash produced here verifies under MRI Devise
  and vice-versa.
- **`friendly_token`** reproduces `SecureRandom.urlsafe_base64((n*3)/4)` with the
  `tr('lIO0', 'sxyz')` substitution — byte-identical output for identical entropy.
- **`secure_compare`** matches `ActiveSupport::SecurityUtils.secure_compare`
  (length check + constant-time comparison).
- **`TokenGenerator`** emits `OpenSSL::HMAC.hexdigest("SHA256", key_for(column),
  value)` digests. [`NewDeviseTokenGenerator(secret)`](token_generator.go)
  reproduces `Devise.token_generator` in full: the key is derived by a
  byte-faithful [`PBKDF2KeyGenerator`](token_generator.go) —
  `ActiveSupport::KeyGenerator` (PBKDF2-HMAC-SHA1, 2¹⁶ iterations, 64-byte key,
  salt `"Devise <column>"`) wrapped in a `CachingKeyGenerator`. Given the same
  `secret_key_base`, the stored reset/confirm/unlock digests are **byte-identical**
  to the gem's, so a raw token issued by either side verifies against a digest
  stored by the other. (A simpler zero-config `HMACKeyGenerator` remains the
  default for tests and non-Rails hosts.)

## Tests & coverage

100% line coverage, enforced in CI, across all module cores — password
valid/invalid, token generation + expiry, lock/unlock thresholds, remember
round-trip, confirm, register/edit/destroy, and the validatable rules —
exercised through fake `Model` / `Finder` seams, with bcrypt driven through
`go-ruby-bcrypt`. These deterministic tests keep coverage at 100% on their own.

**Differential oracle vs MRI.** On top of them, a set of oracle tests shell out
to real Ruby and assert byte-parity against the gem's own code paths:

- `oracle_ruby_test.go` needs only Ruby's stdlib (no gems): the
  reset/confirm/unlock **token digest** (PBKDF2-HMAC-SHA1 key → HMAC-SHA256) and
  `friendly_token`'s encoding, checked byte-for-byte and in both round-trip
  directions. These run on the CI lanes that install Ruby.
- `oracle_gem_test.go` drives `Devise::Encryptor`, `Devise::TokenGenerator` and
  `Devise.secure_compare` directly; it skip-gates when the `devise`/`bcrypt` gems
  are absent (run it locally with the gems on `GEM_PATH`).

The library cross-compiles and is tested on the six supported 64-bit
architectures (`amd64`, `arm64`, `riscv64`, `loong64`, `ppc64le`, `s390x` —
including big-endian s390x) and three operating systems.

```sh
go test -race -cover ./...
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-devise/devise authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
