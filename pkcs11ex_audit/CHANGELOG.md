# pkcs11ex_audit changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-05-08

### Documentation

These fixes landed in the `v0.1.0` git tag but **after** the Hex publish, so they only ship to Hex with `0.1.1`. No code or behavior change.

- **`t:Enumerable.t/0` callback typedoc syntax** in the `c:Pkcs11ex.Audit.Storage.all/1` callback docstring. The previous form was missing the `t:` prefix, so ExDoc treated it as a function reference and warned.
- **Dropped private-function reference** from the `Pkcs11ex.Audit.CanonicalEncoding` moduledoc. The format-versioning section pointed at a `defp`-private function name in `Pkcs11ex.Audit`, which ExDoc warned about as an unresolved link. Replaced with a prose reference to `Pkcs11ex.Audit` and the `@hash_format_version` module attribute.
- **README cross-package link** (`pkcs11ex` → `https://hex.pm/packages/pkcs11ex`) now resolves on hexdocs.pm. The previous `../` path didn't exist in a single-package tree.
- **`{:ex_doc, "~> 0.34", only: :dev, runtime: false}`** added as a dev dep so `mix hex.publish` can build the docs tarball. Not pulled into runtime by consumers.

## [0.1.0] — 2026-05-07

Initial release. Sister library to `pkcs11ex` for tamper-evident signature audit trails.

### Added — foundational modules

- **`Pkcs11ex.Audit`** — append-only hash-chained log. Each entry's content hash includes the previous entry's hash, making the chain self-verifying.
- **Storage adapters** via the `Pkcs11ex.Audit.Storage` behaviour. `Pkcs11ex.Audit.Storage.InMemory` ships built-in for tests; production storage (Postgres, etc.) is up to the consumer.
- **RFC 3161 anchoring** — `Pkcs11ex.Audit.anchor_head/3` POSTs the chain head's `content_hash` to a public Time-Stamping Authority, stores the returned TimeStampToken as a fresh entry. Auditors verify the TST against the TSA's certificate chain to bound when the chain reached that state.
- **`Pkcs11ex.Audit.Anchor.RFC3161.extract_token/1`** — strips PKIStatusInfo from a TimeStampResp and surfaces the bare TST. Used by the PAdES B-T / XAdES B-T attach paths in `sign_core`.
- **`Pkcs11ex.JWS.sign`'s `:audit_to` hook** (in `pkcs11ex`) gates on `Code.ensure_loaded?(Pkcs11ex.Audit)` at runtime, so consumers can omit `pkcs11ex_audit` from their deps and have the hook short-circuit silently.

### Added — canonical hash encoding

- **`Pkcs11ex.Audit.CanonicalEncoding`** — versioned canonical-bytes encoder for hash inputs. Format v1 is documented in the moduledoc; byte-level test vectors lock the format so any silent drift trips a failing test.

### Changed

- **Audit hash binding switched from `:erlang.term_to_binary/2` to `Pkcs11ex.Audit.CanonicalEncoding.encode_v1/1`.** External Term Format is not stable across Erlang/OTP releases — a routine OTP upgrade could re-encode the same logical term to different bytes, invalidating every previously stored `content_hash` and breaking `verify/1` for the entire chain. The replacement is a small, explicit, byte-level format under our control: tagged values, length-prefixed bytes, sorted-by-encoded-key map pairs. Format-version-tagged at the front (currently `1`) so future revisions can coexist with old chains. Pre-publish breaking change — any in-flight chain hashed under the old format must be re-anchored.
- **`Pkcs11ex.Audit.append/3` always truncates `inserted_at` to second precision**, even when the caller supplies it. The previous behavior only truncated the default (`DateTime.utc_now/0`); a caller-supplied DateTime with sub-second precision would round-trip lossy through any storage adapter that downcasts (Postgres `timestamp(0)`, SQLite without explicit microsecond storage), making `verify/1` fail with `:content_hash_mismatch` on otherwise-clean chains.
- **`Pkcs11ex.Audit.verify/1` returns `{:error, :empty_chain}` for an empty chain** instead of `:ok`. Callers can now distinguish "nothing to verify" from "everything verified clean" — important because database-wipe attacks reduce a populated chain to empty, and the previous silent `:ok` would obscure that. RFC 3161 anchoring (`anchor_head/3`) is the cross-cutting answer to truncation; this surfaces the truncation-shaped state at the verify primitive.
- **`Pkcs11ex.Audit.append/3` rejects payloads containing unsupported types** (floats, references, PIDs, ports, functions, non-DateTime structs) with `{:error, {:invalid_payload, reason}}`. The canonical encoder is strict about what's hashable; the rejection is at the API boundary rather than letting an `ArgumentError` escape.

### Tested against

- DigiCert (`http://timestamp.digicert.com`) — public free TSA. Live integration tests in `test/.../live_tsa_test.exs`, opt-in via `PKCS11EX_TSA_TESTS=1`.
