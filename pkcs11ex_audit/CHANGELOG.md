# pkcs11ex_audit changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release. Sister library to `pkcs11ex` for tamper-evident signature audit trails.

### Added

- **`Pkcs11ex.Audit`** — append-only hash-chained log. Each entry's content hash includes the previous entry's hash, making the chain self-verifying.
- **Storage adapters** via the `Pkcs11ex.Audit.Storage` behaviour. `Pkcs11ex.Audit.Storage.InMemory` ships built-in for tests; production storage (Postgres, etc.) is up to the consumer.
- **RFC 3161 anchoring** — `Pkcs11ex.Audit.anchor_head/3` POSTs the chain head's `content_hash` to a public Time-Stamping Authority, stores the returned TimeStampToken as a fresh entry. Auditors verify the TST against the TSA's certificate chain to bound when the chain reached that state.
- **`Pkcs11ex.Audit.Anchor.RFC3161.extract_token/1`** — strips PKIStatusInfo from a TimeStampResp and surfaces the bare TST. Used by the PAdES B-T / XAdES B-T attach paths in `sign_core`.
- **`Pkcs11ex.JWS.sign`'s `:audit_to` hook** (in `pkcs11ex`) gates on `Code.ensure_loaded?(Pkcs11ex.Audit)` at runtime, so consumers can omit `pkcs11ex_audit` from their deps and have the hook short-circuit silently.

### Tested against

- DigiCert (`http://timestamp.digicert.com`) — public free TSA. Live integration tests in `test/.../live_tsa_test.exs`, opt-in via `PKCS11EX_TSA_TESTS=1`.
