# pkcs11ex changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file tracks the **`pkcs11ex` Hex package** specifically. The sister packages (`sign_core`, `soft_signer`, `pkcs11ex_audit`) maintain their own changelogs in their respective directories.

## [Unreleased]

### Changed

- **Pinned `:rustler` to `~> 0.37.0`** (was `~> 0.36`). `Vec<u8>` encoding shape differs between 0.36 and 0.37; the loose constraint left the NIF return shape ABI-unstable, which had to be papered over with multi-shape return handling in `Pkcs11ex.sign_bytes/2` and `Pkcs11ex.Slot.Server`. Pin removes the ambiguity; redundant return-shape branches dropped.
- **Configurable `Pkcs11ex.Slot.Server` GenServer.call timeouts** — per-call `:call_timeout` opt and `:slot_call_timeout` application-env knob. Previously hardcoded at 30s for sign/verify/login/logout/status and 60s for `import_keypair`, which silently truncated long-running operations on slow cloud HSMs.
- **Protocol consolidation re-enabled in `:test`.** The fixture-only `JWSTestSigner` (with its `defimpl SignCore.Signer`) moved to `test/support/`, gated by `elixirc_paths(:test)`. Previously `consolidate_protocols: Mix.env() != :test` worked around the in-test `defimpl`; production and test now run with identical consolidation behavior.

## [0.1.0]

Initial Hex release. The repository hosts a family of packages from a single git tree (Phoenix-style monorepo); this changelog covers the `pkcs11ex` package — the PKCS#11 hardware provider.

### Added — Hex publish setup

- Conditional `:sign_core` and `:pkcs11ex_audit` deps: path during monorepo dev, Hex when consuming the published tarball.
- Tightened `package: files: …` whitelist to ship `lib/`, the Rust NIF source, specs, README, and CHANGELOG.

### Added — monorepo split

- `Pkcs11ex.Signer` struct — implements `SignCore.Signer` protocol. Supports both the slot-ref form (`%Pkcs11ex.Signer{slot_ref: :foo, key_ref: :bar}`) and the explicit-module form (`%Pkcs11ex.Signer{module: ..., slot_id: ..., key_label: ...}`).
- `Pkcs11ex.PDF`, `Pkcs11ex.XML`, `Pkcs11ex.JWS` — convenience wrappers around `SignCore.{PDF,XML,JWS}`. Translate the historical option ergonomics (`signer: {slot_ref, key_ref}`, `module:`/`slot_id:`/`key_label:`) into a `Pkcs11ex.Signer` struct that the format adapters dispatch on.
- `Pkcs11ex.X509` — backwards-compat alias for `SignCore.X509`.
- Format-adapter primitives (PDF Reader/Writer, CMS, XML/XAdES, X509, Policy, Algorithm) extracted into the new `sign_core` package — see `sign_core/CHANGELOG.md`.

### Added — Phase 5 (Compliance) complete

- B-T sign for PDF (`tsa_url:` opt) — attaches an RFC 3161 TimeStampToken as `id-aa-signatureTimeStampToken` in CMS `unsignedAttrs`.
- B-T sign for XML (`tsa_url:` opt) — attaches a `<xades:SignatureTimeStamp>` under `<xades:UnsignedSignatureProperties>` per ETSI EN 319 132-1 §5.4.1.
- `Pkcs11ex.Audit.Anchor.RFC3161.extract_token/1` — strips PKIStatusInfo from a TimeStampResp and surfaces the bare TST. Used by both PDF and XML B-T attach paths.
- Telemetry meta + error-class wiring for the new `{:bt_failed, …}` errors.

### Added — Phase 4 (Format Expansion) complete

- **PAdES B-B** — `Pkcs11ex.PDF.sign/2` and `verify/2`. Hand-rolled CMS encoder over OTP's `'CryptographicMessageSyntax-2009'` codec; minimal trailer/xref reader and incremental-update writer; no full PDF parser. PSS signature parameters (RSASSA-PSS-params) encoded canonically for OpenSSL / BouncyCastle compatibility.
- **XAdES B-B** — `Pkcs11ex.XML.sign/2` and `verify/2`. Exclusive XML Canonicalization 1.0 via vendored + patched `xmerl_c14n`; `<xades:SigningCertificateV2>` with RFC 5035 IssuerSerial.
- 6-step verify pipeline for both formats: locate, append-attack detection, parse, allowlist gate, message digest match, signature math.
- Conformance suite — `pdfsig` (Poppler) and `xmlsec1` (libxmlsec1) accept the output. Opt-in via `mix test --include conformance`.
- SafeNet eToken end-to-end test harness (`test/pkcs11ex/safenet/`). Validated against a real SafeNet Token JC with a self-generated RSA-2048 keypair under PSS-SHA-256.

### Added — Phase 3 (Cloud)

- `:cloud_hsm` slot type — login is a no-op (cloud auth via libkmsp11 / IAM, not PKCS#11 user PIN). `Slot.login/2` returns `{:error, :no_pin_required}`.
- `:driver_config` env-var passthrough — `KMS_PKCS11_CONFIG` set automatically for libkmsp11 drivers before `module_load`.
- `examples/gcp-cloud-hsm/` — runnable runtime.exs + kmsp11.yaml + README walkthrough (gcloud kms setup, Workload Identity Federation auth).

### Added — Phase 2 (Hybrid)

- Per-slot persistent session model (`parking_lot::Mutex<cryptoki::Session>` Rustler resource).
- `Pkcs11ex.SlotSupervisor` + `Pkcs11ex.Slot.Server` GenServer — round-robin session pool for cloud HSMs.
- `pin_callback` lifecycle (config-resolved MFA, PIN never enters GenServer state, Rust-side `Zeroizing<Vec<u8>>`).
- `:signer` resolution in `sign_bytes/2` and JWS.
- Inactivity timeout + `:reauthentication` policy (`:prompt` / `:fail`).
- `mix pkcs11ex.import_p12` task.

### Added — Phase 1 (PoC)

- Initial Mix project with Rustler bridge, OTP application scaffold, configuration files.
- `Pkcs11ex.Native` — Rust NIF over the `cryptoki` crate.
- `Pkcs11ex.sign_bytes/2` and `verify_bytes/4` Layer 2 primitives.
- `Pkcs11ex.JWS` — RFC 7797 detached JWS, PS256.
- `Pkcs11ex.Policy.PinnedRegistry` (default trust policy; SPKI pinning).
- `Pkcs11ex.PKCS12` read-only loader (openssl CLI backing).
- Specifications in `docs/specs/`: `specs.md` (architecture, threat model) and `api.md` (configuration, behaviours, surface, error taxonomy).
- Toolchain pins (`.tool-versions`): Elixir 1.19+, Erlang/OTP 28+, Rust 1.85+.
