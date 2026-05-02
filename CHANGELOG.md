# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 4 (Format Expansion, partial)
- `Pkcs11ex.PDF` skeleton — public API surface (`sign/2`, `verify/2`) reserved
  per `api.md` §3.3. Returns `{:error, :not_implemented_in_v1}`. Module
  documents the implementation blockers (CMS SignedData construction + PDF
  byte-range manipulation). PAdES B-T / B-LT / B-LTA out of scope per §10.
- `Pkcs11ex.XML` skeleton — same shape per `api.md` §3.4. Implementation
  blocker is C14N (no Elixir-native impl exists); will likely wrap libxmlsec
  via Rustler.

### Added — Phase 3 (Cloud)
- `:cloud_hsm` slot type — login is a no-op (cloud auth via libkmsp11 / IAM,
  not PKCS#11 user PIN). `Slot.login/2` returns `{:error, :no_pin_required}`.
- `:driver_config` env-var passthrough — `KMS_PKCS11_CONFIG` set automatically
  for libkmsp11 drivers before `module_load`.
- `examples/gcp-cloud-hsm/` — runnable runtime.exs + kmsp11.yaml + README
  walkthrough (gcloud kms setup, Workload Identity Federation auth).

### Added — Phase 2 (Hybrid)
- Per-slot persistent session model (`parking_lot::Mutex<cryptoki::Session>`
  Rustler resource; single-session-pinned for token slots).
- `Pkcs11ex.SlotSupervisor` + `Pkcs11ex.Slot.Server` GenServer.
- `pin_callback` lifecycle (config-resolved MFA, PIN never enters GenServer
  state, Rust-side `Zeroizing<Vec<u8>>`).
- `:signer` resolution in `sign_bytes/2` and JWS.
- Inactivity timeout + `:reauthentication` policy (`:prompt` / `:fail`).
- `mix pkcs11ex.import_p12` task.

### Added — Phase 1 (PoC)
- Initial project skeleton — Mix project with Rustler bridge, OTP application
  scaffold, configuration files, smoke-test for the NIF wiring.
- Toolchain pins (`.tool-versions`): Elixir 1.19.2-otp-28, Erlang 28.1.1,
  Rebar 3.25.0, Rust 1.95.0.
- Specifications in `docs/specs/`:
  - `specs.md` — architecture, layered design, threat model, roadmap, non-goals.
  - `api.md` — configuration schema, behaviours (`Algorithm`, `Format`, `Policy`),
    surface functions, verification algorithm, error taxonomy, telemetry, mix tasks.
- End-to-end JWS-detached signing path: PS256 + SoftHSM2 round trip.
- `Pkcs11ex.Policy.PinnedRegistry` (default trust policy; SPKI pinning).
- `Pkcs11ex.PKCS12` read-only loader (openssl CLI backing).
