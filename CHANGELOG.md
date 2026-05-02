# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project skeleton — Mix project with Rustler bridge, OTP application
  scaffold, configuration files, smoke-test for the NIF wiring.
- Toolchain pins (`.tool-versions`): Elixir 1.19.2-otp-28, Erlang 28.1.1,
  Rebar 3.25.0, Rust 1.95.0.
- Specifications in `docs/specs/`:
  - `specs.md` — architecture, layered design, threat model, roadmap, non-goals.
  - `api.md` — configuration schema, behaviours (`Algorithm`, `Format`, `Policy`),
    surface functions, verification algorithm, error taxonomy, telemetry, mix tasks.
