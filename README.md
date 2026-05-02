# pkcs11ex

Hardware-backed digital signatures for Elixir, via PKCS#11.

`pkcs11ex` is signing infrastructure for Elixir applications that need to produce or verify digital signatures with keys held in HSMs or hardware tokens. It ships first-class adapters for the formats real workflows use — JWS (RFC 7797), PDF (PAdES), and XML (XML-DSig / XAdES) — backed by a Rust/Rustler bridge over PKCS#11.

## Status

**Pre-release / spec-first.** The repository currently contains the canonical specifications and a runnable project skeleton. Phase 1 (PoC) implementation is in progress.

Specifications:

- [`docs/specs/specs.md`](docs/specs/specs.md) — architecture, threat model, layered design, roadmap.
- [`docs/specs/api.md`](docs/specs/api.md) — public Elixir API: configuration schema, behaviours, surface functions, error taxonomy, telemetry, mix tasks.

## How is this different from `p11ex`?

[`p11ex`](https://hex.pm/packages/p11ex) is a low-level PKCS#11 binding for Elixir (C NIF). `pkcs11ex` is the layer above: algorithm adapters, format adapters (JWS / PDF / XML), trust-policy framework, plug for Phoenix verification, audit hooks. Different layer; complementary scope.

| You need to… | Use… |
|---|---|
| Call `C_FindObjects` / `C_GetAttributeValue` directly | `p11ex` |
| "Sign this JWS payload with my HSM key" | `pkcs11ex` |
| Verify an incoming JWS / PDF / XML signature with allowlist-based trust | `pkcs11ex` |
| Software signing from a `.p12` file | `:public_key` (OTP stdlib) or `jose` |

## Layered design

```
┌───────────────────────────────────────────────────────────────────┐
│  Layer 3 — Format adapters                                        │
│  Pkcs11ex.JWS    Pkcs11ex.PDF   Pkcs11ex.XML   Pkcs11ex.JWS.Plug  │
├───────────────────────────────────────────────────────────────────┤
│  Layer 2 — Signing primitives                                     │
│  sign_bytes / verify_bytes / digest / digest_stream               │
│  Algorithm adapters: PS256 (default), RS256, ES256, EdDSA future  │
├───────────────────────────────────────────────────────────────────┤
│  Layer 1 — PKCS#11 bridge (Elixir + Rustler)                      │
│  Slot/session model, dynamic driver loading, PIN handling         │
└───────────────────────────────────────────────────────────────────┘
```

## Tooling

This repo pins toolchain versions in [`.tool-versions`](.tool-versions) for `asdf` / `mise`:

- Elixir 1.19.2 (OTP 28)
- Erlang/OTP 28.1.1
- Rebar 3.25.0
- Rust 1.95.0 (any 1.85+ with edition 2021 will compile)

Quick start once dependencies are installed:

```sh
mix deps.get
mix compile          # builds the Rust crate via Rustler
mix test             # smoke-tests the NIF wiring
```

## Trust model — read this before you ship anything

`pkcs11ex` treats sender-supplied certificates (the `x5c` header in JWS, `SignerIdentifier` in CMS, `KeyInfo` in XAdES) as **untrusted input**. A signature is accepted only if the sender's identity (typically the SPKI SHA-256 of the leaf certificate) matches an entry in an allowlist the verifier maintains. There is no path through the library that trusts a sender solely because their certificate chains to a CA.

See [`docs/specs/specs.md`](docs/specs/specs.md) §7.1 and [`docs/specs/api.md`](docs/specs/api.md) §2.3 for the canonical verification algorithm and trust-policy contract.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
