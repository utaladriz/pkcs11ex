# pkcs11ex

> Production-grade digital signatures for Elixir — **PDF (PAdES B-B / B-T)**, **XML (XAdES B-B / B-T)**, and **JWS (RFC 7797)** — backed by HSMs, smart-card tokens, or software keys.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-1.19%2B-purple.svg)](https://elixir-lang.org)
[![OTP](https://img.shields.io/badge/OTP-28%2B-red.svg)](https://www.erlang.org)

This repository hosts a family of Hex packages that compose into a single signing toolkit. Pick the ones that match your deployment and ignore the rest.

---

**Validated end-to-end against:**
- ✅ SafeNet eToken (USB hardware token)
- ✅ SoftHSM2 (CI / dev fixtures)
- ✅ GCP Cloud HSM via libkmsp11
- ✅ PKCS#12 software bundles + PKCS#8 PEM private keys
- ✅ Poppler `pdfsig` and libxmlsec1 `xmlsec1` standards conformance
- ✅ DigiCert RFC 3161 TSA (B-T timestamps)

---

## Table of contents

- [Why pkcs11ex?](#why-pkcs11ex)
- [Packages](#packages)
- [Quick start](#quick-start)
- [Trust model — read this before you ship](#trust-model)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Versioning & stability](#versioning--stability)
- [Compatibility](#compatibility)
- [Examples](#examples)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Why pkcs11ex?

Real production signing workflows tend to span more than one signature source. A typical fintech / regulated-industry deployment might:

- Sign **legal-compliance PDFs** with an HSM-resident corporate key.
- Sign **invoices for a tax authority** (e.g., Chilean SII, Spanish FNMT) with a vendor-issued **PKCS#12 bundle**.
- Verify **inbound JWS payloads** from partners, with a strict allowlist of who may sign.
- Cryptographically anchor an **audit trail** with RFC 3161 timestamps from a public TSA.

`pkcs11ex` ships all four paths through one cohesive toolkit. The signature-source abstraction (`SignCore.Signer`) means the same `SignCore.PDF.sign(pdf, signer: ...)` call works whether the signer is a hardware token, a P12 file, a PEM key, or a future cloud KMS provider you write yourself.

It's designed for engineers who need to ship signed artifacts that **external standards-compliant verifiers will accept** — not just our own pipelines. Every release is gated on a conformance suite that runs the output through Poppler `pdfsig` and libxmlsec `xmlsec1`.

## Packages

| Package | Purpose | Hex deps to use |
|---|---|---|
| [**`sign_core`**](sign_core/) | Signer-agnostic format primitives — PDF Reader/Writer, CMS, XML/XAdES, X509, Policy, Algorithm, the `SignCore.Signer` protocol. The format adapters (PDF/XML/JWS) live here. | Always (transitively pulled by the providers below). Stand-alone for **verify-only** deployments. |
| [**`pkcs11ex`**](.) | PKCS#11 hardware provider — slot supervisor, session pool, PIN handling, NIF over `cryptoki`. Ships `Pkcs11ex.Signer` plus convenience wrappers around `SignCore.{PDF,XML,JWS}`. | Hardware tokens (SafeNet eToken, Luna), cloud HSMs (GCP Cloud HSM, libkmsp11), SoftHSM2. |
| [**`soft_signer`**](soft_signer/) | Software-key provider — `SoftSigner.PKCS12` for `.p12`/`.pfx` bundles, `SoftSigner.PKCS8` for PEM private keys (encrypted or not) plus separate cert. | Filesystem-resident keys: vendor-issued PKCS#12, classic key.pem + cert.pem deployments, dev/test fixtures. |
| [**`pkcs11ex_audit`**](pkcs11ex_audit/) | Optional audit-trail sister library — append-only hash-chained entries with RFC 3161 timestamp anchoring. | Compliance-driven workflows that need provable signature provenance over time. |

The packages are released independently to Hex but live in one git tree (Phoenix-style monorepo). Cross-cutting changes ship as a single PR; consumers only depend on what they need.

## Quick start

### Sign a PDF with a hardware token

```elixir
# mix.exs
def deps, do: [
  {:pkcs11ex, "~> 1.0"}    # transitively pulls sign_core
]
```

```elixir
{:ok, signed_pdf} =
  Pkcs11ex.PDF.sign(pdf_bytes,
    signer: {:legal_proxy, :signing},   # slot supervisor reference
    alg: :PS256,
    x5c: leaf_cert_der,
    pin: "..."                          # or use a :pin_callback
  )

{:ok, _subject_id} = Pkcs11ex.PDF.verify(signed_pdf)
```

[Runnable demo against a real SafeNet eToken →](examples/safenet-etoken/)

### Sign a PDF with a PKCS#12 bundle

```elixir
# mix.exs
def deps, do: [
  {:soft_signer, "~> 1.0"}    # transitively pulls sign_core
]
```

```elixir
{:ok, signer} = SoftSigner.PKCS12.load("invoice-signer.p12", password: "...")

{:ok, signed_pdf} =
  SignCore.PDF.sign(pdf_bytes,
    signer: signer,
    alg: :PS256,
    x5c: SoftSigner.PKCS12.cert_chain(signer)   # chain comes for free with P12
  )
```

### Sign a PDF with a PKCS#8 PEM (key + separate cert)

```elixir
{:ok, signer} =
  SoftSigner.PKCS8.load(
    key_path: "/keys/legal-proxy.pem",
    cert_path: "/keys/legal-proxy.crt",
    password: "..."   # only if the PEM is encrypted
  )

{:ok, signed_pdf} =
  SignCore.PDF.sign(pdf,
    signer: signer,
    alg: :PS256,
    x5c: SoftSigner.PKCS8.cert_chain(signer)
  )
```

### Sign XML (XAdES B-B)

```elixir
{:ok, signer} = SoftSigner.PKCS12.load("signer.p12", password: "...")

{:ok, signed_xml} =
  SignCore.XML.sign(xml_doc,
    signer: signer,
    alg: :PS256,
    x5c: SoftSigner.PKCS12.cert_chain(signer)
  )
```

### Add an RFC 3161 timestamp (B-T)

```elixir
{:ok, signed_pdf} =
  Pkcs11ex.PDF.sign(pdf,
    signer: {:legal_proxy, :signing},
    alg: :PS256,
    x5c: leaf_cert_der,
    tsa_url: "http://timestamp.digicert.com",
    tsa_timeout: 15_000,
    placeholder_size: 16_384   # B-T pushes signature size over the default
  )
```

Same pattern works for `SignCore.XML.sign/2`. The timestamp is fetched from the TSA, anchored to the signature, and embedded in `unsignedAttrs` (PAdES) or `<xades:UnsignedSignatureProperties>` (XAdES).

### Verify-only deployment (no signer code shipped at all)

```elixir
# mix.exs
def deps, do: [
  {:sign_core, "~> 1.0"}    # no NIF, no openssl, no providers
]
```

```elixir
{:ok, _subject_id} = SignCore.PDF.verify(signed_pdf)
{:ok, _subject_id} = SignCore.XML.verify(signed_xml)
{:ok, _subject_id} = SignCore.JWS.verify(jws, payload)
```

## Trust model

`pkcs11ex` treats sender-supplied certificates (the `x5c` header in JWS, `SignerIdentifier` in CMS, `KeyInfo` in XAdES) as **untrusted input**.

A signature is accepted only after the configured `Pkcs11ex.Policy` resolves the sender against an allowlist (typically the SHA-256 of the leaf certificate's `SubjectPublicKeyInfo`). There is **no path** through this library that trusts a sender solely because their certificate chains to a CA.

Concretely, every verify operation runs:

1. **Locate** the embedded signature + cert chain.
2. **Append-attack detection** (PDF only) — refuse if bytes exist beyond the signed range.
3. **Parse** the CMS / XML signature envelope.
4. **Allowlist gate** — `policy.resolve/2` then `policy.validate/3`. *No cryptographic check has happened yet.*
5. **Recompute the message digest** and compare against the embedded value.
6. **Verify the signature math** via `:public_key.verify/4`.

Steps 1–4 short-circuit before any expensive math. An attacker can't push verify into a CPU oracle by submitting crafted inputs.

See [`docs/specs/specs.md`](docs/specs/specs.md) §7.1 for the canonical algorithm and [`docs/specs/api.md`](docs/specs/api.md) §2.3 for the policy contract.

## Architecture

### Signer abstraction

The `SignCore.Signer` protocol is the seam between format adapters (PDF/XML/JWS) and signature sources (HSM/PKCS#12/PKCS#8/cloud KMS). Every provider ships a struct that implements the protocol:

```elixir
%Pkcs11ex.Signer{slot_ref: :foo, key_ref: :bar}        # PKCS#11 hardware
%SoftSigner.PKCS12{rsa_key: ..., leaf_der: ..., ...}    # PKCS#12 software
%SoftSigner.PKCS8{rsa_key: ..., leaf_der: ..., ...}     # PKCS#8 PEM software

# All three drop into the same call:
SignCore.PDF.sign(pdf, signer: any_of_the_above, alg: :PS256, ...)
```

Adding a new provider is a struct + a `defimpl SignCore.Signer` block — no changes to the format adapters. See [`sign_core/README.md`](sign_core/README.md#implementing-a-custom-signer) for a worked example.

### Layer-bounded auditability

Each package ships a deliberate slice of capability:

- **`pkcs11ex` only** in your dep tree → can never software-sign. `Pkcs11ex.Signer` only knows how to call the NIF; the absence of `soft_signer` enforces the "no software signing" invariant at the package boundary.
- **`soft_signer` only** → no NIF compilation step, no PKCS#11 stack, no slot supervisor.
- **`sign_core` only** → verify-only by package boundary.

This is the audit-confidence story: which capabilities exist in a build is determined by `mix.lock`, not runtime configuration.

### Layered design

```
┌───────────────────────────────────────────────────────────────────┐
│  sign_core                                                        │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  Layer 3 — Format adapters                                  │  │
│  │  SignCore.{PDF,XML,JWS}.{sign,verify}                       │  │
│  │  Take a `:signer` opt — provider-agnostic.                  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  CMS / XAdES / x5c machinery                                │  │
│  │  Reader, Writer, Builder, Canonicalizer, X509, Policy       │  │
│  └─────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  SignCore.Signer protocol                                   │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
        ↑                              ↑                    ↑
        │                              │                    │
┌───────┴────────────┐  ┌──────────────┴──────────┐  ┌──────┴───────┐
│  pkcs11ex          │  │  soft_signer            │  │  (your KMS,  │
│  Layer 2: sign_b…  │  │  PKCS12 / PKCS8 loaders │  │   PC/SC, …)  │
│  Layer 1: NIF /    │  │  :public_key.sign/3     │  │              │
│  Slot.Server …     │  │  via openssl decrypt    │  │              │
└────────────────────┘  └─────────────────────────┘  └──────────────┘
```

## Documentation

- [`docs/specs/specs.md`](docs/specs/specs.md) — architecture, threat model, layered design.
- [`docs/specs/api.md`](docs/specs/api.md) — public API: configuration, behaviours, surface functions, error taxonomy, telemetry, Mix tasks.
- [`sign_core/README.md`](sign_core/README.md) — verify-only deployments, signer protocol, custom signer walkthrough.
- [`soft_signer/README.md`](soft_signer/README.md) — PKCS#12 vs PKCS#8 ergonomics, error taxonomy.
- [`pkcs11ex_audit/README.md`](pkcs11ex_audit/README.md) — append-only audit log + RFC 3161 anchoring.
- [`examples/`](examples/) — runnable demos.

## Versioning & stability

`pkcs11ex` is **pre-1.0** and currently path-deps inside the monorepo. Hex publishing for `sign_core` and `soft_signer` is on the roadmap. The public API surfaces documented in [`docs/specs/api.md`](docs/specs/api.md) — `SignCore.{PDF,XML,JWS}.{sign,verify}`, `SignCore.Signer`, `Pkcs11ex.{PDF,XML,JWS}` wrappers, `SoftSigner.{PKCS12,PKCS8}.load/2` — are stable in shape and the test suite holds the contract steady. Internal modules (the Reader/Writer mechanics, CMS encoding, exc-c14n shim) may evolve more freely until the 1.0 cut.

When `1.0` ships, semantic versioning applies to the public API as documented in `api.md`.

## Compatibility

- **Elixir 1.19+** / **Erlang/OTP 28+**. Older versions may work but aren't tested.
- **Rust 1.85+** with edition 2021 — required to build the `pkcs11ex` NIF (over the `cryptoki` crate).
- **macOS / Linux**. Windows isn't tested but the cryptoki dependency supports it.

`pkcs11ex` ships its own NIF (Rust + Rustler) — separate from [`p11ex`](https://hex.pm/packages/p11ex)'s C NIF. They're sibling libraries at different abstraction levels: `p11ex` is "I want to call `C_FindObjects` directly", `pkcs11ex` is "I want to sign a PDF and have the plumbing handled." Coexistence in one BEAM is supported.

The XML adapter ([`sign_core/lib/sign_core/xml/c14n/`](sign_core/lib/sign_core/xml/c14n/)) vendors a patched copy of `xmerl_c14n` (BSD-2-Clause) — the upstream Hex package crashes on OTP 28's `xmlAttribute` record shapes for unprefixed attributes without a default namespace. The patch is a single `do_canonical_name/3` clause documented inline.

## Examples

- [`examples/safenet-etoken/`](examples/safenet-etoken/) — sign a PDF with a real SafeNet eToken; cross-verify with `pdfsig`.
- [`examples/gcp-cloud-hsm/`](examples/gcp-cloud-hsm/) — `runtime.exs` + `kmsp11.yaml` for GCP Cloud HSM via libkmsp11.

## Testing

```sh
mix deps.get
mix compile           # builds the Rust crate via Rustler
mix test              # 307+ tests, no SoftHSM/eToken/conformance dependencies
```

Optional test layers, all opt-in:

```sh
# SoftHSM2 + softhsm2-util on PATH
mix test --include softhsm

# Real SafeNet eToken plugged in (driver auto-detected on macOS)
PKCS11EX_SAFENET_PIN=... PKCS11EX_SAFENET_KEY_LABEL=... \
  mix test --include safenet

# Standards-compliant external verifier conformance (pdfsig, xmlsec1)
brew install poppler libxmlsec1
mix test --include conformance

# All of the above + RFC 3161 TSA round-trip against DigiCert
mix test --include conformance --include safenet
```

The maximum-coverage run executes 329 tests in ~20s.

## Contributing

Contributions are welcome. Some areas where help is especially useful:

- **More signers.** Cloud KMS providers (AWS KMS, Azure Key Vault), PC/SC smart-card readers, hardware wallets — drop in beside `pkcs11ex` and `soft_signer` as new sister libraries depending on `sign_core`.
- **More algorithms.** ECDSA (`:ES256` / `:ES384`) and Ed25519 (`:EdDSA`) algorithm adapters in `SignCore.Algorithm`. The behaviour is small (~40 LOC for PS256); the format adapters are already algorithm-agnostic.
- **Conformance corpus.** The W3C exc-c14n test suite and the ETSI XAdES test corpus aren't yet wired into our `:conformance` suite. PRs welcome.
- **Docs.** Especially worked examples for less-common deployments (kubernetes secret-mounted PEMs, AWS Secrets Manager, etc.).

For non-trivial features, please open an issue first to discuss approach. Architectural changes need to fit the trust-model invariants documented in [`docs/specs/specs.md`](docs/specs/specs.md) §7.

## Acknowledgements

- The Rust [`cryptoki`](https://crates.io/crates/cryptoki) crate maintainers for the high-level PKCS#11 binding our NIF wraps.
- Chris Doggett and the [esaml](https://github.com/arekinath/esaml) authors for the original `xmerl_c14n` we vendored and patched for OTP 28.
- The [`X509`](https://hex.pm/packages/x509) hex package authors for the certificate-building primitives that made the test suite possible.
- The Poppler and libxmlsec1 teams for the standards-compliant external verifiers we use as conformance gates.

## License

[Apache 2.0](LICENSE).

Vendored `xmerl_c14n` retains its original [BSD-2-Clause license](sign_core/lib/sign_core/xml/c14n/LICENSE.md).
