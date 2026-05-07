# pkcs11ex

Digital signatures for Elixir — PDF (PAdES), XML (XAdES), and JWS — with pluggable signers backed by HSMs, smart-card tokens, or software keys.

This repository hosts a family of Hex packages designed to compose. Pick the ones that match your deployment and ignore the rest:

| Package | Purpose | When to depend on it |
|---|---|---|
| [**`sign_core`**](sign_core/) | Signer-agnostic format primitives — PDF Reader/Writer, CMS, XML/XAdES, X509, Policy, Algorithm, the `SignCore.Signer` protocol. | Always. Every other package depends on it. **Verify-only fleet members can depend on this alone** — no NIF, no openssl shellout. |
| [**`pkcs11ex`**](.) | PKCS#11 hardware provider — slot supervisor, session pool, PIN handling, NIF over `cryptoki`. Ships `Pkcs11ex.Signer` (impl of `SignCore.Signer`) plus convenience wrappers around `SignCore.{PDF,XML,JWS}`. | Hardware tokens (SafeNet eToken, Luna), cloud HSMs (GCP Cloud HSM, libkmsp11), SoftHSM2 in dev/CI. |
| [**`soft_signer`**](soft_signer/) | Software-key provider — `SoftSigner.PKCS12` for `.p12`/`.pfx` bundles, `SoftSigner.PKCS8` for PEM private keys (encrypted or not) plus separate cert. | Filesystem-resident keys: vendor-issued PKCS#12 bundles, classic key.pem + cert.pem deployments, dev/test fixtures. |
| [**`pkcs11ex_audit`**](pkcs11ex_audit/) | Optional audit-trail sister library — append-only hash-chained entries with RFC 3161 timestamp anchoring. | Compliance-driven workflows that need provable signature provenance over time. |

The packages are released independently to Hex but live in one git tree (Phoenix-style monorepo). Cross-cutting changes ship as a single PR; consumers only depend on the packages they use.

## Quick start

### "I need to sign PDFs with our SafeNet eToken"

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

See [`examples/safenet-etoken/`](examples/safenet-etoken/) for a runnable demo against a real eToken.

### "We have a vendor-issued PKCS#12 bundle"

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

### "Our private key is a PEM, the cert is a separate file"

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

### "I just need to verify signed PDFs/XMLs"

```elixir
# mix.exs — minimal verify-only dep tree
def deps, do: [
  {:sign_core, "~> 1.0"}    # no NIF, no openssl, no providers
]
```

```elixir
{:ok, _subject_id} = SignCore.PDF.verify(signed_pdf)
{:ok, _subject_id} = SignCore.XML.verify(signed_xml)
{:ok, _subject_id} = SignCore.JWS.verify(jws, payload)
```

## Architectural principles

### Signer abstraction

The `SignCore.Signer` protocol is the seam between format adapters (PDF/XML/JWS) and signature sources (HSM/PKCS#12/PKCS#8/cloud KMS). Every provider ships a struct that implements the protocol:

```elixir
%Pkcs11ex.Signer{slot_ref: :foo, key_ref: :bar}        # PKCS#11 hardware
%SoftSigner.PKCS12{rsa_key: ..., leaf_der: ..., ...}    # PKCS#12 software
%SoftSigner.PKCS8{rsa_key: ..., leaf_der: ..., ...}     # PKCS#8 PEM software

# All three drop into the same call:
SignCore.PDF.sign(pdf, signer: any_of_the_above, alg: :PS256, ...)
```

Adding a new provider (cloud KMS, smart-card via PC/SC, etc.) is a struct + a `defimpl SignCore.Signer` block — no changes to the format adapters.

### Trust model

Sender-supplied certificates (the `x5c` header in JWS, `SignerIdentifier` in CMS, `KeyInfo` in XAdES) are **untrusted input**. A signature is accepted only after `Pkcs11ex.Policy` resolves the sender against an allowlist (typically the SPKI SHA-256 of the leaf certificate). There's no path through the library that trusts a sender solely because their certificate chains to a CA.

The allowlist gate runs **before** any signature math — see `SignCore.PDF.verify/2`'s pipeline or the canonical algorithm in [`docs/specs/specs.md`](docs/specs/specs.md) §7.1.

### Layer-bounded auditability

Each package ships a deliberate slice of capability:

- A deployment that depends on **`pkcs11ex` only** can never software-sign — `Pkcs11ex.Signer` only knows how to call the NIF. The "no software signing" invariant is enforced by the absence of `soft_signer` in the dep tree.
- A deployment that depends on **`soft_signer` only** has no NIF compilation step and ships no PKCS#11 code.
- A deployment that depends on **`sign_core` only** is verify-only — no signing capability of any kind, by package boundary.

This is the audit-confidence story: which capabilities exist in a given build is determined by `mix.lock`, not runtime configuration.

## Layered design within the providers

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

## Specifications

The full canonical surface is documented in:

- [`docs/specs/specs.md`](docs/specs/specs.md) — architecture, threat model, layered design, roadmap.
- [`docs/specs/api.md`](docs/specs/api.md) — public API: configuration, behaviours, surface functions, error taxonomy, telemetry, Mix tasks.

## How is this different from `p11ex`?

[`p11ex`](https://hex.pm/packages/p11ex) is a low-level PKCS#11 binding for Elixir (C NIF). `pkcs11ex` is the layer above: format adapters, trust-policy framework, slot supervisor, audit hooks. `p11ex` is "I want to call cryptoki primitives directly"; `pkcs11ex` is "I want to sign a PDF and have the plumbing handled."

`pkcs11ex` does NOT depend on `p11ex`. They're siblings at different abstraction levels.

## Compatibility

`pkcs11ex` itself ships its own NIF (Rust + Rustler over the `cryptoki` crate), separate from `p11ex`'s C NIF. Coexistence in one BEAM is supported but rarely useful.

The XML adapter ([`sign_core/lib/sign_core/xml/c14n/`](sign_core/lib/sign_core/xml/c14n/)) vendors a patched copy of `xmerl_c14n` (BSD-2) — the upstream Hex package crashes on OTP 28's xmerl record shapes. See that file's moduledoc for the patch and the rationale for not pulling in a Rust C14N library yet.

## Tooling

Toolchain versions are pinned in [`.tool-versions`](.tool-versions) for `asdf` / `mise`:

- Elixir 1.19+
- Erlang/OTP 28+
- Rust 1.85+ (edition 2021)

```sh
mix deps.get
mix compile           # builds the Rust crate via Rustler
mix test              # 307+ tests, no SoftHSM/eToken/conformance dependencies
```

Optional test layers:

```sh
# SoftHSM2 + softhsm2-util on PATH
mix test --include softhsm

# Real SafeNet eToken + driver at /Library/Frameworks/eToken.framework/...
PKCS11EX_SAFENET_PIN=... PKCS11EX_SAFENET_KEY_LABEL=... \
  mix test --include safenet

# Standards-compliant external verifier conformance
brew install poppler libxmlsec1
mix test --include conformance

# All of the above + RFC 3161 TSA round-trip
mix test --include conformance --include safenet
```

## License

Apache 2.0 — see [`LICENSE`](LICENSE). Vendored `xmerl_c14n` retains its original BSD-2-Clause license; see [`sign_core/lib/sign_core/xml/c14n/LICENSE.md`](sign_core/lib/sign_core/xml/c14n/LICENSE.md).
