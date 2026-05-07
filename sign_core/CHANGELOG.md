# sign_core changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release. Extracted from the `pkcs11ex` monorepo.

### Added

- **`SignCore.Signer`** protocol — pluggable signer abstraction. Implementations carry whatever state is needed to produce a raw signature over arbitrary bytes (a PKCS#11 slot reference, a loaded PKCS#12 bundle, a cloud KMS handle, etc.). The format adapters dispatch via this protocol and don't know about specific provider types.
- **`SignCore.PDF`** — PAdES B-B and B-T sign + verify. 6-step verify pipeline with allowlist-before-math gate, append-attack detection (`:incremental_update_after_signature`), `messageDigest` / signature math checks. Hand-rolled CMS encoder over OTP's `'CryptographicMessageSyntax-2009'` codec.
- **`SignCore.XML`** — XAdES B-B and B-T sign + verify on top of W3C XML-DSig. Exclusive XML Canonicalization 1.0; `<xades:SigningCertificateV2>` with RFC 5035 IssuerSerial; XAdES `<UnsignedSignatureProperties>` for B-T timestamps. Vendored + patched copy of `xmerl_c14n` (BSD-2) at `lib/sign_core/xml/c14n/` — the upstream Hex package crashes on OTP 28's `xmlAttribute` shapes for unprefixed attributes; the patch is a single fallback clause in `do_canonical_name/3`, documented inline.
- **`SignCore.JWS`** — RFC 7797 detached JWS sign + verify with `b64: false`, `crit: ["b64"]`, and `x5c` headers.
- **`SignCore.CMS`** — RFC 5652 CMS / SignedData encoding (used by PDF). `SignedAttributes`, `SignedData` (with parser), `UnsignedAttributes` (for B-T `id-aa-signatureTimeStampToken`), `Codec`, `OIDs`, `Parsed` struct.
- **`SignCore.X509`** — thin wrapper around OTP's `:public_key`-decoded X.509 certificates. `from_der/1` + `spki_sha256/1` for SHA-256 SPKI pinning.
- **`SignCore.Policy`** — pluggable trust policy behaviour. `SignCore.Policy.Allow` (test-only) and `SignCore.Policy.PinnedRegistry` (default — SPKI-pinned allowlist).
- **`SignCore.Algorithm`** — algorithm-adapter behaviour with `SignCore.Algorithm.PS256` (RSASSA-PSS / SHA-256 / MGF1-SHA-256 / sLen=32).
- **Telemetry events** — `[:pkcs11ex, :sign | :verify, :start | :stop | :exception]` with `:format`, `:alg`, `:encoding_context`, `:signer`, `:byte_count`, and on success `:subject_id` metadata.

### Conformance

The shipped output validates under standards-compliant external verifiers:

- Poppler `pdfsig` accepts B-B + B-T PDFs.
- libxmlsec1 `xmlsec1 --verify` accepts B-B + B-T XML.

### Architectural invariants

- **No software signing in this package.** `sign_core` builds the bytes-to-be-signed and assembles the output, but never produces a signature. That's the signer's job.
- **Allowlist before math.** Every verify path resolves the sender's certificate against `SignCore.Policy` before doing any cryptographic verification.
- **Append-attack detection.** PAdES verify checks `c + d == byte_size(pdf)` before parsing the CMS — bytes appended after the signed range are refused.
