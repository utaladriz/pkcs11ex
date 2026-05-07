# sign_core changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`SignCore.JWS.sign/2` `:attached` opt** — produce attached JWS (RFC 7515 form: `<header>.<payload_b64>.<sig>`) instead of the default detached (RFC 7797 form: `<header>..<sig>`). When attached, the protected header drops `b64`/`crit` and the signing input becomes `<header_b64>.<payload_b64>` per RFC 7515.
- **`SignCore.JWS.sign/2` optional `:x5c` with `kid`** — when `:extra_headers` carries a `kid`, `:x5c` may be omitted. The header includes `kid` (RFC 7515 §4.1.4) instead of `x5c`; verifiers look up the cert by `kid`.
- **`SignCore.JWS.verify/3` auto-detection of attached vs detached.** Empty middle segment → detached path (current behavior). Non-empty middle segment → attached path (extract payload from middle, optionally cross-check against caller-supplied `payload` arg). Detached without payload returns `:missing_payload`; attached with mismatched supplied payload returns `:payload_mismatch`.
- **`SignCore.JWS.verify/3` `:kid_certs` opt** — `%{kid_string => leaf_der}` map for kid-based identity resolution. Bypasses `policy.resolve/2` (the `:kid_certs` map IS the operator-supplied allowlist) but still runs `policy.validate/3` to derive the `subject_id`.
- **`SignCore.JWS.sign/2` `:tsa_url` / `:tsa_timeout` opts (B-T-style signature timestamp).** When `:tsa_url` is set, the output switches from Compact to JWS Flattened JSON Serialization (RFC 7515 §7.2.2) carrying an RFC 3161 TimeStampToken in the unprotected `header` field as `x-tst` (base64-DER). Hash input is `SHA-256(raw signature bytes)` — same convention as PAdES/XAdES B-T. Reuses the `Pkcs11ex.Audit.Anchor.RFC3161` client from `pkcs11ex_audit` (optional dep, dispatched via `apply/3` so callers without the audit lib continue to compile).
- **`SignCore.JWS.verify/3` auto-detection of Compact vs Flattened JSON Serialization.** Input starting with `{` is parsed as JSON; otherwise the existing Compact parser runs. Both forms support detached and attached payloads. JSON form with a missing/empty `payload` field is treated as detached.
- **`SignCore.JWS.extract_tst/1`** — pull the RFC 3161 TimeStampToken (DER bytes) out of a JSON-form JWS for callers who want to validate the timestamp chain themselves; returns `{:error, :no_timestamp}` for compact-form or untimestamped envelopes.

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
