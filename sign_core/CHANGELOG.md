# sign_core changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`SignCore.XML.verify/2` no longer raises on malformed base64.** The five sites that previously called `Base.decode64!/1` (X.509 certs in `<ds:KeyInfo>`, `<ds:SignatureValue>`, `<xades:CertDigest>`, `<xades:IssuerSerialV2>`, reference digest values) now use `Base.decode64/1` and surface tagged errors (`:invalid_x5c`, `:invalid_signature_value`, `:xades_invalid_cert_digest`, `:xades_invalid_issuer_serial_v2`, `:invalid_reference_digest`) through the verify pipeline's `with` chain. Sender-supplied untrusted input must not crash through to telemetry callers.
- **`SignCore.XML.sign/2` `splice_signature/3` now ignores closing-tag matches inside XML comments and CDATA sections.** Previously, the splice picked the LAST `</root>` substring in the document — a comment legitimately containing `</root>` would shift the splice onto the wrong byte position. The new path collects byte ranges occupied by `<!-- ... -->` and `<![CDATA[ ... ]]>` blocks and rejects matches that fall inside them.
- **`SignCore.XML.sign/2` B-T attach path no longer destructures `{:ok, _} = ...` from `Canonicalizer.parse/1` and `canonicalize/2`.** The previous `canonical_signature_value/1` would crash on parse / canonicalisation failure; it now propagates the error through the surrounding `:bt_failed` wrapper.

### Added

- **`SignCore.XML.Builder.signature_value/1`** — typed builder for the standalone `<ds:SignatureValue>` element used by the B-T attach path's canonicalisation step.

### Changed

- **Telemetry `:error_class` for `:missing_x5c` / `:invalid_x5c` / `:disallowed_alg` is now `:input` instead of `:jws`** for both `SignCore.PDF` and `SignCore.XML`. The previous `:jws` classification leaked the JWS spec name into PDF and XML telemetry, misattributing format-shared input-validation errors. The atom names themselves (e.g. `:missing_x5c`) are unchanged.
- **`SignCore.X509.from_der/1` now caches the SHA-256 SPKI pin on the struct** (`:spki_sha256` field). `spki_sha256/1` is now a constant-time field read; the second ASN.1 decode pass per call is gone. Construction does the work once; verify and registry lookups pay only the field access.
- **`Pkcs11ex.Audit.Anchor.RFC3161.extract_token/1` flattened.** The previous `with`-inside-`cond`-inside-`case`-inside-`rescue` layout is replaced with a single `with`-pipeline plus two small helpers (`check_status/1`, `extract_tst_tlv/1`). Functionally identical; readability is now appropriate for a security-relevant codepath.
- **`SignCore.PDF.verify/2` now uses `SignCore.PDF.Reader` to locate the signature dict via the merged xref**, replacing the previous regex-over-raw-bytes approach. The new path:
  - Walks every revision's xref, takes the newest indirect-object offset per number, scans bodies for `/Type /Sig`, and parses `/ByteRange` / `/Contents` from within the bounded Sig dict body.
  - Tolerates arbitrary PDF whitespace inside the dict — the old regex required exactly one ASCII space and would silently miss legitimate dicts emitted by Adobe / iText / DSS.
  - Ignores `/ByteRange`/`/Contents` text appearing inside content streams, comments, or trailing free text. The old regex counted those as signatures, leading to false `:multiple_signatures_unsupported_in_v1` rejections on legitimate third-party PDFs.
  - **Behavior change:** trailing free text appended after the signed revision that *happens* to look like a Sig dict now surfaces as `:incremental_update_after_signature` (the canonical append-attack signal) rather than `:multiple_signatures_unsupported_in_v1`. The dedicated multi-sig rejection now requires real indirect objects with `/Type /Sig` in xref.
- **`SignCore.PDF.verify/2` malformed-CMS handling tightened.** The trailing-zero-padding stripper now propagates `{:error, :malformed_signature_contents}` when `/Contents` doesn't begin with a SEQUENCE tag, instead of silently passing the malformed bytes to the CMS parser.
- **`SignCore.JWS.sign/2` switched to a positive opt-allowlist for signer-forwarded options.** Only `:signer`, `:module`, `:slot_id`, `:pin`, `:key_label` flow through to Layer 2; new JWS-internal opts no longer leak into the signer pipeline by default.

### Added

- **`SignCore.PDF.Reader.merged_xref_offsets/1`** — newest-revision-wins merge of xref tables across all revisions.
- **`SignCore.PDF.Reader.read_dict_at/2`** — read the dict body at an indirect-object offset.
- **`SignCore.PDF.Reader.signature_dicts/1`** — enumerate `{object_number, dict_body}` pairs for every indirect object carrying `/Type /Sig`. Used by `SignCore.PDF.verify/2`.
- **`SignCore.JWS.sign/2` `:attached` opt** — produce attached JWS (RFC 7515 form: `<header>.<payload_b64>.<sig>`) instead of the default detached (RFC 7797 form: `<header>..<sig>`). When attached, the protected header drops `b64`/`crit` and the signing input becomes `<header_b64>.<payload_b64>` per RFC 7515.
- **`SignCore.JWS.sign/2` optional `:x5c` with `kid`** — when `:extra_headers` carries a `kid`, `:x5c` may be omitted. The header includes `kid` (RFC 7515 §4.1.4) instead of `x5c`; verifiers look up the cert by `kid`.
- **`SignCore.JWS.verify/3` auto-detection of attached vs detached.** Empty middle segment → detached path (current behavior). Non-empty middle segment → attached path (extract payload from middle, optionally cross-check against caller-supplied `payload` arg). Detached without payload returns `:missing_payload`; attached with mismatched supplied payload returns `:payload_mismatch`.
- **`SignCore.JWS.verify/3` `:kid_certs` opt** — `%{kid_string => leaf_der}` map for kid-based identity resolution. Bypasses `policy.resolve/2` (the `:kid_certs` map IS the operator-supplied allowlist) but still runs `policy.validate/3` to derive the `subject_id`.

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
