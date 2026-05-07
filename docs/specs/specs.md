# Technical Specification: pkcs11ex
*Hardware-backed digital signatures for Elixir, via PKCS#11.*

## 1. Problem Statement
Producing legally and operationally valid digital signatures in regulated environments requires signing infrastructure that is secure, interoperable, and auditable. `pkcs11ex` aims to solve:
- **Security and Non-Repudiation:** Ensure that signed artifacts (payment instructions, contracts, invoices, audit records) are tamper-proof and originate from authorized signers, using hardware-backed cryptography (HSMs and hardware tokens).
- **Format Coverage:** Provide first-class signing adapters for the formats financial and governmental workflows actually use — JWS (RFC 7797), PDF (PAdES), and XML (XML-DSig / XAdES) — without forcing applications to implement format-specific cryptography themselves.
- **Standards Fragmentation:** Interact with diverse counterparties (operators, banks, governments, clients) that use different signing algorithms and protocols.
- **Performance and Isolation:** Execute intensive signing operations (notably RSA-PSS) without compromising service latency, while keeping private keys outside any software's reach.

## 2. Key Architectural Decisions

### 2.1 Layered Design
`pkcs11ex` is layered. Each layer has a focused responsibility and is independently usable.

```
┌───────────────────────────────────────────────────────────────────┐
│  Layer 3 — Format adapters                                        │
│  Pkcs11ex.JWS (RFC 7515/7797)   Pkcs11ex.PDF (PAdES)              │
│  Pkcs11ex.XML (XML-DSig/XAdES)  Pkcs11ex.JWS.Plug                 │
│  How a signature embeds in a document or transport.               │
├───────────────────────────────────────────────────────────────────┤
│  Layer 2 — Signing primitives                                     │
│  Pkcs11ex.sign_bytes / verify_bytes / digest / digest_stream      │
│  Algorithm adapters (PS256, RS256, ES256, EdDSA).                 │
│  Owns the alg → hash → mechanism contract.                        │
├───────────────────────────────────────────────────────────────────┤
│  Layer 1 — PKCS#11 bridge (Elixir + Rustler)                      │
│  Slot/session model, dynamic driver loading, PIN handling,        │
│  key/cert resolution, dirty-IO scheduler control.                 │
└───────────────────────────────────────────────────────────────────┘
```

Format adapters depend only on Layer 2; they never reach into Layer 1. This lets the JWS adapter ship in v1 while PDF/XML adapters land later without disturbing the lower layers. Applications that need protocols we don't ship an adapter for can use Layer 2 primitives directly.

### 2.2 Other Decisions
- **Elixir–Rust Bridge (Rustler):** Integrate PKCS#11 with native performance and memory safety. Use *Dirty Schedulers* for heavy cryptographic operations and HSM-bound I/O.
- **Hybrid PKCS#11 Abstraction:** A single interface to interact with cloud HSMs (e.g., GCP Cloud HSM via `libkmsp11.so`, AWS CloudHSM, Azure Managed HSM) and local hardware tokens (e.g., SafeNet eToken, YubiKey) for manual signing.
- **Cryptographic Agility:** Adapter-pattern design supporting PS256 (default), RS256, ES256, and an extensible registry for future algorithms.
- **Hashing in scope:** The library owns the alg → hash mapping and computes digests over `iodata` and streams. Centralizes the signing-input contract, supports very large artifacts (multi-GB PDFs), and lets the library transparently choose between *raw-sign-with-precomputed-digest* and *combined-sign-and-hash* PKCS#11 mechanisms based on what the driver supports. Out of scope: HMAC, KDFs, hashes outside `{SHA-256, SHA-384, SHA-512, EdDSA-internal}`.
- **Signature Chaining (Middleware Mode, Optional):** When `pkcs11ex` is used by an intermediary, it can verify an originator's signature and wrap it in a new signature by the platform key, preserving the full chain for audit. Specified for JWS in §4.1; analogous wrapping for PDF/XML is out of scope for v1.

---

## 3. Signing Primitives (Layer 2)

The primitive layer is format-agnostic: it computes digests and produces or verifies raw signatures. Format adapters (§4) build on top.

### 3.1 Supported Algorithms
| `alg`  | Key type    | Hash    | PKCS#11 mechanism                            | Wire-format encoding                                                          |
|--------|-------------|---------|----------------------------------------------|-------------------------------------------------------------------------------|
| PS256  | RSA ≥ 2048  | SHA-256 | `CKM_RSA_PKCS_PSS`, MGF1-SHA-256, salt 32    | Identity (PKCS#11 raw = JOSE/CMS raw).                                        |
| RS256  | RSA ≥ 2048  | SHA-256 | `CKM_SHA256_RSA_PKCS`                        | Identity.                                                                     |
| ES256  | EC P-256    | SHA-256 | `CKM_ECDSA` over digest                      | DER for X.509/CMS contexts (PDF, XML); IEEE P1363 raw `r‖s` for JWS (RFC 7518). |
| EdDSA  | Ed25519     | n/a     | `CKM_EDDSA`                                  | Identity. Future; vendor support uneven.                                      |

`alg: none` is hardcoded reject. The accepted-algorithm allowlist is **runtime configuration** (`Application.get_env(:pkcs11ex, :allowed_algs)`), default `[:PS256]`, validated on boot.

### 3.2 Hashing
Hashing is part of the public surface, exposed both as one-shot and streaming.

```elixir
Pkcs11ex.digest(iodata, alg :: atom()) :: binary()
Pkcs11ex.digest_stream(Enumerable.t(), alg :: atom()) :: binary()
```

The digest is canonical for a given `alg`: `:PS256` always yields SHA-256, etc. Algorithm adapters declare their hash; applications never pick a hash separately from the algorithm. Streaming exists specifically for PDF and large-file workflows: a 2 GB PDF should not be loaded into the BEAM heap to be signed.

For algorithms that prefer combined sign-and-hash mechanisms (e.g., `CKM_SHA256_RSA_PKCS`), the bridge feeds bytes through the driver in chunks and never materializes a separate digest in Elixir.

### 3.3 Sign / Verify Primitives
```elixir
Pkcs11ex.sign_bytes(iodata, opts) :: {:ok, signature :: binary()} | {:error, term()}
Pkcs11ex.verify_bytes(iodata, signature, pubkey_or_cert, opts) :: :ok | {:error, term()}
```

Every format adapter funnels through these. The library:
1. Resolves the `signer_ref` to a slot + key in PKCS#11.
2. Computes the digest (or streams the bytes through the driver if a combined mechanism is in use).
3. Calls `C_Sign` and returns the wire-format signature for the chosen algorithm and context (the `:signature_format` opt selects DER vs. P1363 for ES256; format adapters set this).

`verify_bytes/4` accepts either a public key or a full certificate; the latter is more common because most workflows have the cert in hand.

---

## 4. Format Adapters (Layer 3)

### 4.1 JWS Detached (RFC 7797) — first-class, v1

**HTTP Header:** Configurable per deployment (config key: `:signature_header`). Default: `JWS-Signature`. Deployments interfacing with specific operators set their own (e.g., `X-Operator-Signature`).

**Payload:** HTTP body, not Base64-encoded (`b64: false`).

**Construction:** `base64url(protected_header)..base64url(signature)` — the empty middle segment denotes a detached payload.

**Signing input bytes** (RFC 7797 §3):

```
ASCII(base64url(JWS Protected Header)) || 0x2E || payload_bytes
```

The payload is fed **raw** — not base64url-encoded. This is the key behavioral difference from baseline JWS. Implementations MUST set `b64: false` AND include `"b64"` in `crit`. Verifiers that do not understand `b64` MUST reject the JWS (RFC 7797 §6).

The HTTP body MUST be byte-identical to what was signed. Frameworks that transform the body (gzip decompression, charset normalization, JSON re-serialization, request logging that re-encodes) MUST be configured to leave it untouched, or the application MUST capture the raw bytes before any such transformation.

**Protected header parameters:**
```json
{
  "alg": "PS256",
  "b64": false,
  "crit": ["b64"],
  "x5c": ["DER_CERTIFICATE_BASE64_NO_LINE_BREAKS"]
}
```
- `x5c` (RFC 7515 §4.1.6): leaf-first, DER-encoded, base64 (standard, *not* base64url; no line breaks).
- Optional supported header parameters: `kid`, `x5t#S256`, `cty`, `typ`.

**Signature Chaining (Middleware Mode, Optional):**
1. Verify the originator's JWS using §5.
2. Build an outer payload containing: the verbatim originator JWS, a hash of the originator leaf certificate, the verified subject identifier, and a server timestamp.
3. Sign the outer payload with the platform key.

The outer JWS is what travels on the wire; the inner JWS is preserved verbatim inside its payload, allowing downstream parties and auditors to verify both layers independently.

### 4.2 PDF (PAdES) — shipped

PDF signing follows ETSI EN 319 142 (PAdES) and lives in
`SignCore.PDF`. High-level flow:
1. Build the PDF with a signature dictionary placeholder reserving space for the signature value (`/Contents`).
2. Compute a SHA-256 digest over the byte ranges of the PDF excluding the placeholder (`ByteRange`).
3. Build a CMS `SignedData` structure (RFC 5652) carrying the signed attributes (including the byte-range hash) and a placeholder for the signature value.
4. Compute the digest of the signed attributes.
5. Sign that digest via the configured signer.
6. Inject the resulting CMS bytes into the PDF placeholder.

**Profile support:**
- **PAdES B-B** (basic baseline) — default.
- **PAdES B-T** — opt in with `:tsa_url` to attach an RFC 3161 TimeStampToken as an `unsignedAttr`.
- B-LT and B-LTA are out of scope.

**Implementation:** hand-rolled in pure Elixir. CMS construction wraps OTP's `'CryptographicMessageSyntax-2009'` ASN.1 codec (`SignCore.CMS.SignedData`). PDF byte-range and incremental-update handling are minimal — `SignCore.PDF.Reader` only scans the trailer/xref and `SignCore.PDF.Writer` only emits the appended update. No full PDF parser.

### 4.3 XML (XML-DSig / XAdES) — shipped

XML signatures follow W3C XML-DSig and ETSI EN 319 132 (XAdES) and live in `SignCore.XML`. Core flow:
1. Build the `<Signature>` element with `<SignedInfo>`, `<Reference>`s, and an empty `<SignatureValue>`.
2. For each Reference: apply transforms (Exclusive C14N 1.0 + enveloped-signature), hash the canonical form, place the digest in the Reference.
3. Canonicalize `<SignedInfo>`, hash, sign via the configured signer.
4. Insert the signature into `<SignatureValue>`.

**Profile support:**
- **XML-DSig** (W3C) + **XAdES B-B** with `<SigningCertificateV2>` and RFC 5035 IssuerSerial.
- **XAdES B-T** — opt in with `:tsa_url` to attach a `<xades:SignatureTimeStamp>` under `<xades:UnsignedSignatureProperties>`.
- B-LT / B-LTA out of scope.

**Implementation:** XML parsing via OTP `:xmerl`. Canonicalization via a vendored + patched copy of `xmerl_c14n` in `sign_core/lib/sign_core/xml/c14n/` — the upstream Hex package crashes on OTP 28's `xmlAttribute` shapes for unprefixed attributes. The patch is a single fallback clause in `do_canonical_name/3`, documented inline. A NIF-wrapped pure-Rust C14N implementation (`bergshamra`) was reserved as a fallback in case the patched `xmerl_c14n` failed standards conformance, but the conformance suite (Poppler `pdfsig` + libxmlsec1 `xmlsec1`) confirms it's correct for the use cases we test.

### 4.4 Raw Passthrough — primitive, always available

Protocols not covered by an adapter use `Pkcs11ex.sign_bytes/2` and `Pkcs11ex.verify_bytes/4` directly. The library still owns digest selection, mechanism mapping, and signature-encoding normalization. The application owns whatever wrapping their protocol needs.

---

## 5. Hardware Token Support (Local Signing)
A first-class integration target: manual authorization of high-value transactions by authorized signers using hardware tokens.

### 5.1 Driver Management
- **Dynamic Loading:** The Rust bridge loads PKCS#11 driver libraries at runtime; the path is configurable per deployment. Reference targets:
  - SafeNet eToken: `libeTPkcs11.so`, `eTPkcs11.dll`, `libeTPkcs11.dylib`
  - YubiKey HSM 2 / YubiKey PIV: `libykcs11.so`
  - GCP KMS PKCS#11: `libkmsp11.so`
  - SoftHSM2 (testing): `libsofthsm2.so`
- **Driver Integrity Pinning:** Deployments MAY supply a SHA-256 digest for each driver path (config key: `:driver_pins`). When a pin is configured, the Rust bridge MUST verify the on-disk file's hash before `dlopen`; a mismatch refuses to load and surfaces a typed error. Pinning is the recommended posture for production. See §8.4 for the threat-model context.
- **Slot Management:** Dynamic monitoring to detect token insertion/removal (`CKF_TOKEN_PRESENT`) for hot-pluggable hardware.

### 5.2 Security and PIN Handling

#### Layered model

| Layer       | Promise                                                                                                                                                                                |
|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Elixir/BEAM | The library never logs, persists, or stores the PIN in process state. Lifetime is one NIF call; references are dropped immediately. The BEAM cannot guarantee timely heap wipe (refc binaries are GC'd lazily); this is a documented best-effort, not a hard guarantee. |
| Rust NIF    | The PIN is copied into a `Zeroizing<Vec<u8>>`, used for `C_Login`, then dropped (auto-zeroized).                                                                                       |
| Driver/HSM  | Out of `pkcs11ex` control. Vendors typically cache login state for the lifetime of the PKCS#11 session — by design.                                                                    |

#### API contract: PIN callback
Applications register a `pin_callback` per slot at config time. The library invokes the callback only when login is required (initial open or post-timeout reauth). The callback returns the PIN as a binary; the library passes it directly to the NIF and never retains it. This keeps the PIN out of long-lived state **by construction**, not by convention.

```elixir
config :pkcs11ex,
  slots: [
    legal_proxy_token: [
      driver: "/usr/lib/libeTPkcs11.so",
      pin_callback: {MyApp.PINPrompt, :prompt_for_pin, []}
    ]
  ]
```

A `Pkcs11ex.PIN.with_pin/2` convenience helper is provided for one-shot scripts and tests; it wraps the same single-closure scoping.

#### Session lifetime
Logged-in sessions auto-expire after a configurable inactivity timeout (default: 5 minutes). After expiry, signing requests fail with `{:error, :reauthentication_required}` and the application's `pin_callback` is invoked again on the next attempt.

---

## 6. Component Architecture

### 6.1 Elixir Layer (Orchestration and Business Logic)
- **`Pkcs11ex.Algorithm` Behaviour:** Defines the common interface for algorithm adapters (Layer 2).
- **`Pkcs11ex.Format` Behaviour:** Defines the common interface for format adapters (Layer 3) — JWS, PDF, XML, and any custom formats applications add.
- **`Pkcs11ex.Policy` Behaviour:** Trust-policy contract for verify pipelines.
- **Connectivity Supervisor:** Manages PKCS#11 module/slot resources (`ResourceArc`s) and supervises the health of the connection with the underlying HSM/token.
- **Policy Validation:** Before signing or accepting a verified signature, the host application validates the certificate against its trust policy (e.g., enrolled in a certificate registry, chain rooted in an authorized CA, not revoked).

### 6.2 Rust Layer (Native Bridge)
- **`cryptoki` Crate:** Safe abstractions over PKCS#11 (target: `cryptoki ≥ 0.7`).
- **Session Model:**
  - **Per-slot session pool**, owned in Rust. Each session is pinned to one OS thread; raw `CK_SESSION_HANDLE` never crosses the NIF boundary. Elixir holds opaque `slot_ref`s.
  - **Cloud HSM slots (no PIN):** session-per-thread pool, sized to the `dirty_io` scheduler count; saturates parallelism.
  - **PIN-protected token slots (e.g., SafeNet):** **single session per slot**, accessed under a tokio mutex. Calls to such a slot serialize. Rationale: re-entering the PIN per signature is a non-starter for human-in-the-loop UX, and most tokens are USB devices without parallel-op support.
- **Resource Allocation:** Safe memory management for public keys and session handles via Rustler `ResourceArc`s with explicit close/drop semantics. `Drop` runs `C_CloseSession`; `C_Finalize` only at supervisor shutdown — never per-call.
- **Crash Safety:** All NIF entry points wrap native calls in `catch_unwind`; `cryptoki::Error` is mapped to typed Elixir errors.
- **Schedulers:** `dirty_io` for HSM-bound calls (Cloud HSM = network RTT; SafeNet = USB I/O). `dirty_cpu` reserved for fully-local crypto (e.g., SoftHSM in tests).

---

## 7. Verification

### 7.1 Hard invariant: sender-supplied certificates are untrusted input

The certificate transported in `x5c` (JWS), `SignerIdentifier` (PDF/CMS), `KeyInfo` (XAdES), or any equivalent header **is untrusted input until matched against an explicit allowlist**.

A signature is accepted **only if** the sender-supplied public key (or its identity) appears in an allowlist the verifier maintains. If the lookup fails, verification rejects **before any cryptographic math runs**. There is no path through the library that trusts a sender-supplied certificate solely because its chain validates to a CA — chain validation, where used, must be *combined* with an allowlist of permitted subjects or SPKIs. Pure CA-trust without a per-subject gate is out of scope (§10).

Rationale: signing critical artifacts (payment instructions, contracts, regulatory filings) requires the verifier to know exactly which counterparties are authorized to sign for a given purpose. Delegating that decision to a CA conflates *identity* (this is who they say they are) with *authorization* (they are permitted to do this). The library forces them apart.

### 7.2 Verification flow

The flow is uniform across formats:

1. **Format parsing (adapter):** Extract the signature, the signed bytes (or canonicalized form), and the sender-supplied certificate hint(s) from the format-specific envelope. The hint is treated as untrusted.
2. **Allowlist resolution (`Pkcs11ex.Policy.resolve/2`):** Compute the sender's identity from the hint (typically SPKI SHA-256 of the leaf) and look it up in the deployment's allowlist. If absent → `{:error, :unknown_signer}` and abort. **No further work runs.**
3. **Validity checks (library, always):** `notBefore ≤ now ≤ notAfter` for the resolved certificate. Algorithm/SPKI compatibility (`alg` in header matches the cert's key type).
4. **Authorization (`Pkcs11ex.Policy.validate/3`):** Application-specific checks beyond identity — is this subject permitted for this message type / value range / endpoint? Returns `{:ok, subject_id}` or `{:error, :untrusted_signer}` / `{:error, {:policy_failed, reason}}`.
5. **Cryptography (Layer 2):** Only now, run the mathematical verification (`Pkcs11ex.verify_bytes/4`).

Steps 2–4 are policy-owned; 1, 3, and 5 are library-owned. Step 3 cannot be skipped by a policy.

### 7.3 Trust models supported

| Model | Allowlist mechanism | Fits when… |
|---|---|---|
| **SPKI pinning (default)** | A registry of `{spki_sha256 → subject_id}` entries. Onboarding adds an entry; off-boarding deletes one. | Direct counterparty enrollment. The standard model for fintech / treasury. |
| **CA-validated allowlist** | Chain validates to a configured CA AND the leaf's SPKI (or subject DN) is in an explicit allowlist. | Government PKI workflows where a recognized CA issues per-subject certs and the verifier maintains its own list of permitted subjects. |
| **Test (`Allow`)** | Accepts any signer with a valid format envelope. | Test environments only. Refuses to start under `Mix.env() == :prod`. |

Trust models that *lack* an allowlist gate are not supported. See §10.

---

## 8. Threat Model

### 8.1 Trust Boundaries
1. Caller → Elixir public API (process-internal, language-level).
2. Elixir → Rust NIF (BEAM/native; data crossed: opaque resource refs and byte buffers).
3. Rust → PKCS#11 driver `.so` (process-internal, `dlopen`'d vendor code).
4. Driver → HSM/token (USB / network / kernel module).

### 8.2 Assumed Trusted
- HSM and hardware token firmware.
- Vendor PKCS#11 driver binary (subject to integrity pinning, §5.1).
- The OS user/process boundary.

### 8.3 In Scope
- Replay, tampering, and signature forgery via incorrect `b64` / `crit` handling (JWS), wrong byte-range hashing (PDF), or non-canonicalized references (XML).
- Key extraction via memory dump (mitigated structurally — keys never leave the HSM).
- Misconfiguration: weak alg in allowlist, PIN logged or persisted, `alg: none` accepted, missing driver pin in production.
- Supply chain: rogue cargo dependency, swapped driver path, swapped CA bundle.
- Time-of-check / time-of-use against the trust policy.
- Library API surface vulnerabilities (input validation, parser bugs, header/payload smuggling, malformed CMS or XML structures).

### 8.4 Out of Scope
- **Hostile root on the host.** A kernel-level adversary can `ptrace` the BEAM process, read PIN material from memory, swap the loaded driver, or hijack signing calls. No software defense inside the library is adequate against this; the threat is treated as game over and explicitly excluded.
- **Maliciously modified vendor driver.** Beyond the optional SHA-256 driver pin (§5.1), `pkcs11ex` does not detect a tampered driver. Deployments MUST source drivers from trusted vendor channels and pin them by hash.
- Physical attacks against tokens or HSMs.
- Side-channel attacks against HSM hardware.
- Denial of service at the BEAM scheduler level (operational concern, not a cryptographic one).

---

## 9. Implementation history

The library was built in five named phases. All are shipped; this section is preserved as a historical record of the architectural evolution.

1. **Phase 1 — PoC.** PS256 sign + verify against SoftHSM2 via Rustler. Layer 1 (bridge) + Layer 2 (primitives + algorithms) + Layer 3 JWS adapter.
2. **Phase 2 — Hybrid.** Dynamic driver loading with integrity pinning; first-class SafeNet eToken support; PIN session lifecycle + `pin_callback` API. `mix pkcs11ex.import_p12` provisioning task for SoftHSM and write-permitted tokens.
3. **Phase 3 — Cloud.** GCP Cloud HSM integration via `libkmsp11.so`. Documented patterns for AWS CloudHSM and Azure Managed HSM. Cloud configuration examples in [`examples/`](../../examples/).
4. **Phase 4 — Format Expansion.** PAdES B-B (`SignCore.PDF`) and XAdES B-B (`SignCore.XML`). Hand-rolled CMS encoder over OTP's `'CryptographicMessageSyntax-2009'` codec; vendored + patched `xmerl_c14n` for exclusive C14N. Conformance gated by Poppler `pdfsig` and libxmlsec1 `xmlsec1`.
5. **Phase 5 — Compliance.** `pkcs11ex_audit` sister library: append-only hash-chained log + RFC 3161 anchor. PAdES B-T / XAdES B-T attach `:tsa_url` to fetch and embed a TimeStampToken in `unsignedAttrs` / `<xades:UnsignedSignatureProperties>`.

A subsequent **monorepo split** extracted format-adapter primitives into `sign_core` (provider-agnostic) and software-key signing into `soft_signer` (PKCS#12 + PKCS#8 PEM). `pkcs11ex` now contributes a `Pkcs11ex.Signer` implementation of the `SignCore.Signer` protocol and ships convenience wrappers preserving the existing API.

The roadmap forward is open — no fixed phases. Concrete items being considered:
- More algorithm adapters (`:ES256`, `:EdDSA`).
- More signers (cloud KMS providers, PC/SC smart-card readers).
- B-LT / B-LTA profiles for long-term archival signatures.

---

## 10. Non-Goals

These are deliberate exclusions, not "not yet" items. They bound the threat model and keep the library's contract narrow. Workflows that need any of them should reach for a different tool.

- **Software signing.** `pkcs11ex` does not sign with keys held in software (PEM, DER, PKCS#12 in process memory, in-memory PEM blobs, etc.). Workflows that need software signing should use `:public_key` (OTP stdlib) or a dedicated library like `jose`. The cost of this restriction is intentional: it bounds §8 and keeps "private keys never leave hardware" a true statement.
  - **`Pkcs11ex.PKCS12` is read-only by design.** It loads certificates and chains from a `.p12`/`.pfx`. It never returns the private key, even if one is present in the bundle.
  - **`mix pkcs11ex.import_p12` is provisioning tooling, not a runtime path.** It imports a P12's key+cert into a write-permitted PKCS#11 token (typically SoftHSM for dev/CI). It is not callable from request paths and does not ship as a library function.
- **Custom hash algorithms** outside `{SHA-256, SHA-384, SHA-512, EdDSA-internal}`.
- **HMAC, KDFs, symmetric encryption.** Different problem domain.
- **PKCS#11 object management** (key generation, attribute editing, deletion). The library reads keys and certificates; it does not manage their lifecycle. Use vendor tools (`pkcs11-tool`, cloud consoles) for provisioning.
- **Detection or recovery from a maliciously modified vendor driver.** See §8.4. Driver SHA-256 pinning (§5.1) is the partial mitigation.
- **Pure CA-trust verification.** A trust model that accepts any sender whose certificate chains to a configured CA, *without* an allowlist of permitted subjects or SPKIs, is not supported. See §7.1. CA-validated allowlist policies (chain + per-subject gate) are supported and recommended for government-PKI workflows.
