# Public API Specification: pkcs11ex

This document specifies the public Elixir API of `pkcs11ex`. The architectural rationale lives in [`specs.md`](./specs.md); this document defines what library users interact with.

| Section | Status |
|---|---|
| §1 Configuration Schema | **canonical** |
| §2 Behaviours (`Pkcs11ex.Algorithm`, `Pkcs11ex.Format`, `Pkcs11ex.Policy`) | **canonical** |
| §3 Surface Functions (`sign`, `verify`, `with_pin`, …) | **canonical** |
| §4 Errors and Telemetry | **canonical** |
| §5 Mix Tasks (`pkcs11ex.import_p12`, …) | **canonical** |

---

## 1. Configuration Schema

### 1.1 Overview

`pkcs11ex` is configured at the OTP application level via `Application` env (typically populated from `config/runtime.exs`). The schema is validated by `NimbleOptions` at supervisor start; invalid configuration prevents boot with a path-qualified error.

```elixir
# config/runtime.exs
config :pkcs11ex,
  signature_header: "JWS-Signature",
  allowed_algs: [:PS256],
  default_slot: :platform,
  trust_policy: Pkcs11ex.Policy.PinnedRegistry,
  session_timeout: :timer.minutes(5),
  driver_pins: %{
    "/usr/lib/libeTPkcs11.so" =>
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  slots: [
    platform: [
      type: :cloud_hsm,
      driver: "/opt/google/kmsp11/libkmsp11.so",
      driver_config: "/etc/pkcs11ex/kmsp11.yaml",
      keys: [
        signing: [label: "platform-signing-key", cert_label: "platform-cert"]
      ]
    ],
    legal_proxy: [
      type: :token,
      driver: "/usr/lib/libeTPkcs11.so",
      slot_match: {:token_label, "Legal Proxy A"},
      pin_callback: {MyApp.PINPrompt, :prompt, []},
      keys: [
        signing: [label: "proxy-signing-key", cert_label: "proxy-cert"]
      ]
    ]
  ]
```

### 1.2 Top-level keys

| Key                 | Type                       | Default                            | Notes |
|---------------------|----------------------------|------------------------------------|-------|
| `:signature_header` | `String.t()`               | `"JWS-Signature"`                  | HTTP header for the JWS-detached transport (specs.md §3.1). |
| `:allowed_algs`     | `[atom()]`, non-empty      | `[:PS256]`                         | Accepted `alg` values for sign and verify. `:none` is hardcoded reject regardless of this list. |
| `:default_slot`     | `atom()` (must reference `:slots`) | required when `:slots` non-empty | Slot used by `Pkcs11ex.sign_bytes/2` (and any format adapter that delegates to it) when no `:signer` opt is given. |
| `:trust_policy`     | `module()`                 | `Pkcs11ex.Policy.PinnedRegistry`   | Implements `Pkcs11ex.Policy` (specified in §2). Drives verify-side cert resolution. |
| `:session_timeout`  | `non_neg_integer()` (ms)   | `:timer.minutes(5)`                | Inactivity timeout for PIN-protected sessions. Ignored by `:cloud_hsm` slots. |
| `:driver_pins`      | `%{path => sha256_hex}`    | `%{}`                              | Optional driver integrity pins (specs.md §4.1). When set, the loader verifies on-disk SHA-256 before `dlopen`. |
| `:slots`            | `keyword()` of slot configs | `[]`                              | Slot definitions; see §1.3. Empty is valid for verify-only deployments. |
| `:telemetry_prefix` | `[atom()]`                 | `[:pkcs11ex]`                      | Prefix for emitted `:telemetry` events. |

### 1.3 Per-slot schema

Each slot is keyed by an atom — the `slot_ref` used throughout the API.

| Key                   | Type                                                          | Default                                | Notes |
|-----------------------|---------------------------------------------------------------|----------------------------------------|-------|
| `:type`               | `:cloud_hsm` \| `:token` \| `:soft_hsm`                       | required                               | Drives concurrency model (specs.md §5.2). `:cloud_hsm` → session-per-thread pool. `:token` → single-session-pinned. `:soft_hsm` → like `:cloud_hsm` but `dirty_cpu`. |
| `:driver`             | absolute path                                                 | required                               | PKCS#11 vendor library (`.so` / `.dll` / `.dylib`). Existence is checked at boot. |
| `:driver_config`      | absolute path                                                 | `nil`                                  | Vendor-specific config (e.g., `libkmsp11`'s YAML). Passed via `CK_C_INITIALIZE_ARGS.pReserved` for vendors that consume it. |
| `:slot_match`         | `{:slot_id, integer()}` \| `{:token_label, String.t()}`       | `{:slot_id, 0}`                        | How to identify the target slot inside the loaded module. `:token_label` triggers a discovery scan and matches `CK_TOKEN_INFO.label`. |
| `:pin_callback`       | `{module, atom, [term]}` (MFA)                                | required for `:token`; forbidden for `:cloud_hsm` | Returns `{:ok, pin :: binary()}` \| `{:error, term}`. PIN is consumed once and never stored (specs.md §4.2). |
| `:keys`               | `keyword()` of key configs                                    | `[]` (verify-only slot)                | See §1.4. |
| `:allowed_algs`       | `[atom()]`                                                    | inherits global                        | Per-slot override. Effective allowlist = `MapSet.intersection(global, slot)`. |
| `:session_pool_size`  | `pos_integer()`                                               | `1`                                    | Only for `:cloud_hsm` / `:soft_hsm` (rejected at config validation for `:token` since login state lives on a single session). When `> 1`, `Pkcs11ex.SlotSupervisor` starts N independent `Slot.Server` workers and `Slot.sign`/`verify` round-robin across them via `Pkcs11ex.Slot.Pool`. Stateful ops (`login`, `logout`, `import_keypair`, `status`, `get_config`) target worker 1. |
| `:lazy`               | `boolean()`                                                   | `true` for `:token`, `false` otherwise | `true` → opened on first use (avoids a PIN prompt at boot). `false` → opened eagerly (catches config errors immediately). |
| `:reauthentication`   | `:prompt` \| `:fail`                                          | `:prompt`                              | After session timeout, `:prompt` re-invokes `pin_callback`; `:fail` returns `{:error, :reauthentication_required}` and requires explicit `Pkcs11ex.Slot.login/2`. |

### 1.4 Per-key schema

Inside a slot's `:keys`, each entry is keyed by an atom — the **logical key id**. The pair `{slot_ref, key_ref}` (e.g., `{:platform, :signing}`) addresses a signing identity end-to-end.

| Key            | Type            | Default                  | Notes |
|----------------|-----------------|--------------------------|-------|
| `:label`       | `String.t()`    | one of `:label` / `:id` is required | Matches `CKA_LABEL` of the private key object. |
| `:id`          | `binary()`      | one of `:label` / `:id` is required | Matches `CKA_ID`. Use when labels collide; common for HSMs that auto-label. |
| `:cert_label`  | `String.t()`    | inherits `:label`        | `CKA_LABEL` of the certificate object used to populate `x5c`. Mutually exclusive with `:cert_id`. |
| `:cert_id`     | `binary()`      | inherits `:id`           | `CKA_ID` of the certificate object. Mutually exclusive with `:cert_label`. |
| `:alg`         | `atom()`        | inferred from key type    | Pin a specific signing algorithm to this key. Otherwise the caller picks from the effective allowlist; the call fails if the chosen alg is incompatible with the key type. |

### 1.5 Boot-time validation rules

The library refuses to start if any of:

1. `:allowed_algs` is empty.
2. `:allowed_algs` contains an unknown algorithm (anything outside `specs.md` §3.5).
3. `:default_slot` references a slot not in `:slots`.
4. A `:type :token` slot lacks `:pin_callback`.
5. A `:type :cloud_hsm` slot defines `:pin_callback`.
6. A slot's `:driver` does not exist on disk.
7. `:driver_pins` contains an entry for a slot's driver and the on-disk SHA-256 does not match.
8. A key has neither `:label` nor `:id`.
9. A key has both `:cert_label` and `:cert_id`.
10. A per-slot `:allowed_algs` has an empty intersection with the global allowlist.
11. Two slots share the same `:driver` path with **different** `:driver_config` (PKCS#11 modules are loaded once per `.so`; conflicting init args are unresolvable).

Error messages identify the offending key path (e.g., `slots.legal_proxy.pin_callback: missing for :type :token`).

### 1.6 Configuration sources and layering

- **Compile-time** (`config/config.exs`, `config/<env>.exs`): structural defaults — PIN callback module names, telemetry prefix, default header.
- **Runtime** (`config/runtime.exs`): host- and environment-specific values — driver paths, key labels, pin digests, slot ids.
- **No environment-variable shorthand.** The library does not read env vars directly; use `System.get_env/1` inside `runtime.exs`. This keeps the configuration surface fully visible in one place.

### 1.7 Verify-only deployments

A deployment that only **verifies** incoming JWS needs:
- `:allowed_algs`
- `:trust_policy`
- `:signature_header`

`:slots` may be empty; `:default_slot` is then omitted. Sign-side calls in this configuration return `{:error, :no_signing_slot}`.

### 1.8 Hot configuration changes

The configuration schema is **immutable for the lifetime of the OTP application**. Changes require a restart. Specifically:
- Adding/removing slots: restart.
- Changing `:driver_pins`: restart.
- Changing `:allowed_algs`: restart. (Operations can disable an alg, but the library re-reads on boot — there is no hot-reload to avoid time-of-check/time-of-use windows.)
- Trust policy changes that the policy module handles internally (e.g., reloading an enrollment table) are handled by the policy itself, not by `pkcs11ex`.

### 1.9 Reference: known algorithm atoms

For `:allowed_algs` and the per-key `:alg`:

| Atom     | JOSE `alg` | Compatible key type |
|----------|------------|---------------------|
| `:PS256` | `PS256`    | RSA ≥ 2048          |
| `:RS256` | `RS256`    | RSA ≥ 2048          |
| `:ES256` | `ES256`    | EC P-256            |
| `:EdDSA` | `EdDSA`    | Ed25519 (future)    |

The validator rejects any atom outside this set.

---

## 2. Behaviours

`pkcs11ex` exposes three extension points: **algorithms** (Layer 2), **formats** (Layer 3), and **trust policies** (verification). Implementations plug in through behaviours. Drivers are not an extension point — the Rust bridge talks to whatever PKCS#11 module is loaded at deployment time.

### 2.1 `Pkcs11ex.Algorithm`

Adapts a JOSE `alg` to a hash, a PKCS#11 mechanism, and the wire-format signature encoding for the calling context.

```elixir
defmodule Pkcs11ex.Algorithm do
  @type alg :: atom()
  @type key_type :: :rsa | :ec | :ed25519
  @type mechanism :: term()
  @type signature :: binary()
  @type encoding_context :: :jose | :der    # :jose for JWS; :der for X.509/CMS contexts (PDF, XML)

  @callback alg() :: alg()
  @callback compatible_key_types() :: [key_type()]
  @callback hash() :: :sha256 | :sha384 | :sha512 | :none
  @callback signing_mechanism() :: mechanism()
  @callback verifying_mechanism() :: mechanism()
  @callback encode_signature(raw :: binary(), encoding_context()) :: {:ok, signature()} | {:error, term()}
  @callback decode_signature(signature(), encoding_context()) :: {:ok, raw :: binary()} | {:error, term()}
end
```

The mechanism descriptor is opaque to Elixir; the Rust bridge translates it to `CK_MECHANISM` plus parameters. Elixir never builds PKCS#11 binary structures directly. Header / signed-attribute validation is the format adapter's responsibility (§2.2), not the algorithm's.

The `encoding_context` parameter exists for ES256: PKCS#11 returns DER `SEQUENCE(r, s)`, which is what X.509/CMS expects (PDF, XML), but JWS requires fixed-width raw `r‖s` (RFC 7518). All other algorithms ignore the context.

**Built-in implementations:**

| Module                       | `alg()`  | Notable behavior                                                                                  |
|------------------------------|----------|---------------------------------------------------------------------------------------------------|
| `Pkcs11ex.Algorithm.PS256`   | `:PS256` | `CKM_RSA_PKCS_PSS` with SHA-256 / MGF1-SHA-256 / 32-byte salt. Identity signature encoding.       |
| `Pkcs11ex.Algorithm.RS256`   | `:RS256` | `CKM_SHA256_RSA_PKCS`. Identity signature encoding.                                               |
| `Pkcs11ex.Algorithm.ES256`   | `:ES256` | `CKM_ECDSA` over a SHA-256 digest. Encoding strips DER → IEEE P1363 raw `r‖s`.                    |
| `Pkcs11ex.Algorithm.EdDSA`   | `:EdDSA` | Future. `CKM_EDDSA`; vendor support uneven.                                                       |

**Adding a custom algorithm.** Implement the behaviour and register the module under `:algorithms`:

```elixir
config :pkcs11ex,
  algorithms: %{
    PS256: Pkcs11ex.Algorithm.PS256,
    PS512: MyApp.PS512Algorithm
  }
```

This extends the known-set check in §1.5 rule 2.

### 2.2 `Pkcs11ex.Format`

Adapts a document or transport format (JWS, PDF, XML, custom) to and from the signing primitives. A format adapter is responsible for: building the bytes-to-sign from the application's input, assembling the signed artifact from the resulting signature, and the inverse parse / verify path.

```elixir
defmodule Pkcs11ex.Format do
  @type input :: term()                # format-specific (payload binary, PDF builder, XML doc, ...)
  @type artifact :: term()             # format-specific signed output
  @type prepared :: %Pkcs11ex.Prepared{
          signing_input: iodata() | Enumerable.t(),
          alg: atom(),
          encoding_context: :jose | :der,
          context: map()                # opaque, returned to assemble/3
        }
  @type parsed :: %Pkcs11ex.Parsed{
          signed_input: iodata(),
          signature: binary(),
          alg: atom(),
          encoding_context: :jose | :der,
          signer_hint: term()           # JWS x5c, CMS SignerIdentifier, XAdES KeyInfo, etc.
        }

  @callback name() :: atom()           # :jws, :pdf, :xml, ...
  @callback prepare(input(), opts :: keyword()) :: {:ok, prepared()} | {:error, term()}
  @callback assemble(input(), signature :: binary(), context :: map(), opts :: keyword()) ::
              {:ok, artifact()} | {:error, term()}
  @callback parse(artifact(), opts :: keyword()) :: {:ok, parsed()} | {:error, term()}
end
```

**Built-in implementations:**

| Module                  | `name()` | Status        | Notes                                                                           |
|-------------------------|----------|---------------|---------------------------------------------------------------------------------|
| `Pkcs11ex.JWS`          | `:jws`   | v1            | RFC 7515 / 7797 detached. `encoding_context: :jose`.                            |
| `Pkcs11ex.PDF`          | `:pdf`   | Phase 4       | PAdES B-B; B-T after `pkcs11ex_audit`. `encoding_context: :der`.                |
| `Pkcs11ex.XML`          | `:xml`   | Phase 4       | XML-DSig + XAdES B-B. C14N is the gating cost. `encoding_context: :der`.        |

**Adding a custom format.** Implement the behaviour and register the module under `:formats`:

```elixir
config :pkcs11ex,
  formats: %{
    jws: Pkcs11ex.JWS,
    my_proto: MyApp.MyProtoFormat
  }
```

Format adapters call only the Layer 2 primitives (`Pkcs11ex.sign_bytes/2`, `Pkcs11ex.verify_bytes/4`, `Pkcs11ex.digest/2`); they never reach into Layer 1 directly.

### 2.3 `Pkcs11ex.Policy`

Resolves the signer's certificate from a JWS header and decides whether the signer is currently authorized.

```elixir
defmodule Pkcs11ex.Policy do
  @type header :: map()
  @type cert :: %Pkcs11ex.X509{}
  @type chain :: [cert()]
  @type subject_id :: term()

  @callback resolve(header(), opts :: keyword()) ::
              {:ok, cert(), chain()} | {:error, term()}
  @callback validate(cert(), chain(), opts :: keyword()) ::
              {:ok, subject_id()} | {:error, term()}
end
```

**Hard invariant — sender-supplied certs are untrusted input.** The verify pipeline treats the certificate from `x5c` (or any equivalent format-supplied hint) as untrusted until matched against an allowlist the verifier maintains. `resolve/2` MUST return `{:error, :unknown_signer}` when no allowlist entry matches; the pipeline aborts **before any cryptographic math runs**. There is no built-in policy and no documented recipe that trusts a sender-supplied certificate solely because its chain validates to a CA. See `specs.md` §7.1.

The verify pipeline calls `resolve/2` first; on `{:error, :unknown_signer}` it aborts (cheap denial of unknowns). It then enforces validity period and algorithm/key compatibility (library-owned, never skipped), and finally calls `validate/3`, where authorization decisions live (subject permitted for this message type / value range / endpoint, policy OID checks, etc.). The returned `subject_id` is propagated to telemetry and to the verify result.

**Built-in implementations:**

| Module                                       | Trust model                                                  | Allowlist mechanism                                                                                                                       |
|----------------------------------------------|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `Pkcs11ex.Policy.PinnedRegistry` *(default)* | SPKI pinning. No chain, no CA, no revocation protocol.       | `{spki_sha256_hex → subject_id}` registry. Onboarding adds an entry; off-boarding deletes one. SPKI pin (not cert pin) survives routine cert re-issuance with the same key. |
| `Pkcs11ex.Policy.CASignedAllowlist`          | Chain-to-CA validation **AND** per-subject allowlist.        | Validates the chain to a configured CA bundle, **then** requires the leaf's SPKI hash (or DN) to be in an explicit allowlist. Both gates must pass. Pluggable `crl_fetcher` and `ocsp_check` callbacks for revocation; no built-in fetchers. |
| `Pkcs11ex.Policy.Allow` *(test only)*        | None.                                                        | Accepts any signer. **Refuses to start under `Mix.env() == :prod`.**                                                                      |

A "CA bundle without allowlist" policy is not provided and not documented as a recipe. See `specs.md` §10 Non-Goals.

**`PinnedRegistry` configuration:**

```elixir
config :pkcs11ex, Pkcs11ex.Policy.PinnedRegistry,
  pins: [
    {"a3f1...d29c", :acme_corp},
    {"7e2b...4810", :beta_inc}
  ]
```

Runtime updates: `Pkcs11ex.Policy.PinnedRegistry.put(spki_sha256_hex, subject_id)` and `delete/1`. State is held in a protected ETS table owned by the application supervisor. Off-boarding a counterparty is `delete/1` — local, instant, no protocol.

**`CASignedAllowlist` configuration:**

```elixir
config :pkcs11ex, Pkcs11ex.Policy.CASignedAllowlist,
  ca_bundle: "/etc/pkcs11ex/ca-bundle.pem",
  allow: [
    {:spki_sha256, "a3f1...d29c", :sii_taxpayer_acme},
    {:dn_match, "CN=*,O=Acme Corp,C=CL", :sii_taxpayer_acme}
  ],
  crl_fetcher: nil,        # MFA returning {:ok, [%CRL{}]} or {:error, _}
  ocsp_check: nil          # MFA returning :good | :revoked | :unknown
```

At least one of `crl_fetcher` or `ocsp_check` MUST be set in production; the library refuses to start otherwise. (This is enforced because most government-PKI deployments are exactly the case where revocation matters most.)

**Helpers.** `Pkcs11ex.Policy.Helpers` ships composable functions for building custom policies without re-implementing RFC 5280:

```elixir
Pkcs11ex.Policy.Helpers.spki_sha256(cert) :: binary()
Pkcs11ex.Policy.Helpers.validity_now(cert, opts) :: :ok | {:error, :expired | :not_yet_valid}
Pkcs11ex.Policy.Helpers.alg_compatible?(alg, cert) :: boolean()
Pkcs11ex.Policy.Helpers.path_validate(leaf, intermediates, anchors) :: {:ok, path} | {:error, reason}
Pkcs11ex.Policy.Helpers.basic_constraints_ok?(cert) :: boolean()
Pkcs11ex.Policy.Helpers.key_usage_includes?(cert, usage) :: boolean()
Pkcs11ex.Policy.Helpers.eku_includes?(cert, oid) :: boolean()
```

Custom policies that bypass `PinnedRegistry` and `CASignedAllowlist` MUST still implement an allowlist gate; the helpers above do not enforce this — the policy author does. Documentation makes this obligation explicit.

#### 2.3.1 The Verification Algorithm

Every format adapter's `verify/3` runs through the same canonical pipeline. Steps 1–6 happen *before* the cryptographic math (step 7), giving cheap denial of unknown / disallowed / expired / wrong-alg signatures without spending CPU on RSA/ECC verification.

```
Input: signed_artifact, payload (or signed bytes), opts
Output: {:ok, subject_id} | {:error, reason}

1. Format parse (adapter)
   parsed = Format.parse(signed_artifact, opts)
   parsed = %{signed_input, signature, alg, encoding_context, signer_hint}
   On bad envelope     → {:error, :malformed_<format>}
   On missing header   → {:error, :missing_required_header}

2. Algorithm allowlist gate (library, mandatory)
   if alg == :none                               → {:error, :disallowed_alg}    # hardcoded
   if alg ∉ effective_allowed_algs(opts)         → {:error, :disallowed_alg}
   if alg ∉ registered_algorithms()              → {:error, :unsupported_alg}

3. Identity resolution (policy)
   {cert, chain} = Policy.resolve(signer_hint, opts)
   On allowlist miss   → {:error, :unknown_signer}            # ABORT — no math runs
   On hint disagreement → {:error, :hint_mismatch}

4. Validity window (library, mandatory, NOT skippable)
   for c in [cert | chain]:
     if now < c.notBefore - skew → {:error, :cert_not_yet_valid}
     if now > c.notAfter  + skew → {:error, :cert_expired}

5. Algorithm/key compatibility (library, mandatory, NOT skippable)
   if cert.spki.key_type ∉ alg.compatible_key_types() → {:error, :incompatible_alg}

6. Authorization (policy)
   {:ok, subject_id} = Policy.validate(cert, chain, opts)
   May internally run: chain validation, revocation, subject-permitted checks,
   value/endpoint policy. Errors propagate as :chain_invalid, :incomplete_chain,
   :untrusted_signer, :cert_revoked, :crl_unavailable, :ocsp_unavailable,
   :revocation_unknown, {:policy_failed, reason}.

7. Cryptographic verification (Layer 2)
   :ok = Pkcs11ex.verify_bytes(signed_input, signature, cert.public_key,
                               alg: alg, encoding_context: encoding_context)
   On math failure     → {:error, :signature_invalid}

8. expected_subject gate (library, only if opt set)
   if subject_id != opts[:expected_subject]
     → {:error, {:unexpected_subject, got: subject_id, want: opts[:expected_subject]}}

9. Return {:ok, subject_id}
```

Steps 1, 2, 4, 5, 7, 8 are library-owned and cannot be opted out by a policy. Steps 3 and 6 are policy-owned. Telemetry events `[:pkcs11ex, :verify, :start | :stop | :exception]` span the whole pipeline; `:queue_time` covers any waiting in step 7.

#### 2.3.2 Identity Resolution (`kid` / `x5c` / `x5t#S256`)

The `signer_hint` payload depends on format:

| Format | Hint shape                                                      |
|--------|-----------------------------------------------------------------|
| JWS    | `%{x5c: [b64_der, ...], kid: "...", x5t#S256: "..."}` (any subset) |
| PDF    | CMS `SignerIdentifier` (issuerAndSerialNumber or subjectKeyIdentifier) |
| XML    | `<KeyInfo>` element (X509Data, KeyName, SubjectKeyIdentifier)   |

Resolution rules within the policy:

- **`x5c` / equivalent embedded cert present** → leaf cert is the *candidate* (still untrusted). Additional certs form the candidate chain.
- **`x5t#S256` present, no embedded cert** → SHA-256 of a cert the verifier has stored. Look up in the local registry; if absent → `:unknown_signer`.
- **`kid` present, nothing else** → opaque identifier passed verbatim to the policy. **Required:** the policy MUST resolve `kid` to a cert held in the verifier's registry. `kid` alone, without a registry mapping, is broken — it lets the sender claim any identity.
- **Multiple hints present** → the policy reconciles. `PinnedRegistry`: prefers `SPKI(x5c-leaf)`; falls back to `x5t#S256`. `CASignedAllowlist`: requires `x5c` with the full chain (no AIA chasing). If hints disagree (e.g., `x5t#S256` doesn't match the leaf in `x5c`) → `:hint_mismatch`.

The format adapter passes the hint to the policy verbatim; policies decide which hint(s) to honor.

#### 2.3.3 Validity, Algorithm Compatibility, Constraint Checks

Validity (library-owned, every verify):
- `notBefore - max_clock_skew ≤ now ≤ notAfter + max_clock_skew`
- `:max_clock_skew` defaults to 30s; configurable per call. Negative values rejected at boot.
- All certs in the chain are checked, not just the leaf.

Algorithm/key compatibility (library-owned, every verify):
- `Algorithm.compatible_key_types()` for the header `alg` MUST include the cert's SPKI key type.
- PS256 + EC cert → reject. ES256 + RSA cert → reject.

Constraint checks (policy-owned, only when chain validation runs):
- **Basic Constraints:** every non-leaf cert MUST have `cA: true`. Leaf MUST have `cA: false` (or absent).
- **Key Usage:** non-leaf certs MUST include `keyCertSign`. Leaf SHOULD include `digitalSignature`; if KU is absent (RFC 5280 §4.2.1.3 — any usage allowed), policies are recommended to reject in production but the library does not enforce this.
- **Extended Key Usage:** checked against a policy-supplied OID list (e.g., `id-kp-emailProtection`, `id-kp-clientAuth`, `id-kp-codeSigning`). An unconstrained leaf passes. Policies that mandate a specific EKU (e.g., regulatory non-repudiation OIDs) supply the list.

`Pkcs11ex.Policy.Helpers.basic_constraints_ok?/1`, `key_usage_includes?/2`, and `eku_includes?/2` implement the canonical interpretation; policies should compose these rather than reading X.509 extensions directly.

#### 2.3.4 Path Validation and Revocation

For `CASignedAllowlist` and any custom policy that does CA-chain validation:

**Path validation** (`Pkcs11ex.Policy.Helpers.path_validate/4`):
- Backed by OTP `:public_key.pkix_path_validation/3`.
- Trust anchors come from a deployment-supplied PEM/DER bundle (`:ca_bundle` config key on the policy).
- `:max_depth` opt (default 8) caps chain length.
- **No AIA chasing.** Senders MUST include the full chain (leaf + all intermediates, no root) in the format envelope. A missing intermediate yields `{:error, :incomplete_chain}`.
- **Cross-signed paths:** OTP returns the first valid path; the library does not enumerate alternatives.

**Revocation** (pluggable; no built-in HTTP fetcher):

| Callback        | Signature                                                 | Returns                                                                                              |
|-----------------|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `:crl_fetcher`  | `MFA → ({issuer_dn, opts}) :: {:ok, [%CRL{}]} \| {:error, term}` | The CRLs the library will check serial numbers against. Called once per verification, cached for the call. |
| `:ocsp_check`   | `MFA → (cert, chain, opts) :: :good \| :revoked \| :unknown \| {:error, term}` | Real-time check or stapled-response evaluation.                                                      |

Behavior:
- A `CASignedAllowlist` policy refuses to start in production if neither `:crl_fetcher` nor `:ocsp_check` is set.
- `:revoked` → `{:error, :cert_revoked}`.
- `:unknown` → `{:error, :revocation_unknown}` by default. Configurable per policy via `:revocation_unknown_policy: :allow` (NOT recommended; logs a warning at boot).
- Callback raising or `{:error, _}` → `{:error, :crl_unavailable}` or `{:error, :ocsp_unavailable}`. **Default posture: revocation unavailable = abort.** This is the right default for high-value workflows; flip it deliberately, not by accident.
- **OCSP stapling** (RFC 6961 / 7633): if the format envelope carries a stapled response, it is passed to `:ocsp_check` as a hint; the callback decides whether to trust it (typically: signature on the response chains to a trusted OCSP responder, response timestamp within a configured freshness window).

#### 2.3.5 Subject Matching and Allowlist Encoding

Allowlist entries for `CASignedAllowlist` (and similar policies):

| Entry                                       | Match strategy                                                                          | Notes                                                              |
|---------------------------------------------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `{:spki_sha256, hex, subject_id}`           | Exact match on the leaf's SPKI SHA-256.                                                 | **Recommended.** Survives routine cert re-issuance with same key.  |
| `{:dn_match, pattern, subject_id}`          | Match the leaf's DN against `pattern`.                                                  | Use when the CA is trusted to bind the DN to the right entity.     |
| `{:cert_sha256, hex, subject_id}`           | Whole-cert SHA-256.                                                                     | Discouraged — forces re-pinning on every renewal.                  |

DN pattern syntax for `:dn_match`:
- Exact DN: `"CN=Acme Corp,O=Acme,C=CL"` — string equality after normalization.
- Wildcard CN: `"CN=*,O=Acme,C=CL"` — only the CN component may be `*`. All other components must match exactly. No partial wildcards (`CN=Acme*`) are supported.

DN normalization (RFC 5280 §7.1, applied before comparison):
- Whitespace folded.
- Case-insensitive comparison on `caseIgnoreString` attributes (CN, O, OU, ...).
- Lowercase hex on `octetString` attributes.
- Backed by `:public_key`'s `pkix_normalize_name/1`.

**Allowlist precedence:** SPKI matches are checked first; DN matches only if no SPKI entry matched. This bounds the cost of misconfigured DN patterns and makes SPKI the "fast path".

#### 2.3.6 Failure Mode Map

Mapping each pipeline step to error reasons (full taxonomy in §4.1):

| Step | Failure                                  | Reason                                          |
|------|------------------------------------------|-------------------------------------------------|
| 1    | Bad envelope                             | `:malformed_jws` / `:malformed_pdf` / `:malformed_xml` |
| 1    | Missing required header                  | `:missing_required_header`                      |
| 1    | `b64`/`crit` violation (JWS)             | `:b64_crit_violation`                           |
| 2    | `alg` not allowed                        | `:disallowed_alg`                               |
| 2    | `alg` not registered                     | `:unsupported_alg`                              |
| 3    | Allowlist miss                           | `:unknown_signer`                               |
| 3    | Hints disagree                           | `:hint_mismatch`                                |
| 4    | Cert expired                             | `:cert_expired`                                 |
| 4    | Cert not yet valid                       | `:cert_not_yet_valid`                           |
| 5    | Alg / key type mismatch                  | `:incompatible_alg`                             |
| 6    | Chain validation failed                  | `:chain_invalid`                                |
| 6    | Chain incomplete (no AIA chasing)        | `:incomplete_chain`                             |
| 6    | Subject not on allowlist                 | `:untrusted_signer`                             |
| 6    | Cert revoked                             | `:cert_revoked`                                 |
| 6    | CRL fetcher failed / unavailable         | `:crl_unavailable`                              |
| 6    | OCSP responder failed / unavailable      | `:ocsp_unavailable`                             |
| 6    | Revocation status unknown                | `:revocation_unknown`                           |
| 6    | Custom policy failure                    | `{:policy_failed, reason}`                      |
| 7    | Math failed                              | `:signature_invalid`                            |
| 8    | `expected_subject` mismatch              | `{:unexpected_subject, got: ..., want: ...}`    |

The reasons listed at step 6 are emitted by `validate/3`; the policy is responsible for choosing the precise atom and for consistency. The library propagates them as-is and adds the `:error_reason` and `:error_class` to telemetry metadata.

---

## 3. Surface Functions

Surfaces are organized by layer:
- **§3.1 `Pkcs11ex`** — Layer 2 primitives. Format-agnostic.
- **§3.2 `Pkcs11ex.JWS`** — Layer 3 JWS adapter.
- **§3.3 `Pkcs11ex.PDF`** *(Phase 4 placeholder)* — Layer 3 PAdES adapter.
- **§3.4 `Pkcs11ex.XML`** *(Phase 4 placeholder)* — Layer 3 XML-DSig / XAdES adapter.
- **§3.5 `Pkcs11ex.Slot`** — slot lifecycle and introspection.
- **§3.6 `Pkcs11ex.PIN`** — scoped PIN helper.
- **§3.7 `Pkcs11ex.JWS.Plug`** — Phoenix / Plug verifier for JWS over HTTP.
- **§3.8 `Pkcs11ex.PKCS12`** — read-only loader for certificates and chains from `.p12`/`.pfx` bundles. Never exposes private keys.

### 3.1 `Pkcs11ex` top-level (Layer 2 primitives)

```elixir
@type signer_ref :: {slot_ref :: atom(), key_ref :: atom()} | atom()
@type pubkey :: %Pkcs11ex.PubKey{} | %Pkcs11ex.X509{}

@spec sign_bytes(iodata() | Enumerable.t(), opts :: keyword()) ::
        {:ok, signature :: binary()} | {:error, term()}
@spec sign_bytes!(iodata() | Enumerable.t(), opts :: keyword()) :: binary()

@spec verify_bytes(iodata() | Enumerable.t(), signature :: binary(), pubkey(), opts :: keyword()) ::
        :ok | {:error, term()}

@spec digest(iodata(), alg :: atom()) :: binary()
@spec digest_stream(Enumerable.t(), alg :: atom()) :: binary()
```

**`sign_bytes/2` options:**

| Opt                   | Type             | Default                                            | Notes                                                                                          |
|-----------------------|------------------|----------------------------------------------------|------------------------------------------------------------------------------------------------|
| `:signer`             | `signer_ref()`   | `{default_slot, :signing}`                         | Atom shorthand resolves to `{default_slot, key_ref}`.                                          |
| `:alg`                | `atom()`         | key-pinned alg, else first compatible allowed alg  | Must be in the slot's effective allowlist.                                                     |
| `:encoding_context`   | `:jose \| :der`  | `:der`                                             | Format adapters override; raw users typically want `:der` (X.509/CMS-shaped output).           |
| `:precomputed_digest` | `binary()`       | `nil`                                              | If supplied, the bytes are interpreted as already digested; the library skips hashing and uses a raw-sign mechanism. Mutually exclusive with streaming input. |

**`verify_bytes/4` options:** symmetric to sign — `:alg` (default: inferred from key type), `:encoding_context` (default: `:der`), `:precomputed_digest`.

**`digest/2` and `digest_stream/2`:** the canonical hash for an `alg`. The mapping is fixed by `Pkcs11ex.Algorithm.hash/0`: `:PS256 → :sha256`, etc. Streaming exists for multi-GB artifacts (PDF/XML signing).

The `!` variants raise `Pkcs11ex.Error`. Use only where errors are programming bugs.

### 3.2 `Pkcs11ex.JWS`

```elixir
@type jws :: binary()                  # "header..signature"
@type payload :: iodata()
@type subject_id :: term()

@spec sign(payload(), opts :: keyword()) :: {:ok, jws()} | {:error, term()}
@spec sign!(payload(), opts :: keyword()) :: jws()

@spec verify(jws(), payload(), opts :: keyword()) ::
        {:ok, subject_id()} | {:error, term()}
@spec verify!(jws(), payload(), opts :: keyword()) :: subject_id()

@spec chain_sign(jws(), payload(), opts :: keyword()) ::
        {:ok, jws(), subject_id()} | {:error, term()}
```

**`sign/2` options:**

| Opt              | Type           | Default                                            | Notes                                                                                          |
|------------------|----------------|----------------------------------------------------|------------------------------------------------------------------------------------------------|
| `:signer`        | `signer_ref()` | `{default_slot, :signing}`                         | As Layer 2.                                                                                    |
| `:alg`           | `atom()`       | key-pinned alg, else first compatible allowed alg  | Must be in the effective allowlist.                                                            |
| `:extra_headers` | `map()`        | `%{}`                                              | Merged into the protected header. `alg`, `b64`, `crit`, `x5c` are reserved; overwriting errors.|

**`verify/3` options:**

| Opt                 | Type        | Default                  | Notes                                                          |
|---------------------|-------------|--------------------------|----------------------------------------------------------------|
| `:trust_policy`     | `module()`  | global `:trust_policy`   | Per-call override.                                             |
| `:policy_opts`      | `keyword()` | `[]`                     | Forwarded to `resolve/2` and `validate/3`.                     |
| `:expected_subject` | `term()`    | `nil`                    | If set, the policy-returned `subject_id` must equal this term. |

**`chain_sign/3`:** verifies `inner_jws` against the trust policy, builds an outer payload as specified in `specs.md` §4.1, signs it with the configured signer (defaults match `sign/2`), and returns `{:ok, outer_jws, inner_subject_id}`. Inner verify failure aborts before any outer signing.

### 3.3 `Pkcs11ex.PDF`

PAdES B-B sign + verify. Implementation lands in Phase 4a (steps 6–11).

```elixir
@spec sign(pdf_in :: binary(), opts :: keyword()) ::
        {:ok, pdf_out :: binary()} | {:error, term()}
@spec verify(pdf :: binary(), opts :: keyword()) ::
        {:ok, subject_id()} | {:error, term()}
```

`sign/2` required opts: `:x5c` (leaf-first chain) plus PKCS#11 keying
opts (`:module`, `:slot_id`, `:pin`, `:key_label`, or canonical
`:signer`). Optional: `:alg` (`:PS256` default, `:RS256`),
`:signing_time`, `:placeholder_size`, `:reason`, `:location`,
`:contact_info`. The output is the original PDF plus an incremental
update with a `/Sig` dict whose `/Contents` is the HSM-produced CMS.

`verify/2` runs in this order — every step is a refusal point:

1. Locate the (single) `/Sig` dict and extract `/ByteRange` +
   `/Contents`. v1 refuses multiple `/Sig` dicts.
2. **Append-attack detection.** Refuse if `c + d` ≠ file size.
3. Parse the CMS `ContentInfo`.
4. **Allowlist gate (architectural invariant).** Synthesise a
   JOSE-style header from the embedded chain and run it through
   `Pkcs11ex.Policy` — `resolve/2` then `validate/3`. The chain is
   untrusted input until both succeed.
5. Match `SHA-256(signed_input)` against the CMS `messageDigest`.
6. Verify the signature math.

Streaming input (`Enumerable.t()`) is post-v1.

### 3.4 `Pkcs11ex.XML` *(Phase 4 placeholder)*

Specified in the Phase 4 design pass. Anticipated surface:

```elixir
@spec sign(doc :: :xmerl.document() | binary(), opts :: keyword()) ::
        {:ok, signed_doc :: :xmerl.document()} | {:error, term()}
@spec verify(doc :: :xmerl.document() | binary(), opts :: keyword()) ::
        {:ok, subject_id()} | {:error, term()}
```

Profile target: XML-DSig (W3C) + XAdES B-B for v1.

### 3.5 `Pkcs11ex.Slot`

Operational surface for slot lifecycle and introspection.

```elixir
@type state :: :idle | :logged_in | :expired | :error

@spec login(slot_ref :: atom(), opts :: keyword()) :: :ok | {:error, term()}
@spec logout(slot_ref :: atom()) :: :ok | {:error, term()}
@spec list() :: [%{ref: atom(), type: atom(), state: state()}]
@spec list_keys(slot_ref :: atom()) ::
        [%{ref: atom(), label: String.t() | nil, alg: atom() | nil}]
@spec status(slot_ref :: atom()) :: %{state: state(), last_login: integer() | nil}
```

`login/2` is rarely needed — `sign/2` triggers login transparently via the slot's `pin_callback`. Use it explicitly when:
- the slot is configured `reauthentication: :fail` and you want to control prompt timing;
- you want to provide a one-shot PIN via `opts[:pin]` (scripts), bypassing the callback.

`logout/1` calls `C_Logout` and closes the session. Subsequent signing calls re-login through the callback.

### 3.6 `Pkcs11ex.PIN`

```elixir
@spec with_pin(binary(), (() -> result)) :: result when result: any()
```

Scopes a PIN to a single closure. Useful for tests and one-shot scripts:

```elixir
Pkcs11ex.PIN.with_pin(System.get_env("TOKEN_PIN"), fn ->
  {:ok, jws} = Pkcs11ex.JWS.sign(payload, signer: {:legal_proxy, :signing})
end)
```

Outside `with_pin`, the library never reads PINs from process state — the registered `pin_callback` is the only path.

### 3.7 `Pkcs11ex.JWS.Plug`

Plug for Phoenix / Plug applications that verify on every request.

```elixir
plug Pkcs11ex.JWS.Plug,
  header: :default,                # uses configured :signature_header
  on_failure: :halt_401,
  policy_opts: [],
  assign: :pkcs11ex_subject
```

Behavior:
1. Reads the configured signature header.
2. **Captures the raw body before `Plug.Parsers`.** Must be installed before any body-parsing plug. If installed after, returns `{:error, :body_already_consumed}`.
3. Calls `Pkcs11ex.JWS.verify/3`.
4. On success, assigns `subject_id` under `:assign`. On failure, `:on_failure` controls behavior:
   - `:halt_401` — sends 401, halts the conn.
   - `:halt_403` — sends 403.
   - `{:assign, key}` — assigns `{:error, reason}` under `key` and continues (lets the controller decide).

The plug is opt-in; `pkcs11ex` does not assume Phoenix. Equivalent plugs for non-JWS protocols (e.g., `Pkcs11ex.PDF.Plug` for PDF upload verification) are out of scope for v1.

### 3.8 `Pkcs11ex.PKCS12`

Read-only loader for certificates and chains from PKCS#12 (`.p12` / `.pfx`) bundles. **Never returns the private key**, even if one is present in the bundle — only a flag indicating its presence. This is a deliberate design choice; see `specs.md` §10 (Non-Goals).

```elixir
@type bundle :: %Pkcs11ex.PKCS12.Bundle{
        leaf: %Pkcs11ex.X509{},
        chain: [%Pkcs11ex.X509{}],
        has_private_key: boolean(),
        friendly_name: String.t() | nil
      }

@spec load(source, opts :: keyword()) :: {:ok, bundle()} | {:error, term()}
      when source: String.t() | binary()

@spec load!(source, opts :: keyword()) :: bundle()
      when source: String.t() | binary()
```

**Input.** `source` is either a filesystem path (string) or the raw bundle bytes (binary). Both forms exist because some workflows have the bundle in hand without ever writing it to disk.

**Options:**

| Opt          | Type          | Default | Notes                                                                                          |
|--------------|---------------|---------|------------------------------------------------------------------------------------------------|
| `:password`  | `binary()`    | `nil`   | Required for encrypted bundles. Same lifecycle rules as PINs — the binary is consumed once and never persisted. Pass `nil` only for the rare unencrypted bundle. |
| `:max_chain` | `pos_integer()` | `8`   | Hard cap on chain length. Bundles with more certificates fail loading.                         |

**Implementation backing.** OTP `:public_key` does not ship PKCS#12 ASN.1 schemas, so v1 of this loader shells out to the `openssl pkcs12` CLI (universally available on Linux / macOS / Windows-OpenSSL builds, well-tested across encryption variants). Passwords are passed via process env (`-password env:VAR`), never on the command line. A native Rust PKCS#12 parser via the existing Rustler bridge is on the roadmap as a follow-up; the public API is stable across the swap.

**Common usage patterns:**

```elixir
# 1. Load a CA bundle for trust policy use
{:ok, %{leaf: ca}} = Pkcs11ex.PKCS12.load("/etc/pkcs11ex/trust-anchor.p12", password: ca_pw)

# 2. Hybrid: cert chain from P12, signing key from a PKCS#11 token
{:ok, %{leaf: cert, chain: chain}} = Pkcs11ex.PKCS12.load(p12_bytes, password: pw)
# ...attach `chain` to JWS x5c, sign with PKCS#11 key
```

**Anti-pattern (rejected by the API):** there is no way to pass a `Pkcs11ex.PKCS12` bundle to `Pkcs11ex.sign_bytes/2` or any format adapter as a *signer*. Signers are PKCS#11 references. If you need to sign with a P12-resident key, either (a) provision the key into a SoftHSM slot via `mix pkcs11ex.import_p12` (§5) and sign via the normal PKCS#11 path, or (b) use `:public_key` directly outside this library.

---

## 4. Errors and Telemetry

### 4.1 Error taxonomy

All public functions return `{:error, term}` on failure. The term is one of:
- a bare atom, for predictable branchable failures;
- a tagged tuple `{atom, payload}`, when diagnostic data must travel (e.g., raw PKCS#11 return code);
- a `Pkcs11ex.Error` struct, for failures that benefit from contextual fields.

Configuration errors are **raised**, not returned: invalid configuration prevents boot.

| Reason                                  | Class            | Notes                                                                          |
|-----------------------------------------|------------------|--------------------------------------------------------------------------------|
| `:slot_not_found`                       | slot/session     | `slot_ref` not in `:slots`.                                                    |
| `:slot_not_logged_in`                   | slot/session     | Token slot needs `Pkcs11ex.Slot.login/2` first.                                |
| `:reauthentication_required`            | slot/session     | Session expired; only emitted when `reauthentication: :fail`.                  |
| `:session_pool_exhausted`               | slot/session     | Cloud HSM pool saturated; raise `:session_pool_size` or check HSM RTT.         |
| `{:driver_load_failed, posix_err}`      | slot/session     | `dlopen` failed.                                                               |
| `{:driver_pin_mismatch, expected, got}` | slot/session     | Driver SHA-256 doesn't match `:driver_pins` entry.                             |
| `:key_not_found`                        | key/cert         | No object matched `:label` / `:id` in the slot.                                |
| `:cert_not_found`                       | key/cert         | No certificate matched in the slot for `x5c` population.                       |
| `:incompatible_alg`                     | key/cert         | Requested `alg` is not in `compatible_key_types/0` for the resolved key.       |
| `:no_signing_slot`                      | config/runtime   | Sign called in a verify-only deployment.                                       |
| `:no_signature`                         | PDF              | `Pkcs11ex.PDF.verify/2` got a PDF that doesn't carry a `/Sig` dict.            |
| `:multiple_signatures_unsupported_in_v1` | PDF             | More than one `/Sig` dict in the PDF; multi-signature support is post-v1.      |
| `:malformed_signature_contents`         | PDF              | `/Contents` couldn't be hex-decoded.                                           |
| `:byte_range_out_of_bounds`             | PDF              | `/ByteRange` claimed bytes past the end of the file.                           |
| `:message_digest_mismatch`              | PDF              | `SHA-256` of the bytes covered by `/ByteRange` doesn't match the CMS `messageDigest` attribute — canonical tampered-byte signal. |
| `:incremental_update_after_signature`   | PDF              | Bytes exist beyond the signed range (`c + d < byte_size(pdf)`); fail-fast detection of the PAdES "append attack". |
| `{:malformed_pdf, atom}`                | PDF              | Reader-side structural failure: `:startxref_not_found`, `:xref_keyword_missing`, `:xref_subsection_header_invalid`, `:xref_entry_malformed`, `:trailer_keyword_missing`, `:xref_stream_unsupported`, `:prev_chain_cycle`, etc. |
| `{:writer, :existing_acroform_unsupported_in_v1}` | PDF    | Base PDF already carries `/AcroForm`; v1 won't merge.                          |
| `{:writer, :placeholder_size_out_of_range}` | PDF          | `:placeholder_size` outside `[256, 1 MiB]`.                                    |
| `{:writer, :cms_der_too_large}`         | PDF              | The CMS DER won't fit the prepared `/Contents` placeholder — caller must raise `:placeholder_size`. |
| `:malformed_jws`                        | JWS              | Header not parseable, signature segment missing/extra.                         |
| `:missing_required_header`              | JWS              | One of `alg`, `crit`, `x5c` is absent.                                         |
| `:b64_crit_violation`                   | JWS              | `b64` is `false` but not in `crit`, or vice versa (RFC 7797 §6).               |
| `:disallowed_alg`                       | JWS              | Header `alg` not in the effective allowlist.                                   |
| `:unsupported_alg`                      | JWS              | Header `alg` is not registered in `:algorithms`.                               |
| `{:cms_codec, type, reason}`            | CMS              | OTP ASN.1 codec rejected an encode/decode for `type` (e.g. `:ContentInfo`, `:SignerInfo`, `:SignedAttributes`). Treat as malformed input. |
| `:missing_digest`                       | CMS              | `Pkcs11ex.CMS.SignedAttributes.build/1` called without `:digest`.              |
| `:invalid_digest`                       | CMS              | `:digest` was not a binary (e.g. iolist, charlist).                            |
| `:empty_certificate_chain`              | CMS              | `Pkcs11ex.CMS.SignedData.build/3` called with `certificates: []`.              |
| `{:unsupported_digest_algorithm, atom}` | CMS              | Only `:sha256` is wired in v1.                                                 |
| `{:unsupported_signature_algorithm, atom}` | CMS           | Only `:rsa_sha256` and `:rsa_pss_sha256` are wired in v1.                      |
| `:invalid_leaf_certificate`             | CMS              | First entry of `:certificates` was not parseable as X.509.                     |
| `:invalid_certificate_entry`            | CMS              | A non-leaf chain entry was not a `Pkcs11ex.X509` struct or DER binary.         |
| `:not_signed_data` / `{:not_signed_data, oid}` | CMS       | `Pkcs11ex.CMS.SignedData.parse/1` got a ContentInfo whose contentType is not `id-signedData`. |
| `:no_signer_info`                       | CMS              | Parsed SignedData carried zero SignerInfos.                                    |
| `:multiple_signer_info_unsupported_in_v1` | CMS            | Parsed SignedData carried more than one SignerInfo. Multi-signer support is post-v1. |
| `:no_certificates`                      | CMS              | Parsed SignedData omitted the `certificates` SET (degenerate signer-only CMS not supported in v1). |
| `:unsupported_certificate_choice`       | CMS              | Parsed SignedData embeds an attribute-cert / extended-cert / `other` CHOICE; only plain X.509 is supported. |
| `:invalid_embedded_certificate`         | CMS              | Embedded certificate failed `:public_key.pkix_decode_cert/2`.                  |
| `:leaf_certificate_not_found_in_chain`  | CMS              | SignerInfo `issuerAndSerialNumber` did not match any embedded certificate.     |
| `:subject_key_identifier_unsupported_in_v1` | CMS          | SignerInfo uses `subjectKeyIdentifier`; only `issuerAndSerialNumber` is supported in v1. |
| `{:missing_attribute, oid}`             | CMS              | Required signed attribute (e.g. `id-contentType`, `id-messageDigest`) absent.  |
| `{:multi_value_attribute, oid}`         | CMS              | Signed attribute carried zero or >1 values; v1 expects exactly one.            |
| `:unknown_signer`                       | trust policy     | `Pkcs11ex.Policy.resolve/2` returned no allowlist match (§2.3.1 step 3).       |
| `:hint_mismatch`                        | trust policy     | Multiple identity hints in the header disagree (`x5c` vs `x5t#S256` vs `kid`). |
| `:untrusted_signer`                     | trust policy     | `Pkcs11ex.Policy.validate/3` rejected the signer.                              |
| `:cert_expired`                         | trust policy     | A cert in the chain is past `notAfter` (with `:max_clock_skew` applied).       |
| `:cert_not_yet_valid`                   | trust policy     | A cert in the chain is before `notBefore` (with `:max_clock_skew` applied).    |
| `:chain_invalid`                        | trust policy     | Chain validation failed at `:public_key.pkix_path_validation/3`.               |
| `:incomplete_chain`                     | trust policy     | The sender omitted required intermediates; `pkcs11ex` does not chase AIA.      |
| `:cert_revoked`                         | trust policy     | CRL or OCSP returned a revoked status for a cert in the chain.                 |
| `:crl_unavailable`                      | trust policy     | `:crl_fetcher` failed or raised; revocation could not be checked.              |
| `:ocsp_unavailable`                     | trust policy     | `:ocsp_check` failed or raised; revocation could not be checked.               |
| `:revocation_unknown`                   | trust policy     | Revocation responder returned `:unknown` and `:revocation_unknown_policy` is `:abort` (default). |
| `{:policy_failed, reason}`              | trust policy     | Policy returned a custom failure.                                              |
| `{:unexpected_subject, got, want}`      | trust policy     | `:expected_subject` opt set on `verify/3` and the resolved subject didn't match. |
| `:signature_invalid`                    | crypto           | Mathematical verification failed.                                              |
| `{:pkcs11_error, ck_rv}`                | crypto           | Raw PKCS#11 return code (e.g., `:CKR_PIN_INCORRECT`).                          |
| `:pin_required`                         | PIN              | `pin_callback` returned `{:error, _}` or no callback configured.               |
| `:pin_incorrect`                        | PIN              | Driver returned `CKR_PIN_INCORRECT`.                                           |
| `:pin_locked`                           | PIN              | Driver returned `CKR_PIN_LOCKED` (vendor lockout).                             |
| `:p12_invalid`                          | PKCS#12          | Bundle bytes are malformed or not a valid PKCS#12 structure.                   |
| `:p12_password_incorrect`               | PKCS#12          | Decryption failed; password mismatch or corrupted bundle.                      |
| `:p12_chain_too_long`                   | PKCS#12          | Chain exceeded `:max_chain`.                                                   |
| `{:p12_unsupported_kdf, oid}`           | PKCS#12          | Bundle uses a KDF/cipher OID not supported by `:public_key` (rare; legacy).    |

`Pkcs11ex.Error` exception:

```elixir
defexception [:reason, :path, :context]
```

Used for `!` variants and config errors. `:path` carries the config key path on config errors (e.g., `[:slots, :legal_proxy, :pin_callback]`).

### 4.2 Telemetry

Events are spans (`:start` / `:stop` / `:exception`), prefixed with the configured `:telemetry_prefix` (default `[:pkcs11ex]`).

| Event                                                  | When                                                                        |
|--------------------------------------------------------|-----------------------------------------------------------------------------|
| `[:pkcs11ex, :sign, :start \| :stop \| :exception]`    | Every `Pkcs11ex.sign_bytes/2` and every format-adapter `sign/2`.            |
| `[:pkcs11ex, :verify, :start \| :stop \| :exception]`  | Every `Pkcs11ex.verify_bytes/4` and every format-adapter `verify/3`.        |
| `[:pkcs11ex, :digest, :start \| :stop]`                | `Pkcs11ex.digest/2` and `digest_stream/2` (only when bytes total > 1 MiB).  |
| `[:pkcs11ex, :session, :open]`                         | Slot session opened.                                                        |
| `[:pkcs11ex, :session, :close]`                        | Slot session closed (logout, timeout, shutdown).                            |
| `[:pkcs11ex, :session, :timeout]`                      | Session expired due to inactivity.                                          |
| `[:pkcs11ex, :login, :start \| :stop \| :exception]`   | Token login round-trip (PIN entry happens before `:start`).                 |
| `[:pkcs11ex, :driver, :load]`                          | PKCS#11 module loaded (one per process per `.so`).                          |

**Measurements.** `:duration` (native time, on `:stop` / `:exception`); `:system_time` (on `:start`); `:queue_time` (on `:stop` for sign/verify — time spent waiting for a session in the pool); `:byte_count` (on `:stop` for sign/verify/digest — bytes hashed or signed).

**Metadata.** `:slot_ref`, `:key_ref`, `:alg`, `:format` (`:jws` / `:pdf` / `:xml` / `:raw`), `:encoding_context` (`:jose` / `:der`), `:subject_id` (verify only), `:signer_subject_id` (chain_sign only), `:error_class`, `:error_reason`. Metadata never carries PIN, signature bytes, payload bytes, certificate private key fields, or any raw format envelope.

**Stable contract.** Event names, measurement keys, and metadata keys are part of the public API. New keys may be added; existing ones are not removed without a major-version bump.

---

## 5. Mix Tasks

Mix tasks are tooling, not runtime API. They live under `mix/tasks/` and are invoked from a developer or operator shell. They are **not** callable from request paths or runtime code.

### 5.1 `mix pkcs11ex.import_p12`

Imports the key and certificate from a PKCS#12 bundle into a write-permitted PKCS#11 slot. Intended for: SoftHSM provisioning in dev / CI; one-shot loading of taxpayer / legal-proxy certificates into file-backed tokens; fixture setup in test suites. **Not** intended for production HSMs (most reject software-key import by design; cloud HSMs do so categorically).

```bash
mix pkcs11ex.import_p12 \
  --in legal_proxy.p12 \
  --slot legal_proxy \
  --label proxy-signing-key \
  [--cert-label proxy-cert] \
  [--id 0x01]
```

**Arguments:**

| Flag           | Required | Notes                                                                                       |
|----------------|----------|---------------------------------------------------------------------------------------------|
| `--in`         | yes      | Path to the `.p12` / `.pfx` bundle.                                                         |
| `--slot`       | yes      | A configured slot reference (must exist in `:slots` and be write-permitted).                |
| `--label`      | yes      | `CKA_LABEL` for the imported private key.                                                   |
| `--cert-label` | no       | `CKA_LABEL` for the certificate. Defaults to `--label`.                                     |
| `--id`         | no       | `CKA_ID` (hex) for both objects. Auto-generated if omitted.                                 |

**Prompts (never logged):**
1. PKCS#12 bundle password.
2. Slot user PIN (required for the underlying `C_Login`).

Both are read via `IO.gets/2` with terminal echo disabled, scoped to the task process, and zeroized on the Rust side after use. A `--password-from-env <NAME>` and `--pin-from-env <NAME>` variant is provided for non-interactive CI; both are documented as suitable only for ephemeral CI runners.

**Failure modes:** the task surfaces the same error reasons as `Pkcs11ex.PKCS12.load/2` plus the standard PKCS#11 errors for `C_CreateObject`. A common one is `{:pkcs11_error, :CKR_ATTRIBUTE_READ_ONLY}` from production HSMs — a clear signal that this is the wrong tool for that target.

### 5.2 Future tasks (placeholder)

- `mix pkcs11ex.list_slots` — diagnostic listing of slots, tokens, and keys visible to the configured drivers.
- `mix pkcs11ex.driver_pin <path>` — compute the SHA-256 of a driver `.so` for `:driver_pins` config.

These are convenience wrappers and ship in Phase 2 alongside the SafeNet integration.
