# Phase 4 — PDF (PAdES) and XML (XML-DSig / XAdES) Implementation Plan

Status: **proposed** — awaiting maintainer review.
Authors: research pass for `pkcs11ex`, May 2026.
Scope: ship `Pkcs11ex.PDF` and `Pkcs11ex.XML` adapters that match the
contract in [`docs/specs/api.md`](../specs/api.md) §3.3 and §3.4 without
violating any architectural invariant in [`docs/specs/specs.md`](../specs/specs.md).

> **TL;DR.** Build the shared CMS SignedData primitive **in pure Erlang/Elixir**
> on top of OTP's `'CryptographicMessageSyntax-2009'` ASN.1 codec. Keep PDF
> byte-range manipulation **in Elixir** with a minimal, append-only writer —
> incremental-update PDFs do not require a full PDF parser. For XML
> canonicalisation, wrap **the existing Erlang `xmerl_c14n`** (the esaml
> implementation, available on Hex) with a thin shim and audit it
> against the W3C C14N test suite; if it fails coverage, fall back to a
> Rust NIF wrapping the **`bergshamra`** crate (pure-Rust, no FFI). No
> new mandatory NIFs are required to ship Phase 4. The Rust NIF remains
> dedicated to PKCS#11.

---

## 1. Executive summary

| Area | Recommendation | One-line justification |
|---|---|---|
| **A. CMS SignedData** | Pure-Elixir module wrapping OTP `'CryptographicMessageSyntax-2009'` (`public_key:der_encode/2`). | The codec ships with OTP; the only real work is the Attribute open-type encoding, which is mechanical. No NIF needed; aligns with the existing pdf.ex moduledoc plan. |
| **B. PDF byte-range** | Hand-rolled minimal incremental-update writer in Elixir. Ship `Pkcs11ex.PDF.Reader.scan_signature/1` for verify (locate the existing `/Sig` dict). | An incremental update is a few hundred bytes appended to the file plus a fresh xref subsection. Existing Rust crates (`lopdf`, `pdf`) carry significant maintenance and compatibility risk for the small win they offer. |
| **C. XML C14N** | Phase-1 path: vendor `xmerl_c14n` from esaml/`DoggettCK`; cover its test suite. Phase-2 path (only if coverage fails): NIF-wrap `bergshamra` for full C14N 1.0/1.1 + Exclusive variants. | Erlang already canonicalises; we get to ship without growing the NIF surface. `bergshamra` is the contingency: pure-Rust, BSD-2, no `unsafe`, no FFI, all 6 W3C variants. |

**Architectural invariants preserved (re-asserted).**

1. All private-key operations route through `Pkcs11ex.sign_bytes/2` — Layer 2.
   PDF and XML adapters never call `Pkcs11ex.Native.*` directly.
2. The signed input for CMS is `DER(signedAttrs as SET-OF)`, the canonical
   re-encoding rule from RFC 5652 §5.4. PDF and XML both feed this through
   `Pkcs11ex.sign_bytes/2`; the resulting raw signature gets glued back
   into the CMS structure or the `<SignatureValue>` element, never produced
   in software.
3. Verify-side x5c handling routes through `Pkcs11ex.Policy` exactly as JWS
   already does — the embedded chain is candidate-only until the leaf
   matches the configured allowlist.
4. The allowlist gate fires **before** the signature math (step 3 of the
   §2.3.1 pipeline). The PDF and XML pipelines reuse this verbatim.
5. Driver SHA-256 pinning (`Native.module_load_pinned/2`) is preserved —
   nothing in this plan touches that path.

---

## 2. Crate evaluation matrices

### 2.A — CMS SignedData

| Name | License | Version (last release) | Maturity (1-5) | Recommended? | Main risk |
|---|---|---|---|---|---|
| **OTP `'CryptographicMessageSyntax-2009'`** (built-in) | Apache-2.0 (OTP) | OTP 27 (built-in) | 5 | **YES (primary)** | Open-type Attribute encoding is verbose; we own all the wiring. |
| `cms` (RustCrypto) | Apache-2.0 OR MIT | 0.3.0-pre.2 (Jan 2026) — last *stable* 0.2.3 (Jan 2024) | 3 | conditional | `SignedDataBuilder` requires `signature::Signer` — no first-class external-signer path. We'd construct `SignerInfo` by hand (fields are `pub`) which negates most of the convenience win, and the type still graduates from `0.x`. |
| `pkcs7` (RustCrypto) | Apache-2.0 OR MIT | 0.4.1 (May 2023) | 1 | NO | Officially deprecated. Maintainer points users to `cms`. |
| `cryptographic-message-syntax` (Greg Brzezinski) | MPL-2.0 | active (used by `apple-codesign`) | 4 | conditional | MPL-2.0 is allowlist-compatible but adds licensing complexity vs. Apache-2.0. Tied to a Mac code-signing toolchain; designed for in-process signing keys. |
| Hand-rolled `der`+`spki` Rust | Apache-2.0 OR MIT | n/a | 2 | NO | Reimplements what OTP already does, in the language with no first-class CMS API. Rust path saves nothing once we lose the builder. |

**Why OTP wins.** The signed input for CMS is the DER of `signedAttrs`,
re-encoded under tag `SET OF Attribute` instead of `[0] IMPLICIT
SET OF` (the gotcha from the brief). OTP's ASN.1 generator produces an
encoder for `SignedAttributes` that we drive directly with
`public_key:der_encode('SignedAttributes', Attrs)`. The Attribute type's
open-type values (where the value is `ANY DEFINED BY type`) are encoded
by handing OTP an `{:asn1_OPENTYPE, der_value}` term — same mechanism
the existing `'PKIX1Explicit-2009'` code uses for X.509 extensions. This
is a few hundred lines of Elixir, no NIF, no new system dependency.

**Why not `cms` (Rust).** Three reasons, in order:

1. The builder API is structured around `signature::Signer<Signature>`
   trait bounds. The recommended escape — implementing a
   `Pkcs11Signer` that wraps a callback into Elixir — runs into the
   same problem as JWS earlier: the trait wants a synchronous
   in-process key, and threading a callback to BEAM through a
   trait-object that returns a typed `Signature` while mid-NIF means
   re-entering BEAM, which Rustler can't do safely (no `Env` in a
   blocking trait method on a different thread). Workaround: skip the
   builder, construct `SignerInfo` field-by-field — at which point we're
   not really using the crate's value-add anymore.
2. The crate is at `0.3.0-pre.2`. The last *stable* release is `0.2.3`
   from Jan 2024. ABI churn between `0.x` releases is the norm — the
   `der` and `spki` crates underneath have shifted signatures multiple
   times since Phase 1.
3. Avoiding a new Rust dependency keeps the NIF surface focused on
   what it has to be: PKCS#11. Future additions to that surface (timestamps,
   PDF rendering, etc.) are easier when the crate isn't already
   carrying ~13 transitive deps for ASN.1 work that OTP already handles.

**Conditional path back to `cms` Rust.** If the OTP open-type encoding
proves brittle once we hit production CAdES variants in Phase 5 (B-T,
B-LT), revisit `cms` once it cuts a stable `0.3` or `1.0`. The pure-OTP
implementation is a self-contained module; replacing its body with a
NIF call doesn't require API churn.

---

### 2.B — PDF byte-range manipulation

| Name | License | Version (last release) | Maturity (1-5) | Recommended? | Main risk |
|---|---|---|---|---|---|
| **Hand-rolled minimal incremental writer** (Elixir) | Apache-2.0 (us) | n/a | 4 (the spec is small) | **YES (primary)** | Cross-PDF compatibility — we only need to write valid incremental updates; reading existing files is a parsing-tolerance question. |
| `lopdf` | MIT | 0.40.0 (Mar 2026) | 4 | conditional | Active, downloads-rich. But maintainer-acknowledged signature gaps (issue #305): no first-class incremental-with-ByteRange path; multi-signature byte-position tracking is unfinished. We'd be a beta tester of an in-progress feature. Adds the crate's full PDF parser to our process where we only need ~150 LoC of writing. |
| `pdf` (pdf-rs) | MIT | 0.10.0 (Mar 2026) | 3 | NO | Writing is documented as "still experimental." Read-side is more mature, but for our use case the writing side is the load-bearing part. |
| `pdf-extract` | MIT | active | 2 | NO | Read-only. Nothing to add over `lopdf` for our path. |
| `pdfium-render` (+ `pdfium-binaries`) | MIT OR Apache-2.0 (wrapper); BSD-3-Clause (PDFium) | 0.9.0 (Mar 2026) | 4 | NO | Heavy footprint. PDFium is a ~10-15 MB native binary per platform. Designed for rendering, not low-level signing primitives. License is fine, weight isn't. |
| Roll-our-own append in Rust via Rustler | Apache-2.0 (us) | n/a | 3 | NO | No advantage over rolling the same thing in Elixir. The byte-range work is I/O, not CPU. |

**Why hand-roll in Elixir.** A PAdES B-B incremental update is mechanical:

1. Take the existing PDF bytes verbatim.
2. Append a `\n` if the file doesn't end with one (some don't).
3. Compute the offset where new content starts. Call this `O`.
4. Emit (in order):
   - A new annotation object — empty signature widget, references the page.
   - A new acroform object (or update if one exists — we copy and
     extend).
   - A new `/Sig` dictionary with `/ByteRange [0 X Y Z]` placeholder
     (`/ByteRange [0 9999999999 9999999999 9999999999]` is the convention)
     and `/Contents <00...00>` (hex-zero placeholder, sized for the
     CMS bytes plus padding).
   - A new page-tree object that wraps the original `/Annots` plus the
     new sig widget. (Or copy-and-extend.)
   - A new catalog with the updated AcroForm reference.
   - A new xref subsection covering only the new objects, with `/Prev`
     pointing at the original xref offset.
   - The `trailer` line and the new `startxref` offset.
5. Compute the actual `ByteRange`: `[0, sig_contents_offset,
   sig_contents_offset + sig_contents_len, file_end - (sig_contents_offset + sig_contents_len)]`.
6. Re-write `/ByteRange` in place — the placeholder is fixed-width
   so the substitution doesn't shift any subsequent byte.
7. Hash the bytes covered by `/ByteRange` (everything except the
   `/Contents <...>` hex string itself). This is the message digest
   for the CMS `signedAttrs` `messageDigest` attribute.
8. Build the CMS via the OTP path (§2.A). Sign `DER(signedAttrs)` via
   `Pkcs11ex.sign_bytes/2`.
9. Wrap the resulting raw signature into the `SignerInfo`'s
   `signature` field; encode the full CMS ContentInfo as DER.
10. Hex-encode the CMS DER and write it (still fixed-width) into the
    `/Contents <...>` placeholder.

The nontrivial work is finding existing object numbers (so the new
objects don't collide), reading the existing trailer to find `/Prev`
and `/Root`, and extending the AcroForm. None of this requires parsing
content streams or interpreting page resources. We need maybe four
PDF parsing primitives:

- `find_last_xref_offset/1` — read backwards from the file end for
  `startxref`, parse the trailing integer.
- `read_trailer/2` — read the trailer dictionary (a small text-format
  dict at a known offset).
- `next_object_number/1` — derive from the existing xref's `/Size`.
- `find_acroform/1` — follow the `/AcroForm` ref from the trailer's
  `/Root`-pointed catalog (may not exist; we create one if not).

These are ~150-200 lines of Elixir using `:binary` module pattern
matching. We **deliberately** do not parse content streams, encoded
streams, or anything inside an object's body — we only handle the
file-level structure and the catalog/AcroForm dicts at a textual
level.

**Verification path.** Symmetric: scan from the file end, walk the
linked xref chain via `/Prev` (until a chain entry contains the `/Sig`
dict), extract `/ByteRange`, hash the covered bytes, parse the CMS
ContentInfo via OTP (`public_key:der_decode('ContentInfo', ...)`),
extract the cert, route through `Pkcs11ex.Policy` for the allowlist
gate, then verify the signature math via `Pkcs11ex.verify_bytes/4`.

**When to escalate to `lopdf`.** If real-world test corpora reveal
that vendor PDFs (Adobe, Foxit, government-issued CL-SII) emit xref
streams (`/Type /XRef` rather than the text trailer) heavily enough
that scanning becomes brittle, swap the verify-side scanner for
`lopdf`'s parser — but keep the writer hand-rolled. Mixed mode is
fine; the writer outputs the legacy text-format xref subsection
(legal in PDF 1.7+ and accepted by every conforming reader).

---

### 2.C — XML Canonicalisation (C14N)

| Name | License | Version (last release) | Maturity (1-5) | Recommended? | Main risk |
|---|---|---|---|---|---|
| **`xmerl_c14n`** (esaml-derived; `DoggettCK/xmerl_c14n` on Hex) | BSD-2-Clause | 0.2.0 (Sep 2019); esaml internal copy still maintained | 3 | **YES (primary)** | Only **Exclusive C14N 1.0** — no inclusive C14N or 1.1. Sufficient for XAdES B-B (which uses Exclusive). Risk: low community visibility. |
| **`bergshamra`** (Rust) | BSD-2-Clause | 0.4.0 (Apr 2026) | 4 | **YES (Phase 4b.2 fallback)** | Pure-Rust, all 6 C14N variants, no FFI, no `unsafe`, RustCrypto-based. Young (workspace, cut Mar 2026). 22 MB compiled, ~417k LoC dependency tree. |
| `xml_c14n` (rMazeiks) | MIT OR Apache-2.0 | active | 2 | NO | libxml2 FFI. Adds a system-package dependency we currently don't have. Single-author, low traffic. Even with C14N modes, libxml2 versioning across distros is its own compatibility story. |
| `xml-canonicalization` (lilopkins) | MIT | active | 2 | NO | Pure Rust but explicitly *does not* support entity references, default DTD attributes, or document-subset expressions. XAdES with `<ds:Reference URI="#id">` uses document-subset selection — this gap is disqualifying. |
| `libxml` (Rust crate) | MIT | 0.3.9 (Apr 2026) | 4 (as a libxml2 binding) | NO | No documented C14N API exposed at the wrapper level. Same libxml2 install requirement as `xml_c14n`. |
| `xml-rs` | MIT | 1.0.0 (Aug 2025) | 5 (as a parser) | NO (for C14N) | No canonicalisation. Useful only as a parser layer underneath a C14N implementation. |
| Direct libxml2 FFI | MIT | n/a | 5 | NO | libxml2 has the canonical implementation, but the system-dependency surface is identical to `xml_c14n` with more code to write. |
| Apache Santuario port | Apache-2.0 | n/a | n/a | NO | Java; out-of-process port is a project of its own, not Phase 4 scope. |

**Why `xmerl_c14n` first.** XAdES B-B needs **Exclusive C14N 1.0**
specifically (W3C `http://www.w3.org/2001/10/xml-exc-c14n#`). The
esaml-derived module covers exactly that, has shipped in production
SAML-IdP code for years, and integrates directly with the `:xmerl`
records OTP already gives us. The repository is quiet but the code
is small and we own a copy by vendoring it.

**Why `bergshamra` as fallback.** If the W3C interop suite reveals
gaps (the SAML-focused module may lag on edge cases like xml:base or
xml:lang inheritance for arbitrary documents), `bergshamra` is a
clean Rust dependency: BSD-2, no FFI, no `unsafe`, all 6 C14N
variants validated. The NIF wrapper would be one function:
`canonicalize(xml_bytes, mode) -> bytes`, `DirtyCpu` scheduler.

**Why not libxml2-based crates.** The library currently has zero
system-library dependencies. Adding libxml2 means coordinating
distro-package versions across SoftHSM2 dev environments, Debian-
based CI, Alpine-based containers, and macOS Homebrew. The
operational cost is real and easy to underestimate.

---

## 3. Recommended NIF surface

**Headline: zero new NIFs are required for Phase 4.** The PKCS#11
bridge in `native/pkcs11ex_nif/src/lib.rs` does not grow.

### 3.1 Why no NIFs

| Component | Why it stays in BEAM |
|---|---|
| CMS SignedData encode/decode | OTP `public_key:der_encode/2` and `der_decode/2` cover both directions of `'ContentInfo'`, `'SignedData'`, `'SignerInfo'`, `'SignedAttributes'`. |
| PDF incremental writer | I/O-bound: pattern-matching on bytes plus `IO.iodata_to_binary/1`. BEAM handles binaries efficiently. |
| PDF reader / xref scan | Same as above. |
| XML parsing / serialisation | OTP `:xmerl_scan` and `:xmerl_lib`. |
| C14N | `xmerl_c14n` (vendored) — pure Erlang. |
| Signing | Existing `Pkcs11ex.sign_bytes/2`, no change. |
| Verification (math) | `:public_key.verify/4` — already used by JWS. |

### 3.2 Conditional Phase 4b.2 NIF (only if `xmerl_c14n` coverage fails)

If the conformance test pass rules out `xmerl_c14n`, we add one NIF
that wraps `bergshamra::c14n`:

```rust
/// Canonicalise an XML document using one of the W3C C14N modes.
///
/// `mode` is one of: "c14n10_inclusive", "c14n10_exclusive",
/// "c14n11_inclusive", with `_with_comments` suffix variants.
/// Returns the canonical octets per W3C XML-C14N or XML-EXC-C14N.
///
/// Pure CPU work — schedule on DirtyCpu rather than DirtyIo because
/// the cost scales with document size, not with I/O latency.
#[rustler::nif(schedule = "DirtyCpu")]
fn xml_c14n(
    xml: Binary<'_>,
    mode: String,
    inclusive_namespaces: Vec<String>,
) -> Result<Vec<u8>, Error> { /* ... */ }
```

Notes on convention:
- Matches the existing surface: `Binary<'_>` for inputs, `Vec<u8>`
  return (which the Elixir caller normalises to a binary, per the
  pattern in `Pkcs11ex.run_sign/3`).
- `Result<T, Error>` with a new `Error::Canonicalization(String)`
  variant added to the existing enum; the encoder gets one new arm.
- `DirtyCpu` rather than `DirtyIo` because canonicalisation is
  algorithmic, not I/O-bound. (This is a slight departure from the
  current PKCS#11 NIFs which are all `DirtyIo`; documented in the
  function's rustdoc.)
- No new resource type. Strings in / bytes out, stateless.

### 3.3 No new resources

The existing `Module` and `Session` resources in
`native/pkcs11ex_nif/src/lib.rs` cover the PKCS#11 path. Phase 4
adds none. The Rust crate stays focused on `cryptoki` plus
sha256-pinning; if `bergshamra` lands later as the C14N
fallback, it is added as a dependency in the same `Cargo.toml`.

---

## 4. Recommended Elixir adapter API

### 4.1 `Pkcs11ex.PDF`

Aligns with `docs/specs/api.md` §3.3. Three small additions to the
spec proposed inline; no breaking changes vs. the existing skeleton.

```elixir
defmodule Pkcs11ex.PDF do
  @moduledoc """
  PAdES Baseline B (B-B) format adapter.

  PDF signing follows §2.3.1 verify pipeline — allowlist resolution
  precedes the signature math.

  Calls into Layer 2 (Pkcs11ex.sign_bytes/2) for the cryptographic
  primitive; never invokes the NIF directly.
  """

  @type pdf_bytes :: binary()
  @type signed_pdf :: binary()
  @type sign_opt ::
          {:signer, Pkcs11ex.signer_ref()}
          | {:alg, atom()}
          | {:x5c, binary() | [binary()]}
          | {:reason, String.t()}            # /Sig dict /Reason field
          | {:location, String.t()}          # /Sig dict /Location field
          | {:contact, String.t()}           # /Sig dict /ContactInfo
          | {:signed_at, DateTime.t()}       # signedAttrs signingTime
          | {:contents_size, pos_integer()}  # bytes reserved for /Contents (default 16384)

  @spec sign(pdf_bytes(), [sign_opt()]) :: {:ok, signed_pdf()} | {:error, term()}
  @spec verify(signed_pdf(), keyword()) :: {:ok, subject_id :: term()} | {:error, term()}
end
```

**Spec deltas to recommend in api.md §3.3.**

1. Drop `Enumerable.t()` from `sign/2`'s input type for v1. PAdES needs
   to scan the trailer (last ~1 KiB) and compute hashes over arbitrary
   ranges (`/ByteRange`) — neither is friendly to streamed input.
   Re-introduce later if a streaming consumer materialises and the cost
   of a temp file on the verifier side is documented. **Concrete
   suggestion:** narrow `pdf_in` to `binary() | iodata()`.
2. Make `:x5c` mandatory at the API level (mirror JWS). Without an
   embedded chain we have no `signer_hint` to pass to
   `Pkcs11ex.Policy.resolve/2` on verify, and the policy has nothing
   to allowlist. The spec's silence on x5c at §3.3 is consistent with
   §3.4 — both should call this out.
3. Add `:contents_size` as an explicit knob. PAdES requires the
   signature `/Contents` placeholder be sized up-front, before signing
   knows the final CMS bytes. Default 16 KiB is enough for an RSA-2048
   PSS signature with a typical 2-3 cert chain; larger keys or B-T
   timestamps need more. Failure mode `:contents_size_exceeded` is the
   right error.

**Sign flow.**

```
1. Parse minimal trailer + xref of the input PDF (offsets only).
2. Build the incremental update with:
   - Hex-zero /Contents placeholder of `:contents_size` bytes.
   - /ByteRange placeholder [0 9999999999 9999999999 9999999999].
   - /Sig dict: /Type /Sig, /Filter /Adobe.PPKLite,
                /SubFilter /ETSI.CAdES.detached, /M signing_time,
                /Reason, /Location, /ContactInfo (optional from opts).
   - AcroForm + Annot wiring.
3. Concatenate input PDF + incremental update.
4. Compute final ByteRange offsets (placeholder is fixed-width; substitution preserves length).
5. Substitute final /ByteRange bytes in place.
6. Compute message digest = SHA256 of the bytes covered by /ByteRange.
7. Build CMS SignedData via Pkcs11ex.PDF.CMS.build_signed_data/3 (§5.3):
   - signedAttrs: contentType (id-data), messageDigest, signingTime.
   - external_message_digest = the SHA256 above (detached signature).
8. Sign DER(signedAttrs as SET-OF Attribute) via:
       Pkcs11ex.sign_bytes(signed_attrs_der,
         signer: opts[:signer], alg: opts[:alg],
         encoding_context: :der)
9. Inject the signature into SignerInfo, encode the full ContentInfo DER.
10. Hex-encode the DER bytes and write into the /Contents placeholder
    (zero-padded to fill exactly :contents_size).
11. Return the final byte stream.
```

**Verify flow.**

```
1. Locate the most recent /Sig dict (walk /Prev xref chain; first one wins).
2. Parse /ByteRange and /Contents.
3. Hash bytes covered by /ByteRange with the digestAlgorithm declared
   in CMS (must equal the alg's hash — library enforces this).
4. Parse Contents as DER ContentInfo.
5. Extract:
   - cert from SignedData.certificates (leaf as SignerInfo.sid match).
   - signed_attrs from SignerInfo.signed_attrs.
   - signature bytes from SignerInfo.signature.
   - alg from SignerInfo.signature_algorithm.
6. Build signer_hint = %{cms_signer_id: sid, cms_certs: [leaf | chain]}
   and run Pkcs11ex.Policy.resolve/2.            <-- ALLOWLIST GATE
7. Verify the messageDigest signed-attribute equals the hash from step 3.
8. Verify SHA256(DER(signed_attrs as SET-OF)) equals the value the
   sender signed.
9. Pkcs11ex.verify_bytes(signed_attrs_der, signature, leaf_pubkey,
                         alg: alg, encoding_context: :der).
10. Run Policy.validate/3, return {:ok, subject_id}.
```

**Error reasons (additions to api.md §4.1).**

| Reason | Class | Where |
|---|---|---|
| `:malformed_pdf` | PDF | xref/trailer scan failure |
| `:no_signature_dict` | PDF | verify on unsigned PDF |
| `:contents_size_exceeded` | PDF | sign: rendered CMS bigger than reserved |
| `:byterange_does_not_cover_file` | PDF | verify: PAdES rule that /ByteRange covers everything except /Contents itself |
| `:incremental_update_after_signature` | PDF | verify: untrusted bytes appended after the signed revision |
| `:digest_mismatch` | PDF | verify: messageDigest signed-attribute disagrees with the recomputed file hash |
| `:cms_malformed` | CMS | shared with XML |

### 4.2 `Pkcs11ex.XML`

Aligns with `docs/specs/api.md` §3.4. Spec deltas same shape as
PDF — propose them in api.md as part of Phase 4b ship.

```elixir
defmodule Pkcs11ex.XML do
  @moduledoc """
  XML-DSig + XAdES Baseline B (B-B) format adapter.

  Produces enveloped signatures (`<Signature>` inside the document)
  with Exclusive C14N 1.0 (XAdES default).

  Routes the signature primitive through Pkcs11ex.sign_bytes/2.
  """

  @type doc :: :xmerl.document() | binary()
  @type sign_opt ::
          {:signer, Pkcs11ex.signer_ref()}
          | {:alg, atom()}
          | {:x5c, binary() | [binary()]}
          | {:reference_uri, String.t()}              # default ""  (whole doc)
          | {:c14n_method, :exclusive_c14n_10}        # only choice in v1
          | {:digest_method, :sha256}                 # only choice in v1
          | {:signed_at, DateTime.t()}
          | {:signing_certificate_v2, boolean()}      # XAdES SigningCertificateV2 (default true)
          | {:inclusive_namespaces, [String.t()]}     # for ExcC14N InclusiveNamespaces

  @spec sign(doc(), [sign_opt()]) :: {:ok, :xmerl.document() | binary()} | {:error, term()}
  @spec verify(doc(), keyword()) :: {:ok, subject_id :: term()} | {:error, term()}
end
```

**Spec deltas to recommend in api.md §3.4.**

1. Make explicit that v1 ships **enveloped** signatures only.
   Detached and enveloping XML-DSig modes are out of scope for Phase
   4b. (XAdES B-B for SII / regulatory workflows is enveloped.)
2. Make `:x5c` mandatory (same reasoning as PDF / JWS).
3. Pin `:c14n_method` and `:digest_method` to a single supported
   value each in v1 — `:exclusive_c14n_10` and `:sha256` — and reject
   anything else with `:unsupported_canonicalization` /
   `:unsupported_digest`. Multi-mode comes when conformance demands it.
4. Return type: callers should be able to round-trip `binary() ->
   binary()` or `:xmerl.document() -> :xmerl.document()`. Concretely:
   if `doc` is `binary()`, return `binary()`; if `:xmerl.document()`,
   return `:xmerl.document()`. The current spec says `signed_doc ::
   :xmerl.document()` always — recommend updating to match input
   shape.

**Sign flow.**

```
1. Normalise input to :xmerl.document() (parse if binary).
2. Compute reference digest:
   2a. Apply enveloped-signature transform to the doc fragment
       referenced by :reference_uri (the whole doc by default — but
       NOT including the <Signature> we're about to insert).
   2b. Apply Exclusive C14N 1.0 with :inclusive_namespaces.
   2c. SHA-256 the canonical bytes.
3. Build <SignedInfo> element with:
   - <CanonicalizationMethod Algorithm="...exc-c14n#">
   - <SignatureMethod Algorithm="rsa-sha256-mgf1" /* PS256 */ />
   - <Reference URI="#...">:
       <Transforms>
         <Transform Algorithm="...enveloped-signature">
         <Transform Algorithm="...exc-c14n#">
       </Transforms>
       <DigestMethod Algorithm="...#sha256">
       <DigestValue>base64(digest from step 2)</DigestValue>
   - + a second <Reference> pointing at the XAdES <SignedProperties>
     (computed below).
4. Build XAdES <QualifyingProperties> with <SignedProperties>:
   - <SigningTime>
   - <SigningCertificateV2>: <CertDigest> (sha256 of the leaf cert)
                             <IssuerSerialV2> (DER(IssuerSerial) base64)
   Compute its Exclusive-C14N digest and patch into the second Reference.
5. Canonicalise <SignedInfo> via :exc-c14n#.
6. Sign via Pkcs11ex.sign_bytes(c14n_signed_info,
       signer: opts[:signer], alg: opts[:alg],
       encoding_context: :der).
7. Build <Signature>:
   <Signature>
     <SignedInfo>...</SignedInfo>
     <SignatureValue>base64(sig_bytes)</SignatureValue>
     <KeyInfo>
       <X509Data>
         <X509Certificate>base64(x5c[0])</X509Certificate>
         ... (chain certs)
       </X509Data>
     </KeyInfo>
     <Object>
       <xades:QualifyingProperties>...</xades:QualifyingProperties>
     </Object>
   </Signature>
8. Insert <Signature> into the document at the conventional spot
   (root element child by default; configurable later).
9. Return the modified :xmerl.document() (or serialise to binary
   matching the caller's input type).
```

**Verify flow.** Mirror sign:

```
1. Parse to :xmerl.document().
2. Locate <Signature>. {:error, :no_signature_element} if absent.
3. Extract:
   - <SignedInfo> (raw, by element identity in the source doc)
   - <SignatureValue>
   - <X509Certificate> entries from <KeyInfo>/<X509Data>
   - <SignedProperties> from <QualifyingProperties> (XAdES)
4. signer_hint = %{x5c: cert_ders, xades_cert_digest: ...}.
5. Pkcs11ex.Policy.resolve/2.                    <-- ALLOWLIST GATE
6. Recompute Reference digests:
   6a. For the data Reference: apply enveloped-signature transform,
       Exclusive C14N, SHA-256. Compare to <DigestValue>.
   6b. For the XAdES Reference: Exclusive C14N over <SignedProperties>,
       SHA-256. Compare to <DigestValue>.
   Mismatch on either -> {:error, :digest_mismatch}.
7. Canonicalise <SignedInfo> with the declared CanonicalizationMethod.
8. Pkcs11ex.verify_bytes(c14n_signed_info, sig_bytes, leaf_pubkey,
       alg: alg_from_signature_method, encoding_context: :der).
9. Verify XAdES SigningCertificateV2 binds the leaf cert (digest match).
10. Policy.validate/3, return {:ok, subject_id}.
```

**Error reasons (additions to api.md §4.1).**

| Reason | Class |
|---|---|
| `:malformed_xml` | XML |
| `:no_signature_element` | XML |
| `:multiple_signatures` | XML (v1: reject; multi-sig is Phase 4b.3) |
| `:unsupported_canonicalization` | XML |
| `:unsupported_digest` | XML |
| `:digest_mismatch` | XML |
| `:c14n_failure` | XML |
| `:xades_cert_binding_failed` | XML — SigningCertificateV2 doesn't match the X509Certificate in KeyInfo |

---

## 5. Phased delivery sequence

The shared dependency is the CMS module — both PAdES (PDF) and CAdES
(XML's underlying CMS-shaped signature scheme is XML-DSig, *not* CMS,
so this is more PDF-specific than universally shared, but) any future
detached-CAdES use case wants the same module. **CMS first, PDF
second, XML third.** Each row below is one commit-sized step.

### Phase 4a — CMS + PDF (PAdES B-B)

| # | Step | Lines (est) | Tests |
|---|---|---|---|
| 4a.0 | Vendor `'CryptographicMessageSyntax-2009'` ASN.1 records into a `Pkcs11ex.CMS.Records` module via `:public_key`'s API. Define struct wrappers `Pkcs11ex.CMS.{ContentInfo,SignedData,SignerInfo,SignedAttribute}`. | ~150 | Round-trip a known-good `.p7s` (e.g., RFC 5652 appendix C) through decode/re-encode. |
| 4a.1 | `Pkcs11ex.CMS.build_signed_attributes/1` — builds the SET-OF Attribute, including the open-type encoding for contentType / messageDigest / signingTime. | ~80 | Compare bytes against a fixture produced by `openssl cms -sign -nodetach -noattr=0`. |
| 4a.2 | `Pkcs11ex.CMS.signed_attrs_to_be_signed/1` — re-encodes signed attributes under the `[0] IMPLICIT` -> `SET OF` rule (the CMS gotcha). | ~30 | Bit-exact match to the openssl reference. |
| 4a.3 | `Pkcs11ex.CMS.build_signed_data/3` — given (signedAttrs, signature_bytes, x5c), assemble the `ContentInfo` envelope. | ~120 | OpenSSL parses the output; bouncycastle (offline reference) parses the output. |
| 4a.4 | `Pkcs11ex.CMS.parse_signed_data/1` — inverse direction. Returns `%Pkcs11ex.CMS.Parsed{}` with the leaf cert as `%Pkcs11ex.X509{}`. | ~100 | Round-trip with 4a.3 outputs. |
| 4a.5 | Wire `:cms_malformed` and any CMS-specific errors into `api.md` §4.1. | docs | n/a |
| 4a.6 | `Pkcs11ex.PDF.Reader` — minimal trailer/xref scanner (text-trailer mode). | ~150 | Test corpus: 5+ PDFs from `pdfa.org` reference suite, plus `pdftk` outputs. |
| 4a.7 | `Pkcs11ex.PDF.Writer` — incremental-update emitter with `/Sig` placeholder. | ~200 | Output validates with `pdfsig` (Poppler) and `verifypdf` (BouncyCastle). |
| 4a.8 | `Pkcs11ex.PDF.sign/2` end-to-end. | ~80 | Sign a corpus PDF with SoftHSM2-backed PS256, verify via OpenSSL `cms -verify` against the cert. |
| 4a.9 | `Pkcs11ex.PDF.verify/2` end-to-end (allowlist gate, math, policy). | ~100 | Round-trip from 4a.8. Negative cases: tampered byte after sign, tampered byte before sign, swapped signer cert, out-of-allowlist signer (PinnedRegistry). |
| 4a.10 | `:incremental_update_after_signature` detection — verify that no bytes appended after the signed revision modify the signed scope. | ~50 | Synthetic test: append a benign comment + new xref after the signed revision; verify it is detected. |
| 4a.11 | Telemetry, error-class wiring, `subject_id` propagation. | ~30 | Existing `:telemetry` test pattern. |

**4a exit criteria.** PAdES B-B sign/verify round-trips against the
`pdfa.org` reference corpus AND against Adobe Reader's
"Signatures" panel showing the signature as valid (manual cross-
check on at least 3 PDFs).

### Phase 4b.1 — XML adapter on `xmerl_c14n`

| # | Step | Lines (est) | Tests |
|---|---|---|---|
| 4b.1.0 | Vendor `xmerl_c14n` from esaml into `lib/pkcs11ex/xml/c14n/` with attribution + BSD-2 LICENSE preserved. | ~600 (vendored) | The repo's own test cases. |
| 4b.1.1 | Run W3C exc-c14n test suite against the vendored module. Document pass/fail per case. | n/a (test) | W3C exc-c14n testdata. |
| 4b.1.2 | Decision gate: if pass-rate < 100% on the cases relevant to XAdES, jump to 4b.2 (NIF fallback). Else continue. | n/a | n/a |
| 4b.1.3 | `Pkcs11ex.XML.Builder` — `<SignedInfo>` / `<Reference>` / `<Transforms>` element construction. | ~200 | Round-trip with 4b.1.4 verify. |
| 4b.1.4 | `Pkcs11ex.XML.XAdES` — `<QualifyingProperties>` + `<SigningCertificateV2>`. | ~150 | Cross-verify with `xmlsec1` CLI (libxmlsec). |
| 4b.1.5 | `Pkcs11ex.XML.sign/2` end-to-end. | ~80 | Sign a SII-DTE-shaped fixture (Chilean tax document, public schema), verify with `xmlsec1 --xades`. |
| 4b.1.6 | `Pkcs11ex.XML.verify/2` end-to-end (allowlist gate, math, policy). | ~100 | Round-trip and negative cases. |
| 4b.1.7 | Telemetry, error-class wiring. | ~30 | Existing pattern. |

**4b.1 exit criteria.** XAdES B-B sign produces output that
`xmlsec1 --xades --verify` reports as valid against the same x5c
chain. Tampered-document detection passes.

### Phase 4b.2 — XML fallback to `bergshamra` NIF (only if 4b.1.2 fails)

| # | Step |
|---|---|
| 4b.2.0 | Add `bergshamra = "0.4"` to `native/pkcs11ex_nif/Cargo.toml`. |
| 4b.2.1 | Implement `xml_c14n` NIF (signature in §3.2). Add `Error::Canonicalization` variant + atom. |
| 4b.2.2 | Replace the vendored `xmerl_c14n` calls in `Pkcs11ex.XML.Canonicalizer` with the NIF. Same signature in/out. |
| 4b.2.3 | Re-run the W3C suite. Re-run 4b.1.5 / 4b.1.6 / 4b.1.7. |

**4b.2 exit criteria.** Same as 4b.1, with the C14N path provably
covering all 6 W3C variants (test-suite output captured).

### Phase 4 wrap-up

- Update `api.md` §3.3 and §3.4 with the proposed deltas (§4 of this
  plan), turning the placeholders into canonical sections.
- Update `specs.md` §10 (Non-Goals) to spell out: B-T, B-LT, B-LTA;
  detached / enveloping XML-DSig; multi-signature PDFs (a single
  signature per document is the v1 contract); xref-stream-only PDFs
  beyond what the verify-side fallback handles.
- Replace the moduledoc warnings in `lib/pkcs11ex/pdf.ex` and
  `lib/pkcs11ex/xml.ex` with the actual usage docstrings.

---

## 6. Open questions

1. **Test corpus — PDFs.** What's the canonical Chilean SII / Shinkansen
   PDF fixture set we should sign-and-verify against? The
   `pdfa.org` reference suite covers structural variety; we likely need
   a real-world counterpart from the operator side that mirrors what
   `pkcs11ex` consumers will actually sign. Maintainer call.
2. **Test corpus — XML.** Same question for the SII DTE schema /
   Shinkansen-internal envelope. The W3C test data covers C14N
   correctness; we still need an end-to-end XAdES B-B fixture that
   mirrors the production envelope shape.
3. **OCSP/CRL revocation in PDF/XML verify.** The §2.3 verify pipeline
   plumbs `:crl_fetcher` and `:ocsp_check` for the JWS path. PAdES B-B
   itself does not embed validation material (B-LT does), so revocation
   is the policy's call. For Phase 4 v1 do we keep parity (revocation
   active when the policy demands it) or punt to the same Phase-5
   audit work that handles B-T? Recommendation: parity — if
   `CASignedAllowlist` is the policy, revocation is checked; the policy
   is unaware of the format. Confirm before locking it in.
4. **`/Contents` placeholder default size.** 16 KiB is a common
   industry default and fits PS256 + a 3-cert chain comfortably. Adobe
   Acrobat ships 32 KiB. If we expect Phase 5 to bring B-T (timestamp
   adds another ~6 KiB), defaulting to 32 KiB now avoids a backward-
   compat headache later. Maintainer call: 16 KiB or 32 KiB default?
5. **PDF input shape.** Drop `Enumerable.t()` from `sign/2` for v1
   (recommended in §4.1)? If the user has a streaming use case, what
   does it look like? The brief uses "multi-GB PDFs" as the
   motivation; do we have a concrete consumer for that, or is it
   future-proofing we can cut now?
6. **Multi-signature PDFs on verify.** A PDF can carry multiple
   signatures (counter-signing, sequential approvals). v1 verifies
   the most recent one; what does the API surface look like for a
   caller that wants to assert "all signatures pass + each maps to a
   subject_id"? Phase 4b.3 territory; needs design.
7. **`xmerl_c14n` provenance.** The repository hasn't seen activity
   since 2019. We have the option to vendor (BSD-2 permits) or to
   contribute upstream. Vendoring is the lower-friction call given
   the apparent dormancy; reach out to maintainers regardless? Light
   touch courtesy.
8. **`bergshamra` track record.** It's ~12 weeks old at our writing.
   For Phase 4b fallback this is fine because it's behind a feature
   gate, but the question of when to commit to it (or to invest in a
   pure-OTP exclusive-C14N implementation if neither pans out) needs
   a 6-month review.
9. **Streaming hash for `digest_stream/2`.** The Layer 2 spec offers
   `digest_stream/2` "for multi-GB artifacts". Phase 4 PAdES verify
   is one of those callers. The current implementation does
   `:crypto.hash_init/1` -> incremental updates; PDF byte-range can
   feed it from `File.stream!`. Confirm this is the intended path
   (rather than slurping the file).
10. **CL-SII hard interop.** Is the SII DTE the explicit production
    target for the XML adapter at v1, or are there parallel targets
    (other regulators, other countries)? The XAdES profile differs in
    minor ways across regulators (e.g., signed-properties references,
    namespace declarations). Phase 4b.1 needs to know the primary
    target to set acceptance.

---

## 7. Risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation | Fallback |
|---|---|---|---|---|---|
| R1 | OTP `'CryptographicMessageSyntax-2009'` open-type Attribute encoding has subtle bugs we don't catch in fixture testing. | Medium | High (signed PDFs that vendor PDF readers reject) | Cross-validate every test signature with both `openssl cms -verify` and `pdfsig` (Poppler). Adobe Reader manual smoke test at the 4a exit gate. | Swap the CMS module for a `cms` Rust NIF wrapper (4a.0–4a.4 are isolated). |
| R2 | `xmerl_c14n` C14N output disagrees with `xmlsec1` on edge cases (xml:base, default namespaces in XAdES properties). | Medium | High (regulator-rejected XAdES) | Run the W3C exc-c14n testdata at 4b.1.2 as a hard gate. | Phase 4b.2: NIF-wrap `bergshamra`. Plan and budget already account for this. |
| R3 | `bergshamra` is abandoned mid-Phase-5 if we end up depending on it. | Low | Medium (we'd need to either vendor or replace) | License is BSD-2 — vendoring is permitted. The crate footprint is bounded; we know what we'd own. | Vendor at the point of dependency; at worst that's ~22 MB of audited Rust. |
| R4 | `lopdf` API churn if we adopt it for verify-side xref-stream support. | Medium (active 0.x) | Low | Pin to `0.40.0` exactly; review on each minor bump. | Hand-roll xref-stream support — it's another ~200 lines, and we already own the writer side. |
| R5 | License shift on a transitive dep (e.g., a `cms` upstream changes from MIT to GPL — extremely unlikely but the tail isn't zero). | Very Low | Critical | The crates we recommend (`bergshamra`, conditional only) lock licenses at adoption time. We pin exact versions in `Cargo.toml`. | Hold the previous version until a license-clean replacement emerges. |
| R6 | NIF stability — adding `bergshamra` brings new transitive deps that conflict with `cryptoki` 0.12 / `parking_lot` 0.12. | Low | Medium | Run `cargo tree` at adoption; flag any version skew. | Worst case: vendor `bergshamra-c14n` (the workspace member) without the rest of the workspace. |
| R7 | Hand-rolled PDF writer breaks on a real-world PDF whose trailer the scanner doesn't expect (e.g., a hybrid xref + xref-stream file). | Medium | High | Sign produces — we never read existing trailer in a non-trivial way; sign is robust. Verify is the side at risk; it scans an existing file. Mitigation: 5+ corpus PDFs across vendor outputs (Adobe, LibreOffice, Foxit, pdftk, Ghostscript) at 4a.6. | Verify-only escape hatch: try the hand-rolled scanner first; on `:malformed_pdf`, retry via `lopdf` parse. Two-tier verification. |
| R8 | Cert chain length / `/Contents` size mismatch in production: we picked 16 KiB, the operator's chain plus B-T grows to 18 KiB. | Low | Medium (sign fails with `:contents_size_exceeded`) | `:contents_size` is a public opt; document it. Set default to 32 KiB if Open Question 4 lands that way. | Doc it at v1 + emit a clear error reason. |
| R9 | We discover at 4b.1.2 that `xmerl_c14n` works for SII DTE specifically but not the W3C corpus. Do we ship a SII-only solution? | Medium | Low (if scoped) | If 4b.1.2 passes the SII-shaped tests but fails W3C corner cases that DTE doesn't exercise, document the gap and ship 4b.1 anyway. Mark the crate "SII DTE qualified" and gate the general-purpose use behind 4b.2. | 4b.2 is the general-purpose path; both can ship side-by-side with a `:c14n_backend` opt. |
| R10 | The `Pkcs11ex.Algorithm.PS256.encode_signature/2` path with `:der` context returns identity bytes for RSA — but for ECDSA (when `:ES256` lands) the CMS context wants DER `SEQUENCE(r,s)` while JWS wants raw `r‖s`. PDF/XML must pass `encoding_context: :der`. | High (foot-gun for v2) | Medium | Lock the contract in code: PDF/XML adapters always pass `:der`; JWS always passes `:jose`. Add a test that confirms this for every algorithm registered. | Catch in CI. |

---

## 8. Appendix — concrete CMS encoding notes

For implementer reference. None of this is policy; it's just the
"what does OTP want?" question answered up front so 4a.0–4a.3 are
quick.

**`SignedAttributes` is `IMPLICIT [0] SET OF Attribute`** in
`SignerInfo`. The bytes-to-sign for the signature use **`SET OF
Attribute`** instead — i.e., the implicit tag is replaced with a
universal `SET OF`. OTP's `'CryptographicMessageSyntax-2009'` exposes
both `'SignedAttributes'` and `'Attributes'` types. The signing-input
is `public_key:der_encode('Attributes', AttrsList)` — the universal
form.

**Open-type Attributes.** The `Attribute` ASN.1 type is:

```asn1
Attribute ::= SEQUENCE {
    attrType   OBJECT IDENTIFIER,
    attrValues SET OF AttributeValue }
AttributeValue ::= ANY
```

OTP encodes `ANY` via `{:asn1_OPENTYPE, der_bytes}`. So building a
`messageDigest` attribute looks like:

```elixir
content_type_oid = {1, 2, 840, 113549, 1, 9, 3}
message_digest_oid = {1, 2, 840, 113549, 1, 9, 4}
signing_time_oid = {1, 2, 840, 113549, 1, 9, 5}

# id-data (CMS content type) for PAdES detached:
data_oid = {1, 2, 840, 113549, 1, 7, 1}
content_type_attr_value =
  :public_key.der_encode(:'ContentType', data_oid)

content_type_attr = {
  :'Attribute',
  content_type_oid,
  [{:asn1_OPENTYPE, content_type_attr_value}]
}

message_digest_attr_value =
  :public_key.der_encode(:'MessageDigest', sha256_of_doc)

message_digest_attr = {
  :'Attribute',
  message_digest_oid,
  [{:asn1_OPENTYPE, message_digest_attr_value}]
}

signing_time_attr_value =
  :public_key.der_encode(:'SigningTime', {:utcTime, ~c"260502130000Z"})

signing_time_attr = {
  :'Attribute',
  signing_time_oid,
  [{:asn1_OPENTYPE, signing_time_attr_value}]
}

# 1) Encode for the SignerInfo's signed_attrs slot — IMPLICIT [0]:
{:ok, signed_attrs_for_signerinfo} =
  :public_key.der_encode(:'SignedAttributes',
    [content_type_attr, message_digest_attr, signing_time_attr])

# 2) Encode for the bytes-to-sign — universal SET OF:
{:ok, signed_attrs_to_sign} =
  :public_key.der_encode(:'Attributes',
    [content_type_attr, message_digest_attr, signing_time_attr])

# Sign #2 via Pkcs11ex.sign_bytes/2; embed the signature plus #1
# inside the SignerInfo struct.
```

(Note: Names like `:'ContentType'` and `:'MessageDigest'` are the
ASN.1 types OTP exposes from `'PKCS-9'` — verify the exact names at
4a.0.)

**Content of the encapsulated content info.** PAdES detached means
`encapContentInfo.eContent` is absent. OTP encodes that as
`{:asn1_NOVALUE}` in the corresponding `EncapsulatedContentInfo`
record field. The `eContentType` is `id-data` (`1.2.840.113549.1.7.1`).

**SubFilter.** The PDF `/Sig` dictionary's `/SubFilter` is
`/ETSI.CAdES.detached` (PAdES B-B). Adobe's older
`/adbe.pkcs7.detached` is interoperable but not PAdES-conformant; we
emit `/ETSI.CAdES.detached`.

---

## 9. Appendix — references

- RFC 5652 (CMS) — https://www.rfc-editor.org/rfc/rfc5652
- ETSI EN 319 142-1 (PAdES) — https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/
- ETSI EN 319 132-1 (XAdES) — https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/
- W3C XML-DSig 1.1 — https://www.w3.org/TR/xmldsig-core1/
- W3C Exclusive XML Canonicalization 1.0 — https://www.w3.org/TR/xml-exc-c14n/
- RustCrypto `cms` — https://docs.rs/cms
- `lopdf` — https://docs.rs/lopdf
- `bergshamra` — https://lib.rs/crates/bergshamra
- `xmerl_c14n` (esaml-derived) — https://github.com/DoggettCK/xmerl_c14n
- OTP `'CryptographicMessageSyntax-2009'` schema — https://github.com/erlang/otp/blob/master/lib/public_key/asn1/CryptographicMessageSyntax-2009.asn1
- pdfium-binaries (license context) — https://github.com/bblanchon/pdfium-binaries
