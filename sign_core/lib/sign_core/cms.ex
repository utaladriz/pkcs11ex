defmodule SignCore.CMS do
  @moduledoc """
  Cryptographic Message Syntax (RFC 5652) primitives for `pkcs11ex`.

  > #### Status — Phase 4a step 0 {: .info}
  >
  > Skeleton module. Currently exposes only the OID constants and a thin
  > encode/decode wrapper over OTP's `:CryptographicMessageSyntax-2009`
  > ASN.1 codec. The full SignedData construction lands incrementally
  > across Phase 4a steps 1-4 per `docs/plans/phase4-pdf-xml-implementation.md`.

  ## Why this lives in pure Elixir

  The OTP `public_key` application ships a compiled
  `'CryptographicMessageSyntax-2009'` ASN.1 codec that produces and
  consumes RFC 5652 structures. The codec auto-recurses through the
  information-object-class mappings (ContentInfo's `content` field is
  resolved by `contentType`), so we hand it Elixir tuples shaped after
  the ASN.1 module and get back DER without owning the byte-level
  encoding rules ourselves.

  The signing primitive itself is hardware-backed: `SignCore.CMS` builds
  the to-be-signed bytes (the DER of `signedAttrs` re-tagged as
  `SET OF Attribute` per RFC 5652 §5.4), and the caller signs them via
  `Pkcs11ex.sign_bytes/2`. The CMS module never touches a private key.

  ## Layered architecture

  This module is **Layer 2.5** — a primitive shared by Layer 3 format
  adapters (`SignCore.PDF` PAdES, future `Pkcs11ex.CAdES`). Like
  `SignCore.JWS`, it composes Layer 2 (`Pkcs11ex.sign_bytes/2`) and
  produces a wire format. Unlike JWS, the wire format is binary DER,
  not Base64URL JSON.

  ## Roadmap (per `docs/plans/phase4-pdf-xml-implementation.md`)

    * 4a.0 (this commit) — module skeleton, codec wrapper, OID constants.
    * 4a.1 — `build_signed_attributes/1` (contentType, messageDigest, signingTime).
    * 4a.2 — `signed_attrs_to_be_signed/1` (the `[0] IMPLICIT` → `SET OF` re-tag).
    * 4a.3 — `build_signed_data/3` (assemble the ContentInfo envelope).
    * 4a.4 — `parse_signed_data/1` (inverse direction).
  """
end
