defmodule Pkcs11ex.CMS.Parsed do
  @moduledoc """
  Output of `Pkcs11ex.CMS.SignedData.parse/1` — a struct with the
  fields a verify pipeline actually needs, plus the original DER for
  audit / re-emission.

  The struct is intentionally narrow: only the fields used by
  `Pkcs11ex.PDF.verify/2` (and any future CAdES verify path) live here.
  Callers that need deeper introspection should use
  `Pkcs11ex.CMS.Codec.decode/2` directly.
  """

  alias Pkcs11ex.X509

  @type digest_algorithm :: :sha256 | :sha384 | :sha512
  @type signature_algorithm :: :rsa_sha256 | :rsa_pss_sha256

  defstruct [
    :der,
    :signed_attrs,
    :to_be_signed,
    :signature,
    :digest_algorithm,
    :signature_algorithm,
    :leaf,
    :certificates,
    :content_oid,
    :message_digest,
    :signing_time
  ]

  @typedoc """
  Fields:

    * `:der` — the original ContentInfo DER (binary).
    * `:signed_attrs` — raw `Attribute` tuples as the OTP codec emits
      them. Useful for callers that want to inspect non-required
      attributes.
    * `:to_be_signed` — DER of `signedAttrs` re-encoded under the
      universal `SET OF Attribute` tag. This is the input the signer
      committed to; verifiers feed it to `:public_key.verify/4` (or
      `Pkcs11ex.verify_bytes/3`).
    * `:signature` — raw signature bytes lifted from `SignerInfo.signature`.
    * `:digest_algorithm` / `:signature_algorithm` — atom shorthands for
      the algorithm OIDs found inside `SignerInfo`.
    * `:leaf` — the leaf signing certificate as a parsed `Pkcs11ex.X509`.
      This is the cert whose `IssuerAndSerialNumber` matches the
      `SignerInfo.sid`.
    * `:certificates` — the full embedded chain (leaf first), every
      entry parsed.
    * `:content_oid` — the `eContentType` OID from
      `EncapsulatedContentInfo`. For PAdES B-B this should be `id-data`.
    * `:message_digest` — the bytes carried in the `messageDigest`
      signed attribute. Verify must compare this to the freshly
      computed digest of the document.
    * `:signing_time` — `DateTime.t()` lifted from the `signingTime`
      attribute, or `nil` if absent. Informational only — the bytes
      were committed to but the signer chose them; trustworthy
      time-binding lives in RFC 3161 timestamps (Phase 5).
  """
  @type t :: %__MODULE__{
          der: binary(),
          signed_attrs: [tuple()],
          to_be_signed: binary(),
          signature: binary(),
          digest_algorithm: digest_algorithm() | {:unknown_oid, tuple()},
          signature_algorithm: signature_algorithm() | {:unknown_oid, tuple()},
          leaf: X509.t(),
          certificates: [X509.t()],
          content_oid: tuple(),
          message_digest: binary(),
          signing_time: DateTime.t() | nil
        }
end
