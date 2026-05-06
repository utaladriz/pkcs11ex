defmodule Pkcs11ex.CMS.OIDs do
  @moduledoc """
  Well-known ASN.1 object identifiers used by CMS / PKCS#7 / PKCS#9.

  All OIDs are returned as the tuple form OTP's ASN.1 runtime expects
  (e.g., `{1, 2, 840, 113549, 1, 7, 2}` for `id-signedData`).

  Centralising these prevents mistyping and gives one place to look up
  the dotted-decimal form a verifier might log.
  """

  # PKCS#7 / RFC 5652 content types — `1.2.840.113549.1.7.*`
  @id_data {1, 2, 840, 113_549, 1, 7, 1}
  @id_signed_data {1, 2, 840, 113_549, 1, 7, 2}

  # PKCS#9 attributes — `1.2.840.113549.1.9.*`
  @id_content_type {1, 2, 840, 113_549, 1, 9, 3}
  @id_message_digest {1, 2, 840, 113_549, 1, 9, 4}
  @id_signing_time {1, 2, 840, 113_549, 1, 9, 5}

  # S/MIME attributes — `1.2.840.113549.1.9.16.2.*`
  # `id-aa-signatureTimeStampToken` per RFC 3161 §3.3.4. Embedded in
  # CMS `unsignedAttrs` to carry an RFC 3161 TimeStampToken anchoring
  # the SignerInfo's `signature` field — the canonical PAdES /
  # CAdES B-T attribute.
  @id_aa_signature_timestamp {1, 2, 840, 113_549, 1, 9, 16, 2, 14}

  # NIST hash algorithms — `2.16.840.1.101.3.4.2.*`
  @id_sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @id_sha384 {2, 16, 840, 1, 101, 3, 4, 2, 2}
  @id_sha512 {2, 16, 840, 1, 101, 3, 4, 2, 3}

  # PKCS#1 RSA signature algorithms — `1.2.840.113549.1.1.*`
  @id_rsassa_pss {1, 2, 840, 113_549, 1, 1, 10}
  @id_sha256_with_rsa {1, 2, 840, 113_549, 1, 1, 11}

  @doc "`id-data` — RFC 5652 §4."
  def id_data, do: @id_data

  @doc "`id-signedData` — RFC 5652 §5.1."
  def id_signed_data, do: @id_signed_data

  @doc "`id-contentType` PKCS#9 attribute — RFC 5652 §11.1."
  def id_content_type, do: @id_content_type

  @doc "`id-messageDigest` PKCS#9 attribute — RFC 5652 §11.2."
  def id_message_digest, do: @id_message_digest

  @doc "`id-signingTime` PKCS#9 attribute — RFC 5652 §11.3."
  def id_signing_time, do: @id_signing_time

  @doc "SHA-256 digest algorithm OID."
  def id_sha256, do: @id_sha256

  @doc "SHA-384 digest algorithm OID."
  def id_sha384, do: @id_sha384

  @doc "SHA-512 digest algorithm OID."
  def id_sha512, do: @id_sha512

  @doc "RSASSA-PSS signature algorithm OID — RFC 4056."
  def id_rsassa_pss, do: @id_rsassa_pss

  @doc "`sha256WithRSAEncryption` (RSA PKCS#1 v1.5 + SHA-256)."
  def id_sha256_with_rsa, do: @id_sha256_with_rsa

  @doc "`id-aa-signatureTimeStampToken` PKCS#9/SMIME attribute — RFC 3161 §3.3.4."
  def id_aa_signature_timestamp, do: @id_aa_signature_timestamp
end
