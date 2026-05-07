defmodule SignCore.X509 do
  @moduledoc """
  Thin wrapper around an OTP `:public_key`-decoded X.509 certificate.

  The library operates on this struct rather than raw DER so cert-resolution
  policies and the verify pipeline don't redo ASN.1 work on every call. The
  underlying `otp_cert` is kept around for chain validation, name comparisons,
  and any downstream X.509 inspection a custom policy needs.
  """

  require Record

  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :otp_tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :otp_subject_public_key_info,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  defstruct [:der, :public_key, :otp_cert]

  @type otp_cert :: tuple()

  @type t :: %__MODULE__{
          der: binary(),
          public_key: term(),
          otp_cert: otp_cert()
        }

  @doc """
  Decodes a DER-encoded X.509 certificate into a `SignCore.X509` struct.

  Returns `{:error, :invalid_cert}` for malformed DER. Does **not** validate
  the certificate (no validity-period check, no chain validation, no signature
  check); decoding is a structural operation only — trust decisions live in
  `SignCore.Policy`.
  """
  @spec from_der(binary()) :: {:ok, t()} | {:error, :invalid_cert}
  def from_der(der) when is_binary(der) do
    cert = :public_key.pkix_decode_cert(der, :otp)
    tbs = otp_certificate(cert, :tbsCertificate)
    spki = otp_tbs_certificate(tbs, :subjectPublicKeyInfo)
    pubkey = otp_subject_public_key_info(spki, :subjectPublicKey)

    {:ok, %__MODULE__{der: der, public_key: pubkey, otp_cert: cert}}
  rescue
    _ -> {:error, :invalid_cert}
  end

  @doc """
  Computes the SHA-256 hash of the leaf's `subjectPublicKeyInfo` (DER-encoded),
  hex-lowercase. This is the canonical "SPKI pin" used by
  `SignCore.Policy.PinnedRegistry`.

  Implementation note: re-decodes the cert in `:plain` ASN.1 form because OTP's
  `pkix_encode` doesn't accept `:OTPSubjectPublicKeyInfo`. The plain SPKI
  record encodes cleanly via `der_encode(:SubjectPublicKeyInfo, ...)`. The
  one-time decode cost is paid only on registry lookups and verify, not on
  sign.
  """
  @spec spki_sha256(t()) :: binary()
  def spki_sha256(%__MODULE__{der: der}) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    plain_tbs = elem(plain_cert, 1)
    plain_spki = elem(plain_tbs, 7)
    spki_der = :public_key.der_encode(:SubjectPublicKeyInfo, plain_spki)
    :crypto.hash(:sha256, spki_der) |> Base.encode16(case: :lower)
  end
end
