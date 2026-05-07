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

  defstruct [:der, :public_key, :otp_cert, :spki_sha256]

  @type otp_cert :: tuple()

  @type t :: %__MODULE__{
          der: binary(),
          public_key: term(),
          otp_cert: otp_cert(),
          spki_sha256: binary()
        }

  @doc """
  Decodes a DER-encoded X.509 certificate into a `SignCore.X509` struct.

  Returns `{:error, :invalid_cert}` for malformed DER. Does **not** validate
  the certificate (no validity-period check, no chain validation, no signature
  check); decoding is a structural operation only — trust decisions live in
  `SignCore.Policy`.

  The SPKI SHA-256 pin (used by `SignCore.Policy.PinnedRegistry`) is
  computed once at construction and cached on the struct — `spki_sha256/1`
  is then a constant-time field read instead of two repeated ASN.1 passes
  per verify.
  """
  @spec from_der(binary()) :: {:ok, t()} | {:error, :invalid_cert}
  def from_der(der) when is_binary(der) do
    cert = :public_key.pkix_decode_cert(der, :otp)
    tbs = otp_certificate(cert, :tbsCertificate)
    spki = otp_tbs_certificate(tbs, :subjectPublicKeyInfo)
    pubkey = otp_subject_public_key_info(spki, :subjectPublicKey)

    {:ok,
     %__MODULE__{
       der: der,
       public_key: pubkey,
       otp_cert: cert,
       spki_sha256: compute_spki_sha256(der)
     }}
  rescue
    _ -> {:error, :invalid_cert}
  end

  @doc """
  Returns the SHA-256 hash of the leaf's `subjectPublicKeyInfo`
  (DER-encoded), hex-lowercase — the canonical "SPKI pin" used by
  `SignCore.Policy.PinnedRegistry`.

  Cached on the struct at `from_der/1` time; this function is now a
  field read.
  """
  @spec spki_sha256(t()) :: binary()
  def spki_sha256(%__MODULE__{spki_sha256: hash}), do: hash

  # Re-decodes the cert in `:plain` ASN.1 form because OTP's
  # `der_encode` doesn't accept `:OTPSubjectPublicKeyInfo` — only the
  # plain `:SubjectPublicKeyInfo` record encodes cleanly. Called once
  # per cert at `from_der/1` time; the result is stashed on the struct.
  defp compute_spki_sha256(der) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    plain_tbs = elem(plain_cert, 1)
    plain_spki = elem(plain_tbs, 7)
    spki_der = :public_key.der_encode(:SubjectPublicKeyInfo, plain_spki)
    :crypto.hash(:sha256, spki_der) |> Base.encode16(case: :lower)
  end
end
