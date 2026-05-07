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

  Record.defrecordp(
    :validity,
    :Validity,
    Record.extract(:Validity, from_lib: "public_key/include/public_key.hrl")
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

  @doc """
  Returns the certificate's validity window as `{not_before, not_after}`
  DateTimes (UTC). The Time CHOICE in X.509 (UTCTime / GeneralizedTime)
  is decoded per RFC 5280 §4.1.2.5.
  """
  @spec validity_window(t()) :: {DateTime.t(), DateTime.t()} | :error
  def validity_window(%__MODULE__{otp_cert: cert}) do
    tbs = otp_certificate(cert, :tbsCertificate)
    val = otp_tbs_certificate(tbs, :validity)
    not_before = decode_time(validity(val, :notBefore))
    not_after = decode_time(validity(val, :notAfter))

    case {not_before, not_after} do
      {%DateTime{} = nb, %DateTime{} = na} -> {nb, na}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  @doc """
  Checks whether `at` falls within the certificate's validity window
  (inclusive). Returns `:ok` or `{:error, :cert_not_yet_valid |
  :cert_expired | :cert_validity_unparseable}`.
  """
  @spec check_validity(t(), DateTime.t()) :: :ok | {:error, atom()}
  def check_validity(%__MODULE__{} = cert, %DateTime{} = at) do
    case validity_window(cert) do
      {nb, na} ->
        cond do
          DateTime.compare(at, nb) == :lt -> {:error, :cert_not_yet_valid}
          DateTime.compare(at, na) == :gt -> {:error, :cert_expired}
          true -> :ok
        end

      :error ->
        {:error, :cert_validity_unparseable}
    end
  end

  # Time CHOICE: {utcTime, charlist} | {generalTime, charlist}.
  # UTCTime: YYMMDDHHMMSSZ; GeneralizedTime: YYYYMMDDHHMMSSZ.
  # RFC 5280 §4.1.2.5.1: YY < 50 → 20YY, else 19YY.
  defp decode_time({:utcTime, charlist}) do
    case List.to_string(charlist) do
      <<yy::binary-2, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2, "Z">> ->
        full_year =
          case String.to_integer(yy) do
            n when n < 50 -> 2000 + n
            n -> 1900 + n
          end

        build_datetime(full_year, mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

  defp decode_time({:generalTime, charlist}) do
    case List.to_string(charlist) do
      <<yyyy::binary-4, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2,
        "Z">> ->
        build_datetime(String.to_integer(yyyy), mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

  defp decode_time(_), do: nil

  defp build_datetime(year, mm, dd, hh, mi, ss) do
    with {:ok, date} <- Date.new(year, String.to_integer(mm), String.to_integer(dd)),
         {:ok, time} <-
           Time.new(String.to_integer(hh), String.to_integer(mi), String.to_integer(ss)),
         {:ok, naive} <- NaiveDateTime.new(date, time),
         {:ok, dt} <- DateTime.from_naive(naive, "Etc/UTC") do
      dt
    else
      _ -> nil
    end
  end
end
