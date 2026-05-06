defmodule Pkcs11ex.CMS.SignedData do
  @moduledoc """
  Assemble a CMS `SignedData` `ContentInfo` envelope (RFC 5652 §5).

  The hardware signature is supplied by the caller — this module never
  signs. The expected flow:

      {:ok, attrs} = Pkcs11ex.CMS.SignedAttributes.build(digest: payload_digest)
      {:ok, tbs}   = Pkcs11ex.CMS.SignedAttributes.to_be_signed(attrs)
      {:ok, sig}   = Pkcs11ex.sign_bytes(tbs, signer: {:platform, :signing}, alg: :PS256)
      {:ok, der}   = Pkcs11ex.CMS.SignedData.build(attrs, sig,
                       certificates: [leaf_x509 | issuer_x509s],
                       digest_algorithm: :sha256,
                       signature_algorithm: :rsa_pss_sha256)

  The result is a self-contained DER blob suitable for embedding in
  PAdES `/Contents`, an XML `<Object>` element, or any other CMS-shaped
  envelope. The PAdES adapter glues this DER (hex-encoded) into the
  reserved `/Contents` placeholder.

  ## What ships in v1

    * One `SignerInfo` per envelope (single-signer documents — the
      Phase 4 contract).
    * `IssuerAndSerialNumber` signer identifier (CMS version 1). The
      `SubjectKeyIdentifier` form (CMS version 3) lands later if the
      maintainer asks; PAdES B-B defaults to issuer+serial.
    * Detached content (`eContent` absent) — the signed payload is the
      bytes covered by `/ByteRange`, not embedded inside the CMS.
    * `unsignedAttrs` omitted (B-B specifically — B-T's timestamp token
      lives there in Phase 5 work).

  ## What's deferred

    * Multi-signer SignedData (counter-signing).
    * `SubjectKeyIdentifier` signer identifier (CMS v3).
    * `OriginatorInfo`, `crls`, `attribute certificates` (none needed
      for B-B).
    * Embedded eContent (the EncapsulatedContentInfo eContent field is
      always absent in this v1 — detached signatures only).
  """

  alias Pkcs11ex.CMS.{Codec, OIDs, Parsed}
  alias Pkcs11ex.X509

  @typedoc """
  Per-call options for `build/3`.

  Required:
    * `:certificates` — `[Pkcs11ex.X509.t() | binary()]`. Leaf first,
      then any issuers / intermediates the verifier may need. Each
      entry can be a parsed `Pkcs11ex.X509` struct or a raw DER binary
      (parsed inline). The leaf identifies the signer for the
      `IssuerAndSerialNumber` field.

  Optional:
    * `:digest_algorithm` — `:sha256` (default) | `:sha384` | `:sha512`.
    * `:signature_algorithm` — `:rsa_sha256` (default — PKCS#1 v1.5) |
      `:rsa_pss_sha256`. Match the algorithm the hardware actually
      produced; the OID lands inside `SignerInfo.signatureAlgorithm`.
    * `:content_oid` — defaults to `id-data`. Must match the
      `:content_oid` passed to `SignedAttributes.build/1`; the codec
      doesn't cross-check.
  """
  @type build_opts :: keyword()

  @doc """
  Assemble a SignedData ContentInfo from already-built signedAttrs,
  the hardware-produced signature bytes, and the certificate chain.
  """
  @spec build(signed_attrs :: [tuple()], signature :: binary(), opts :: build_opts()) ::
          {:ok, binary()} | {:error, term()}
  def build(signed_attrs, signature, opts)
      when is_list(signed_attrs) and is_binary(signature) and is_list(opts) do
    with {:ok, certs} <- normalise_certificates(opts),
         {:ok, leaf} <- fetch_leaf(certs),
         {:ok, digest_oid} <- resolve_digest_algorithm(opts),
         {:ok, sig_oid, sig_params} <- resolve_signature_algorithm(opts),
         content_oid = Keyword.get(opts, :content_oid, OIDs.id_data()),
         {:ok, signer_info} <-
           build_signer_info(leaf, signed_attrs, digest_oid, sig_oid, sig_params, signature),
         {:ok, signed_data_term} <-
           build_signed_data_inner(certs, signer_info, digest_oid, content_oid),
         content_info = {:ContentInfo, OIDs.id_signed_data(), signed_data_term} do
      Codec.encode(:ContentInfo, content_info)
    end
  end

  # ---------- Internals ----------

  defp normalise_certificates(opts) do
    case Keyword.fetch(opts, :certificates) do
      {:ok, []} ->
        {:error, :empty_certificate_chain}

      {:ok, certs} when is_list(certs) ->
        certs
        |> Enum.reduce_while({:ok, []}, fn cert, {:ok, acc} ->
          case to_x509(cert) do
            {:ok, x} -> {:cont, {:ok, [x | acc]}}
            {:error, _} = err -> {:halt, err}
          end
        end)
        |> case do
          {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
          err -> err
        end

      :error ->
        {:error, :missing_certificates}

      _ ->
        {:error, :invalid_certificates}
    end
  end

  defp to_x509(%X509{} = cert), do: {:ok, cert}
  defp to_x509(der) when is_binary(der), do: X509.from_der(der)
  defp to_x509(_), do: {:error, :invalid_certificate_entry}

  defp fetch_leaf([leaf | _rest]), do: {:ok, leaf}

  defp resolve_digest_algorithm(opts) do
    case Keyword.get(opts, :digest_algorithm, :sha256) do
      :sha256 -> {:ok, OIDs.id_sha256()}
      :sha384 -> {:ok, OIDs.id_sha384()}
      :sha512 -> {:ok, OIDs.id_sha512()}
      other -> {:error, {:unsupported_digest_algorithm, other}}
    end
  end

  # AlgorithmIdentifier.parameters is `OPTIONAL ANY DEFINED BY algorithm`.
  # The OTP codec accepts the field as either:
  #   * `:asn1_NOVALUE` — parameters absent
  #   * `{:asn1_OPENTYPE, der_bytes}` — opaque DER passed through verbatim
  #
  # For PKCS#1 v1.5 the signed-with-RSA family historically requires an
  # explicit DER NULL (`<<5, 0>>`) per RFC 8017 §A.2.4 — many strict
  # verifiers reject absent parameters here.
  #
  # For RSASSA-PSS we encode the explicit `RSASSA-PSS-params` per RFC
  # 8017 Appendix A.2.3. The "PS256" JOSE convention (and what our
  # `Pkcs11ex.Algorithm.PS256` adapter requests from PKCS#11) is:
  # SHA-256 / MGF1-SHA-256 / sLen=32 / trailerField=1. We hard-code
  # the canonical DER for these parameters because OTP's
  # `:CryptographicMessageSyntax-2009` codec does not expose a
  # `RSASSA-PSS-params` ASN.1 type, and BouncyCastle / OpenSSL CMS
  # parsers reject `:rsa_pss` SignerInfos that omit the parameters.
  @der_null <<5, 0>>

  # SEQUENCE {
  #   [0] HashAlgorithm     { sha256-OID, NULL }
  #   [1] MaskGenAlgorithm  { mgf1-OID, SEQUENCE { sha256-OID, NULL } }
  #   [2] saltLength        INTEGER 32
  #   -- trailerField defaults to 1 and is omitted
  # }
  @pss_params_sha256_salt32 <<
    0x30,
    0x34,
    0xA0,
    0x0F,
    0x30,
    0x0D,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x01,
    0x05,
    0x00,
    0xA1,
    0x1C,
    0x30,
    0x1A,
    0x06,
    0x09,
    0x2A,
    0x86,
    0x48,
    0x86,
    0xF7,
    0x0D,
    0x01,
    0x01,
    0x08,
    0x30,
    0x0D,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x01,
    0x05,
    0x00,
    0xA2,
    0x03,
    0x02,
    0x01,
    0x20
  >>

  defp resolve_signature_algorithm(opts) do
    case Keyword.get(opts, :signature_algorithm, :rsa_sha256) do
      :rsa_sha256 ->
        {:ok, OIDs.id_sha256_with_rsa(), {:asn1_OPENTYPE, @der_null}}

      :rsa_pss_sha256 ->
        {:ok, OIDs.id_rsassa_pss(), {:asn1_OPENTYPE, @pss_params_sha256_salt32}}

      other ->
        {:error, {:unsupported_signature_algorithm, other}}
    end
  end

  defp build_signer_info(%X509{} = leaf, signed_attrs, digest_oid, sig_oid, sig_params, signature) do
    with {:ok, issuer_and_serial} <- issuer_and_serial(leaf) do
      info =
        {:SignerInfo, 1, {:issuerAndSerialNumber, issuer_and_serial},
         {:DigestAlgorithmIdentifier, digest_oid, :asn1_NOVALUE}, signed_attrs,
         {:SignatureAlgorithmIdentifier, sig_oid, sig_params}, signature, :asn1_NOVALUE}

      {:ok, info}
    end
  end

  # Plain-decoded TBSCertificate fields (positional in the OTP record):
  #   1: version, 2: serialNumber, 3: signature, 4: issuer (Name),
  #   5: validity, 6: subject, 7: spki, ...
  defp issuer_and_serial(%X509{der: der}) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    tbs = elem(plain_cert, 1)
    issuer = elem(tbs, 4)
    serial = elem(tbs, 2)

    {:ok, {:IssuerAndSerialNumber, issuer, serial}}
  rescue
    _ -> {:error, :invalid_leaf_certificate}
  end

  defp build_signed_data_inner(certs, signer_info, digest_oid, content_oid) do
    cert_choices = Enum.map(certs, &to_certificate_choice/1)

    sd =
      {:SignedData, 1, [{:DigestAlgorithmIdentifier, digest_oid, :asn1_NOVALUE}],
       {:EncapsulatedContentInfo, content_oid, :asn1_NOVALUE}, cert_choices, :asn1_NOVALUE, [signer_info]}

    {:ok, sd}
  end

  defp to_certificate_choice(%X509{der: der}) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    {:certificate, plain_cert}
  end

  # ---------- Parse path ----------

  @doc """
  Parse a CMS `ContentInfo` DER and project it into a `Pkcs11ex.CMS.Parsed`
  struct that carries everything a verify pipeline needs (the
  to-be-signed bytes, the signature, the leaf cert, the message digest
  and signing time from the signed attributes).

  Rejects:
    * non-`id-signedData` ContentInfo (returns `{:error, :not_signed_data}`)
    * envelopes carrying anything other than exactly one `SignerInfo`
      (single-signer is the v1 contract — multi-signature support is
      Phase 4b territory)
    * empty certificate sets (we need the leaf to verify the signature)
    * malformed or absent required signed attributes (`messageDigest`)
  """
  @spec parse(binary()) :: {:ok, Parsed.t()} | {:error, term()}
  def parse(der) when is_binary(der) do
    with {:ok, ci} <- Codec.decode(:ContentInfo, der),
         {:ok, signed_data} <- expect_signed_data(ci),
         {:ok, signer_info} <- expect_single_signer(signed_data),
         {:ok, certs} <- parse_certificate_set(elem(signed_data, 4)),
         {:ok, leaf} <- match_leaf(certs, elem(signer_info, 2)),
         signed_attrs = elem(signer_info, 4),
         {:ok, tbs} <- Codec.encode(:SignedAttributes, signed_attrs),
         {:ok, message_digest} <- attribute_value(signed_attrs, OIDs.id_message_digest()),
         signing_time = attribute_signing_time(signed_attrs),
         content_oid = elem(elem(signed_data, 3), 1),
         digest_oid = elem(elem(signer_info, 3), 1),
         sig_oid = elem(elem(signer_info, 5), 1),
         signature = elem(signer_info, 6) do
      {:ok,
       %Parsed{
         der: der,
         signed_attrs: signed_attrs,
         to_be_signed: tbs,
         signature: signature,
         digest_algorithm: oid_to_digest_algorithm(digest_oid),
         signature_algorithm: oid_to_signature_algorithm(sig_oid),
         leaf: leaf,
         certificates: certs,
         content_oid: content_oid,
         message_digest: message_digest,
         signing_time: signing_time
       }}
    end
  end

  defp expect_signed_data({:ContentInfo, oid, content}) do
    if oid == OIDs.id_signed_data() do
      {:ok, content}
    else
      {:error, {:not_signed_data, oid}}
    end
  end

  defp expect_single_signer(signed_data) do
    case elem(signed_data, 6) do
      [signer_info] -> {:ok, signer_info}
      [] -> {:error, :no_signer_info}
      [_ | _] -> {:error, :multiple_signer_info_unsupported_in_v1}
    end
  end

  defp parse_certificate_set(:asn1_NOVALUE), do: {:error, :no_certificates}
  defp parse_certificate_set([]), do: {:error, :no_certificates}

  defp parse_certificate_set(choices) when is_list(choices) do
    choices
    |> Enum.reduce_while({:ok, []}, fn
      {:certificate, plain_cert}, {:ok, acc} ->
        case x509_from_plain(plain_cert) do
          {:ok, x} -> {:cont, {:ok, [x | acc]}}
          err -> {:halt, err}
        end

      _other, {:ok, _} ->
        {:halt, {:error, :unsupported_certificate_choice}}
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      err -> err
    end
  end

  defp x509_from_plain(plain_cert) do
    der = :public_key.pkix_encode(:Certificate, plain_cert, :plain)
    X509.from_der(der)
  rescue
    _ -> {:error, :invalid_embedded_certificate}
  end

  # SignerInfo.sid is `{:issuerAndSerialNumber, IssuerAndSerialNumber}`
  # for CMS v1 signers; SubjectKeyIdentifier form is v3 (deferred).
  #
  # Comparing issuer Names structurally is brittle: the OTP X.509 ASN.1
  # module (`:public_key.pkix_decode_cert`) uses `:AttributeTypeAndValue`
  # records, while the CMS-2009 ASN.1 module decodes the embedded cert
  # with `:SingleAttribute` records — different tag-name, identical
  # logical content. Encode both Names back to DER via
  # `:public_key.der_encode(:Name, _)` and compare bytes instead.
  defp match_leaf(certs, {:issuerAndSerialNumber, {:IssuerAndSerialNumber, sid_issuer, serial}}) do
    sid_issuer_der = :public_key.der_encode(:Name, sid_issuer)

    Enum.find(certs, fn %X509{der: der} ->
      plain = :public_key.pkix_decode_cert(der, :plain)
      tbs = elem(plain, 1)
      cert_issuer_der = :public_key.der_encode(:Name, elem(tbs, 4))
      cert_issuer_der == sid_issuer_der and elem(tbs, 2) == serial
    end)
    |> case do
      nil -> {:error, :leaf_certificate_not_found_in_chain}
      leaf -> {:ok, leaf}
    end
  end

  defp match_leaf(_, {:subjectKeyIdentifier, _}),
    do: {:error, :subject_key_identifier_unsupported_in_v1}

  defp attribute_value(signed_attrs, target_oid) do
    case Enum.find(signed_attrs, fn {:Attribute, oid, _values} -> oid == target_oid end) do
      {:Attribute, _, [value]} -> {:ok, value}
      {:Attribute, _, _} -> {:error, {:multi_value_attribute, target_oid}}
      nil -> {:error, {:missing_attribute, target_oid}}
    end
  end

  defp attribute_signing_time(signed_attrs) do
    case Enum.find(signed_attrs, fn {:Attribute, oid, _} -> oid == OIDs.id_signing_time() end) do
      {:Attribute, _, [{:utcTime, charlist}]} -> parse_utc_time(charlist)
      {:Attribute, _, [{:generalTime, charlist}]} -> parse_generalized_time(charlist)
      _ -> nil
    end
  end

  defp parse_utc_time(charlist) do
    case List.to_string(charlist) do
      <<yy::binary-2, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2, "Z">> ->
        # RFC 5280 §4.1.2.5.1: YY < 50 → 20YY, else 19YY.
        full_year = 2000 + String.to_integer(yy)

        full_year =
          if full_year > 2049 do
            full_year - 100
          else
            full_year
          end

        build_datetime(full_year, mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

  defp parse_generalized_time(charlist) do
    case List.to_string(charlist) do
      <<yyyy::binary-4, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2, "Z">> ->
        build_datetime(String.to_integer(yyyy), mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

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

  defp oid_to_digest_algorithm(oid) do
    cond do
      oid == OIDs.id_sha256() -> :sha256
      oid == OIDs.id_sha384() -> :sha384
      oid == OIDs.id_sha512() -> :sha512
      true -> {:unknown_oid, oid}
    end
  end

  defp oid_to_signature_algorithm(oid) do
    cond do
      oid == OIDs.id_sha256_with_rsa() -> :rsa_sha256
      oid == OIDs.id_rsassa_pss() -> :rsa_pss_sha256
      true -> {:unknown_oid, oid}
    end
  end
end
