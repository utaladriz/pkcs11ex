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

  alias Pkcs11ex.CMS.{Codec, OIDs}
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
  # verifiers reject absent parameters here. For RSASSA-PSS we omit
  # parameters and verifiers default to SHA-256 / MGF1-SHA-256 /
  # sLen=hLen / trailerField=1; the explicit `RSASSA-PSS-params` struct
  # is a Phase 5 hardening item.
  @der_null <<5, 0>>

  defp resolve_signature_algorithm(opts) do
    case Keyword.get(opts, :signature_algorithm, :rsa_sha256) do
      :rsa_sha256 -> {:ok, OIDs.id_sha256_with_rsa(), {:asn1_OPENTYPE, @der_null}}
      :rsa_pss_sha256 -> {:ok, OIDs.id_rsassa_pss(), :asn1_NOVALUE}
      other -> {:error, {:unsupported_signature_algorithm, other}}
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
       {:EncapsulatedContentInfo, content_oid, :asn1_NOVALUE}, cert_choices, :asn1_NOVALUE,
       [signer_info]}

    {:ok, sd}
  end

  defp to_certificate_choice(%X509{der: der}) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    {:certificate, plain_cert}
  end
end
