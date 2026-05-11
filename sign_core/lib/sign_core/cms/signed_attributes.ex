defmodule SignCore.CMS.SignedAttributes do
  @moduledoc """
  Build and encode the `signedAttrs` SET-OF Attribute that goes into a
  CMS `SignerInfo` (RFC 5652 §5.3) — and produce the to-be-signed bytes
  per RFC 5652 §5.4 ("the message digest calculation process").

  ## What's in here

  Three required PKCS#9 attributes per RFC 5652 §11:

    * `contentType` (1.2.840.113549.1.9.3) — the OID of the encapsulated
      content type, typically `id-data` for detached PAdES / CAdES.
    * `messageDigest` (1.2.840.113549.1.9.4) — the digest of the
      encapsulated content (or the to-be-signed bytes for detached).
    * `signingTime` (1.2.840.113549.1.9.5) — the time the signature was
      produced, as recorded by the signer (not authoritative — that's
      what RFC 3161 timestamping is for).

  Plus the ESS `signing-certificate-v2` attribute mandated by ETSI EN
  319 142-1 §5.3 (PAdES B-B) when a leaf certificate is supplied:

    * `signing-certificate-v2` (1.2.840.113549.1.9.16.2.47) — RFC 5035
      §3 `ESSCertIDv2` binding the signature to the leaf cert by
      SHA-256 hash. Default-on whenever `:leaf_cert_der` is passed.
      Without it Adobe Acrobat refuses to validate the signature even
      when the math is sound.

  ## The §5.4 re-tag (no, OTP handles it)

  CMS distinguishes two encodings of the same SET-OF Attribute:

    * **As SET OF Attribute** (universal SET tag `0x31`) — the input to
      the signature digest. This is what `to_be_signed/1` returns.
    * **As `[0] IMPLICIT Attributes`** (context-specific tag `0xA0`) —
      the form embedded inside `SignerInfo`. The OTP codec emits this
      form automatically when you encode a `SignerInfo`.

  Callers should compute the signature over `to_be_signed/1`'s output
  and let the codec handle the IMPLICIT-tagged embed during the final
  `SignerInfo` assembly. We never re-tag bytes by hand.

  ## OPEN-TYPE Attribute encoding

  An ASN.1 `Attribute` is `{type OID, values SET OF ANY}`. The OTP CMS
  module ships an information-object-class table that maps known PKCS#9
  attribute OIDs to typed value definitions:

    * `id-contentType` → OBJECT IDENTIFIER
    * `id-messageDigest` → OCTET STRING
    * `id-signingTime` → Time CHOICE (UTCTime or GeneralizedTime)

  So when building the inner `Attribute` tuple, we pass the **typed
  Erlang/Elixir value directly** (an OID tuple, a binary, a tagged Time
  choice) rather than wrapping bytes as `{:asn1_OPENTYPE, der}`. OTP
  encodes them properly. This is the "OPEN-TYPE Attribute encoding
  gotcha" that the Phase 4 plan §8 walks through; in practice the OTP
  codec absorbs it.

  ## Time choice cutover

  Per RFC 5280 §4.1.2.5 (which CMS adopts via §11.3): UTCTime for years
  1950..2049 (inclusive), GeneralizedTime otherwise. Phase 4 expects to
  ship in the UTCTime window for the foreseeable future, but the
  selection is automatic.
  """

  alias SignCore.CMS.{Codec, OIDs}

  @typedoc "Erlang `Attribute` record-shaped tuple."
  @type attribute :: {:Attribute, :public_key.oid(), [term()]}

  @typedoc "Required + optional input for `build/1`."
  @type build_opts :: [
          digest: binary(),
          content_oid: :public_key.oid(),
          signing_time: DateTime.t(),
          leaf_cert_der: binary(),
          signing_certificate: boolean()
        ]

  @doc """
  Build the three required signed attributes (`contentType`,
  `messageDigest`, `signingTime`) plus any extras.

  ## Required opts

    * `:digest` — `binary()`. The SHA-256 (or matching algorithm) digest
      over the encapsulated content. For detached signatures this is
      computed over the document bytes the signer commits to — for
      PAdES, the bytes covered by `/ByteRange`.

  ## Optional opts

    * `:content_oid` — defaults to `id-data` (1.2.840.113549.1.7.1).
      Use a different content-type OID for non-detached payloads.
    * `:signing_time` — defaults to `DateTime.utc_now/0`. Truncated to
      seconds; sub-second precision is not encoded (UTCTime granularity).
    * `:leaf_cert_der` — leaf certificate DER bytes. When supplied (and
      `:signing_certificate` is not `false`), the ESS
      `signing-certificate-v2` attribute (RFC 5035 §3) is appended,
      carrying `SHA-256(leaf_cert_der)` as `certHash`. Required for
      PAdES B-B conformance per ETSI EN 319 142-1 §5.3 — Adobe Acrobat
      refuses to validate signatures lacking this attribute.
    * `:signing_certificate` — `false` to skip emitting the
      `signing-certificate-v2` attribute even when `:leaf_cert_der` is
      supplied. Default: `true`. Escape hatch for callers that need
      bit-for-bit reproducibility with pre-fix output.

  Returns a list of `Attribute` tuples — sorted by the OTP codec into
  DER canonical SET order at encode time.
  """
  @spec build(build_opts()) :: {:ok, [attribute()]} | {:error, term()}
  def build(opts) do
    with {:ok, digest} <- fetch_digest(opts),
         {:ok, signing_cert_attrs} <- maybe_signing_certificate_v2(opts) do
      content_oid = Keyword.get(opts, :content_oid, OIDs.id_data())
      signing_time = Keyword.get_lazy(opts, :signing_time, &default_signing_time/0)

      {:ok,
       [
         content_type_attr(content_oid),
         message_digest_attr(digest),
         signing_time_attr(signing_time)
         | signing_cert_attrs
       ]}
    end
  end

  @doc """
  Encode `attrs` as the universal `SET OF Attribute` (RFC 5652 §5.4
  "to be signed" form). The returned bytes are the digest input — the
  signer calls `Pkcs11ex.sign_bytes/2` over them, and the resulting
  raw signature is glued back into the `SignerInfo`.

  Equivalent to `Codec.encode(:SignedAttributes, attrs)`; this name
  documents intent at the call site.
  """
  @spec to_be_signed([attribute()]) :: {:ok, binary()} | {:error, term()}
  def to_be_signed(attrs) when is_list(attrs) do
    Codec.encode(:SignedAttributes, attrs)
  end

  @doc """
  Verify the ESS `signing-certificate-v2` attribute against the
  presented leaf certificate. Symmetric to what `build/1` emits when
  `:leaf_cert_der` is supplied.

  Returns:

    * `:ok` when the attribute is present and `certHash` matches the
      leaf — i.e., the attribute genuinely binds the signature to
      `leaf_cert_der`.
    * `:missing` when no `signing-certificate-v2` attribute is in
      `signed_attrs`. Pre-0.1.2 PAdES output from this library, and
      legacy PKCS#7 signatures, fall here. The caller decides whether
      `:missing` should be treated as `:ok` (lenient) or as an error
      (strict ETSI EN 319 142-1 §6.4 conformance).
    * `{:error, reason}` when the attribute is present but malformed,
      mismatched, or carries an unsupported `hashAlgorithm`. Reasons:
        - `:signing_certificate_v2_mismatch` — `certHash` doesn't match
          `SHA-256(leaf_cert_der)` (or the matching hash for an
          explicit `hashAlgorithm`).
        - `{:unsupported_signing_certificate_v2_hash_algorithm, oid}` —
          we accept only the SHA-2 family by raw OID match.
        - `:malformed_signing_certificate_v2` — DER didn't parse as
          the RFC 5035 §3 structure.
        - `:unexpected_attribute_shape` — the `Attribute.values` SET
          wasn't a single OPENTYPE / binary as we emit and the OTP
          codec round-trips.

  Only the first `ESSCertIDv2` in the SEQUENCE OF is checked — RFC
  5035 §3 and ETSI EN 319 142-1 §5.3 require the leaf to be first.
  Subsequent entries (intermediate certs) are out of scope for B-B
  verification.
  """
  @spec verify_signing_certificate_v2([attribute()], binary()) ::
          :ok | :missing | {:error, term()}
  def verify_signing_certificate_v2(signed_attrs, leaf_cert_der)
      when is_list(signed_attrs) and is_binary(leaf_cert_der) do
    target_oid = OIDs.id_aa_signing_certificate_v2()

    case Enum.find(signed_attrs, fn {:Attribute, oid, _values} -> oid == target_oid end) do
      nil ->
        :missing

      {:Attribute, _, [value]} ->
        with {:ok, cert_hash, hash_alg} <- parse_value(value) do
          verify_cert_hash(cert_hash, hash_alg, leaf_cert_der)
        end

      _ ->
        {:error, :unexpected_attribute_shape}
    end
  end

  defp parse_value({:asn1_OPENTYPE, der}), do: parse_signing_certificate_v2_der(der)
  defp parse_value(der) when is_binary(der), do: parse_signing_certificate_v2_der(der)
  defp parse_value(_), do: {:error, :unexpected_attribute_shape}

  # SigningCertificateV2 ::= SEQUENCE {
  #   certs    SEQUENCE OF ESSCertIDv2,
  #   policies SEQUENCE OF PolicyInformation OPTIONAL  -- ignored
  # }
  #
  # ESSCertIDv2 ::= SEQUENCE {
  #   hashAlgorithm AlgorithmIdentifier DEFAULT sha-256,
  #   certHash      OCTET STRING,
  #   issuerSerial  IssuerSerial OPTIONAL              -- ignored
  # }
  defp parse_signing_certificate_v2_der(der) do
    with {:ok, scv2_body, _} <- der_take_tlv(der, 0x30),
         {:ok, certs_body, _} <- der_take_tlv(scv2_body, 0x30),
         {:ok, ess_body, _rest_certs} <- der_take_tlv(certs_body, 0x30),
         {:ok, hash_alg, body_after_alg} <- maybe_take_hash_algorithm(ess_body),
         {:ok, cert_hash, _rest} <- der_take_tlv(body_after_alg, 0x04) do
      {:ok, cert_hash, hash_alg}
    else
      _ -> {:error, :malformed_signing_certificate_v2}
    end
  end

  defp maybe_take_hash_algorithm(<<0x30, _::binary>> = body) do
    with {:ok, alg_body, rest} <- der_take_tlv(body, 0x30),
         {:ok, oid_bytes, _params} <- der_take_tlv(alg_body, 0x06) do
      {:ok, hash_oid_from_der(oid_bytes), rest}
    end
  end

  defp maybe_take_hash_algorithm(body), do: {:ok, :sha256, body}

  @sha256_oid_der <<0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01>>
  @sha384_oid_der <<0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02>>
  @sha512_oid_der <<0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03>>

  defp hash_oid_from_der(@sha256_oid_der), do: :sha256
  defp hash_oid_from_der(@sha384_oid_der), do: :sha384
  defp hash_oid_from_der(@sha512_oid_der), do: :sha512
  defp hash_oid_from_der(other), do: {:unknown_oid, other}

  defp verify_cert_hash(cert_hash, alg, leaf_der) when alg in [:sha256, :sha384, :sha512] do
    if :crypto.hash(alg, leaf_der) == cert_hash do
      :ok
    else
      {:error, :signing_certificate_v2_mismatch}
    end
  end

  defp verify_cert_hash(_cert_hash, {:unknown_oid, oid}, _leaf_der) do
    {:error, {:unsupported_signing_certificate_v2_hash_algorithm, oid}}
  end

  # Minimal DER TLV reader for the structures in
  # `verify_signing_certificate_v2/2`. Short-form length and 1-byte
  # long-form (0x81 LL); SigningCertificateV2 + a single ESSCertIDv2
  # with optional IssuerSerial fits comfortably under 255 bytes.
  defp der_take_tlv(<<tag, rest::binary>>, expected_tag) when tag == expected_tag do
    case rest do
      <<len, content::binary-size(len), tail::binary>> when len < 0x80 ->
        {:ok, content, tail}

      <<0x81, len, content::binary-size(len), tail::binary>> ->
        {:ok, content, tail}

      _ ->
        {:error, :malformed_der}
    end
  end

  defp der_take_tlv(_, _), do: {:error, :unexpected_tag}

  # ---------- Internals ----------

  defp fetch_digest(opts) do
    case Keyword.fetch(opts, :digest) do
      {:ok, bin} when is_binary(bin) and byte_size(bin) > 0 -> {:ok, bin}
      {:ok, _} -> {:error, :invalid_digest}
      :error -> {:error, :missing_digest}
    end
  end

  defp default_signing_time, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp content_type_attr(content_oid) when is_tuple(content_oid) do
    {:Attribute, OIDs.id_content_type(), [content_oid]}
  end

  defp message_digest_attr(digest) when is_binary(digest) do
    {:Attribute, OIDs.id_message_digest(), [digest]}
  end

  defp signing_time_attr(%DateTime{} = dt) do
    {:Attribute, OIDs.id_signing_time(), [encode_time_choice(dt)]}
  end

  defp maybe_signing_certificate_v2(opts) do
    cond do
      Keyword.get(opts, :signing_certificate, true) == false ->
        {:ok, []}

      leaf = Keyword.get(opts, :leaf_cert_der) ->
        case signing_certificate_v2_attr(leaf) do
          {:ok, attr} -> {:ok, [attr]}
          {:error, _} = err -> err
        end

      true ->
        {:ok, []}
    end
  end

  # Hand-encoded `SigningCertificateV2` per RFC 5035 §3. Minimal form
  # omits both the `hashAlgorithm` field (defaults to sha-256) and the
  # `issuerSerial` field (optional). This is the shape that Adobe
  # Acrobat and the EU DSS validator accept; including IssuerSerial is
  # allowed by spec but not required for B-B.
  #
  #   SigningCertificateV2 ::= SEQUENCE {
  #     certs    SEQUENCE OF ESSCertIDv2,
  #     policies SEQUENCE OF PolicyInformation OPTIONAL  -- omitted
  #   }
  #
  #   ESSCertIDv2 ::= SEQUENCE {
  #     hashAlgorithm AlgorithmIdentifier DEFAULT sha-256, -- omitted
  #     certHash      OCTET STRING,
  #     issuerSerial  IssuerSerial OPTIONAL                -- omitted
  #   }
  #
  # With SHA-256 (32 bytes), the wire form is exactly 40 bytes:
  #   30 26 30 24 30 22 04 20 <32 bytes>
  defp signing_certificate_v2_attr(leaf_cert_der) when is_binary(leaf_cert_der) do
    cert_hash = :crypto.hash(:sha256, leaf_cert_der)
    ess_cert_id_v2 = der_sequence(der_octet_string(cert_hash))
    certs_seq = der_sequence(ess_cert_id_v2)
    signing_cert_v2_der = der_sequence(certs_seq)

    attr =
      {:Attribute, OIDs.id_aa_signing_certificate_v2(),
       [{:asn1_OPENTYPE, signing_cert_v2_der}]}

    {:ok, attr}
  end

  defp signing_certificate_v2_attr(_), do: {:error, :invalid_leaf_cert_der}

  # Minimal DER helpers — only emit the short-form length encoding we
  # actually need (length < 128). The SigningCertificateV2 over a
  # SHA-256 hash never exceeds that bound.
  defp der_octet_string(bytes) when is_binary(bytes) and byte_size(bytes) < 128 do
    <<0x04, byte_size(bytes), bytes::binary>>
  end

  defp der_sequence(inner) when is_binary(inner) and byte_size(inner) < 128 do
    <<0x30, byte_size(inner), inner::binary>>
  end

  # RFC 5280 §4.1.2.5 / RFC 5652 §11.3: UTCTime for 1950..2049, GeneralizedTime otherwise.
  # UTCTime format: YYMMDDHHMMSSZ.
  # GeneralizedTime format: YYYYMMDDHHMMSSZ.
  defp encode_time_choice(%DateTime{year: y} = dt) when y >= 1950 and y <= 2049 do
    yy = rem(y, 100)
    {:utcTime, format_time(yy, dt, 2)}
  end

  defp encode_time_choice(%DateTime{year: y} = dt) do
    {:generalTime, format_time(y, dt, 4)}
  end

  defp format_time(year_part, %DateTime{} = dt, year_digits) do
    [
      pad(year_part, year_digits),
      pad(dt.month, 2),
      pad(dt.day, 2),
      pad(dt.hour, 2),
      pad(dt.minute, 2),
      pad(dt.second, 2),
      ?Z
    ]
    |> :erlang.iolist_to_binary()
    |> :erlang.binary_to_list()
  end

  defp pad(n, width) do
    n |> Integer.to_string() |> String.pad_leading(width, "0")
  end
end
