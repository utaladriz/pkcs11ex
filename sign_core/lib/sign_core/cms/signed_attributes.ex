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
          signing_time: DateTime.t()
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

  Returns a list of `Attribute` tuples — sorted by the OTP codec into
  DER canonical SET order at encode time.
  """
  @spec build(build_opts()) :: {:ok, [attribute()]} | {:error, term()}
  def build(opts) do
    with {:ok, digest} <- fetch_digest(opts) do
      content_oid = Keyword.get(opts, :content_oid, OIDs.id_data())
      signing_time = Keyword.get_lazy(opts, :signing_time, &default_signing_time/0)

      {:ok,
       [
         content_type_attr(content_oid),
         message_digest_attr(digest),
         signing_time_attr(signing_time)
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
