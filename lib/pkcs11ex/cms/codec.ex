defmodule Pkcs11ex.CMS.Codec do
  @moduledoc """
  Thin wrapper around OTP's `:CryptographicMessageSyntax-2009` ASN.1
  codec for CMS structures.

  The OTP codec returns `{:error, {:asn1, reason}}` with deeply nested
  internal stack frames on failure. This module flattens those into
  flat `{:error, {:cms_codec, type, reason}}` tuples that compose with
  the rest of `pkcs11ex`'s `with` chains.

  ## Encoding shape

  The codec accepts Elixir tuples shaped after the ASN.1 type
  definitions in OTP's
  [`CryptographicMessageSyntax-2009.asn1`](https://github.com/erlang/otp/blob/master/lib/public_key/asn1/CryptographicMessageSyntax-2009.asn1).
  Some shape rules:

    * Records are represented as tagged tuples with the type name as
      first element. E.g., `ContentInfo` is `{:ContentInfo, oid, content}`.
    * `OPTIONAL` fields use the atom `:asn1_NOVALUE` when absent.
    * For ContentInfo, the `content` field is parameterised by
      `contentType` via the information-object-class table — pass the
      inner term **directly** (not wrapped as `{:asn1_OPENTYPE, der}`).
      The codec recurses.
    * For genuinely opaque fields (`Attribute.values` SET OF ANY), wrap
      bytes as `{:asn1_OPENTYPE, der_bytes}` — the codec emits them
      verbatim.

  ## Examples

      iex> oid_signed_data = Pkcs11ex.CMS.OIDs.id_signed_data()
      iex> oid_data = Pkcs11ex.CMS.OIDs.id_data()
      iex> oid_sha256 = Pkcs11ex.CMS.OIDs.id_sha256()
      iex> inner = {
      ...>   :SignedData, 1,
      ...>   [{:DigestAlgorithmIdentifier, oid_sha256, :asn1_NOVALUE}],
      ...>   {:EncapsulatedContentInfo, oid_data, :asn1_NOVALUE},
      ...>   :asn1_NOVALUE, :asn1_NOVALUE, []
      ...> }
      iex> ci = {:ContentInfo, oid_signed_data, inner}
      iex> {:ok, der} = Pkcs11ex.CMS.Codec.encode(:ContentInfo, ci)
      iex> {:ok, decoded} = Pkcs11ex.CMS.Codec.decode(:ContentInfo, der)
      iex> match?({:ContentInfo, ^oid_signed_data, _}, decoded)
      true
  """

  @asn1_module :"CryptographicMessageSyntax-2009"

  @typedoc "Top-level CMS types we encode/decode."
  @type cms_type ::
          :ContentInfo
          | :SignedData
          | :SignerInfo
          | :EncapsulatedContentInfo
          | :SignedAttributes
          | :IssuerAndSerialNumber
          | :Attribute
          | :DigestAlgorithmIdentifier
          | :SignatureAlgorithmIdentifier

  @typedoc "Encoded DER bytes."
  @type der :: binary()

  @doc """
  Encode a CMS term to DER. Returns `{:ok, der}` or
  `{:error, {:cms_codec, type, reason}}`.
  """
  @spec encode(cms_type(), term()) :: {:ok, der()} | {:error, {:cms_codec, cms_type(), term()}}
  def encode(type, term) do
    case @asn1_module.encode(type, term) do
      {:ok, iodata} -> {:ok, IO.iodata_to_binary(iodata)}
      {:error, reason} -> {:error, {:cms_codec, type, reason}}
    end
  rescue
    e -> {:error, {:cms_codec, type, {:codec_raised, Exception.message(e)}}}
  end

  @doc """
  Decode DER to a CMS term. Returns `{:ok, term}` or
  `{:error, {:cms_codec, type, reason}}`.
  """
  @spec decode(cms_type(), der()) :: {:ok, term()} | {:error, {:cms_codec, cms_type(), term()}}
  def decode(type, der) when is_binary(der) do
    case @asn1_module.decode(type, der) do
      {:ok, term} -> {:ok, term}
      {:error, reason} -> {:error, {:cms_codec, type, reason}}
    end
  rescue
    e -> {:error, {:cms_codec, type, {:codec_raised, Exception.message(e)}}}
  end
end
