defmodule SignCore.XML.XAdES do
  @moduledoc """
  Builds the XAdES B-B `<xades:QualifyingProperties>` block.

  Produces the canonical shape ETSI EN 319 132-1 prescribes for B-B:

      <xades:QualifyingProperties Target="#Signature-{id}"
          xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"
          xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xades:SignedProperties Id="xades-{id}">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-05-06T14:05:30Z</xades:SigningTime>
            <xades:SigningCertificateV2>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm=".../sha256"/>
                  <ds:DigestValue>...</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerialV2>...</xades:IssuerSerialV2>
              </xades:Cert>
            </xades:SigningCertificateV2>
          </xades:SignedSignatureProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>

  The `<xades:SignedProperties>` element is what the second
  `<ds:Reference>` in the signature points at. The verifier
  recomputes its exc-c14n digest and matches it against the
  reference's `<ds:DigestValue>` — that's how the signature binds
  the claimed signing certificate, signing time, and any other
  signed properties to the rest of the signed data.

  ## v1 scope

    * `SigningCertificateV2` with `IssuerSerialV2` (XAdES EN 319
      132-1). The older `SigningCertificate` / `IssuerSerial`
      (TS 101 903 v1.3.2) form is post-v1.
    * Only the leaf cert is digested into `SigningCertificateV2`.
      Including intermediates is allowed by spec but not required
      for B-B; each cert in the chain would otherwise become its
      own `<xades:Cert>` element.
    * `SigningTime` is the only signed-signature-property emitted
      besides `SigningCertificateV2`. `SignaturePolicyIdentifier`,
      `SignatureProductionPlaceV2`, and `SignerRoleV2` are post-v1.
  """

  alias SignCore.X509
  alias SignCore.XML.Builder

  @c14n_exclusive_uri "http://www.w3.org/2001/10/xml-exc-c14n#"

  @doc """
  Builds the full `<xades:QualifyingProperties>` block ready for
  splicing into the `<ds:Object>` element of a `<ds:Signature>`.

  Required:

    * `:signature_id` — the `Id` of the parent `<ds:Signature>`.
      Used as the `Target` attribute (`\#{signature_id}`).
    * `:signed_properties_id` — the `Id` for `<xades:SignedProperties>`.
      The data Reference's URI in the `<ds:SignedInfo>` block must
      point at `\#\#{signed_properties_id}`.
    * `:leaf_cert` — `SignCore.X509.t()` for the signing cert.

  Optional:

    * `:signing_time` — `DateTime.t()`. Default `DateTime.utc_now/0`.
  """
  @spec qualifying_properties(keyword()) :: {:ok, String.t()} | {:error, term()}
  def qualifying_properties(opts) when is_list(opts) do
    with {:ok, signature_id} <- fetch(opts, :signature_id),
         {:ok, signed_props_id} <- fetch(opts, :signed_properties_id),
         {:ok, %X509{} = leaf} <- fetch(opts, :leaf_cert),
         {:ok, issuer_serial_v2_der} <- build_issuer_serial_v2_der(leaf) do
      cert_digest = leaf.der |> hash_sha256() |> Base.encode64()
      issuer_serial_b64 = Base.encode64(issuer_serial_v2_der)

      signing_time =
        opts
        |> Keyword.get(:signing_time, DateTime.utc_now())
        |> DateTime.shift_zone!("Etc/UTC")
        |> DateTime.truncate(:second)
        |> DateTime.to_iso8601()

      qp =
        ~s(<xades:QualifyingProperties xmlns:xades="#{Builder.xades_ns()}" xmlns:ds="#{Builder.ds_ns()}" Target="#) <>
          escape_attr(signature_id) <>
          ~s(">) <>
          ~s(<xades:SignedProperties Id="#{escape_attr(signed_props_id)}">) <>
          "<xades:SignedSignatureProperties>" <>
          "<xades:SigningTime>" <>
          signing_time <>
          "</xades:SigningTime>" <>
          "<xades:SigningCertificateV2>" <>
          "<xades:Cert>" <>
          "<xades:CertDigest>" <>
          ~s(<ds:DigestMethod Algorithm="#{Builder.digest_sha256_uri()}"></ds:DigestMethod>) <>
          ~s(<ds:DigestValue>#{cert_digest}</ds:DigestValue>) <>
          "</xades:CertDigest>" <>
          ~s(<xades:IssuerSerialV2>#{issuer_serial_b64}</xades:IssuerSerialV2>) <>
          "</xades:Cert>" <>
          "</xades:SigningCertificateV2>" <>
          "</xades:SignedSignatureProperties>" <>
          "</xades:SignedProperties>" <>
          "</xades:QualifyingProperties>"

      {:ok, qp}
    end
  end

  @doc """
  Builds the `<xades:UnsignedProperties>` block carrying a
  `<xades:SignatureTimeStamp>` (XAdES B-T per ETSI EN 319 132-1
  §5.4.1). The TST is embedded base64-encoded as
  `<xades:EncapsulatedTimeStamp>`.

      <xades:UnsignedProperties>
        <xades:UnsignedSignatureProperties>
          <xades:SignatureTimeStamp Id="...">
            <ds:CanonicalizationMethod Algorithm="...exc-c14n#"/>
            <xades:EncapsulatedTimeStamp>...</xades:EncapsulatedTimeStamp>
          </xades:SignatureTimeStamp>
        </xades:UnsignedSignatureProperties>
      </xades:UnsignedProperties>

  Note: this returns just the `<xades:UnsignedProperties>` block.
  Splice it inside the parent `<xades:QualifyingProperties>` after
  `<xades:SignedProperties>`.

  Required opts:

    * `:tst_der` — RFC 3161 TimeStampToken DER (the
      `Pkcs11ex.Audit.Anchor.RFC3161.extract_token/1` output).
    * `:timestamp_id` — `Id` attribute on the
      `<xades:SignatureTimeStamp>` element.
  """
  @spec unsigned_signature_timestamp(keyword()) :: {:ok, String.t()} | {:error, term()}
  def unsigned_signature_timestamp(opts) when is_list(opts) do
    with {:ok, tst_der} <- fetch(opts, :tst_der),
         {:ok, ts_id} <- fetch(opts, :timestamp_id) do
      tst_b64 = Base.encode64(tst_der)

      block =
        "<xades:UnsignedProperties>" <>
          "<xades:UnsignedSignatureProperties>" <>
          ~s(<xades:SignatureTimeStamp Id="#{escape_attr(ts_id)}">) <>
          ~s(<ds:CanonicalizationMethod Algorithm="#{@c14n_exclusive_uri}"></ds:CanonicalizationMethod>) <>
          "<xades:EncapsulatedTimeStamp>" <>
          tst_b64 <>
          "</xades:EncapsulatedTimeStamp>" <>
          "</xades:SignatureTimeStamp>" <>
          "</xades:UnsignedSignatureProperties>" <>
          "</xades:UnsignedProperties>"

      {:ok, block}
    end
  end

  @doc """
  Splices an `<xades:UnsignedProperties>` block into the
  `<xades:QualifyingProperties>` produced by `qualifying_properties/1`.
  Inserts immediately before the `</xades:QualifyingProperties>`
  closing tag.
  """
  @spec splice_unsigned_properties(String.t(), String.t()) ::
          {:ok, String.t()} | {:error, term()}
  def splice_unsigned_properties(qp_xml, up_block) do
    closing = "</xades:QualifyingProperties>"

    case :binary.match(qp_xml, closing) do
      :nomatch ->
        {:error, {:xades, :qp_closing_tag_not_found}}

      {pos, len} ->
        prefix = binary_part(qp_xml, 0, pos)
        suffix = binary_part(qp_xml, pos + len, byte_size(qp_xml) - pos - len)
        {:ok, prefix <> up_block <> closing <> suffix}
    end
  end

  @doc """
  Builds the DER-encoded `IssuerSerial` (RFC 5035 §4) octets for a
  `<xades:IssuerSerialV2>` element. Returns the raw DER — the caller
  base64-encodes it for the XML element body.

  ## ASN.1 shape

      IssuerSerial ::= SEQUENCE {
          issuer       GeneralNames,
          serialNumber CertificateSerialNumber
      }
      GeneralNames  ::= SEQUENCE OF GeneralName
      GeneralName   ::= CHOICE { ..., directoryName [4] Name, ... }

  Single-element `GeneralNames` containing a single `[4] EXPLICIT
  Name` is the canonical encoding for an X.509 issuer.
  """
  @spec build_issuer_serial_v2_der(X509.t()) :: {:ok, binary()} | {:error, term()}
  def build_issuer_serial_v2_der(%X509{der: der}) do
    plain_cert = :public_key.pkix_decode_cert(der, :plain)
    tbs = elem(plain_cert, 1)
    issuer = elem(tbs, 4)
    serial = elem(tbs, 2)

    issuer_name_der = :public_key.der_encode(:Name, issuer)

    # [4] IMPLICIT Name within GeneralName CHOICE — but per ASN.1
    # rules for CHOICE inside `EXPLICIT TAGS` modules, the
    # `directoryName [4] Name` alternative is encoded with a
    # constructed [4] tag wrapping the Name SEQUENCE bytes.
    general_name_der = with_tag(0xA4, issuer_name_der)
    general_names_der = with_tag(0x30, general_name_der)
    serial_der = der_integer(serial)

    issuer_serial_der = with_tag(0x30, general_names_der <> serial_der)
    {:ok, issuer_serial_der}
  rescue
    _ -> {:error, :invalid_leaf_certificate}
  end

  # ---------- internals ----------

  defp fetch(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, val} -> {:ok, val}
      :error -> {:error, {:missing_xades_opt, key}}
    end
  end

  defp hash_sha256(data), do: :crypto.hash(:sha256, data)

  defp escape_attr(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(~s("), "&quot;")
  end

  # ---------- minimal DER primitives ----------

  defp with_tag(tag, body) when is_integer(tag) and is_binary(body) do
    <<tag, der_length(byte_size(body))::binary, body::binary>>
  end

  defp der_length(len) when len < 128, do: <<len>>

  defp der_length(len) when len < 256, do: <<0x81, len>>

  defp der_length(len) when len < 65_536, do: <<0x82, len::16>>

  defp der_length(len) when len < 16_777_216, do: <<0x83, len::24>>

  defp der_integer(n) when is_integer(n) and n >= 0 do
    bytes = encode_unsigned_minimal(n)
    # If the high bit is set, prepend 0x00 to keep the integer positive.
    bytes =
      case bytes do
        <<b, _::binary>> when b >= 0x80 -> <<0x00, bytes::binary>>
        _ -> bytes
      end

    with_tag(0x02, bytes)
  end

  defp encode_unsigned_minimal(0), do: <<0x00>>

  defp encode_unsigned_minimal(n) do
    bytes = :binary.encode_unsigned(n, :big)
    # encode_unsigned strips leading zeros already.
    bytes
  end
end
