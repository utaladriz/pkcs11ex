defmodule Pkcs11ex.XML.Builder do
  @moduledoc """
  Builds XML-DSig elements for the XAdES B-B sign flow.

  The shape produced is the W3C XML Signature 1.1 envelope:

      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm=".../exc-c14n#"/>
          <ds:SignatureMethod Algorithm="..."/>
          <ds:Reference URI="...">
            <ds:Transforms>
              <ds:Transform Algorithm=".../enveloped-signature"/>
              <ds:Transform Algorithm=".../exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm=".../sha256"/>
            <ds:DigestValue>...</ds:DigestValue>
          </ds:Reference>
          <ds:Reference Type="...SignedProperties" URI="#xades-...">
            <ds:Transforms>
              <ds:Transform Algorithm=".../exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm=".../sha256"/>
            <ds:DigestValue>...</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>...</ds:SignatureValue>
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>...</ds:X509Certificate>
            ...
          </ds:X509Data>
        </ds:KeyInfo>
        <ds:Object>
          <xades:QualifyingProperties .../>
        </ds:Object>
      </ds:Signature>

  Builder functions emit raw binary XML — exc-c14n is applied during
  digest / signature computation, so attribute order and whitespace
  in these strings is normalised away before any hash is taken.
  """

  @ds_ns "http://www.w3.org/2000/09/xmldsig#"
  @xades_ns "http://uri.etsi.org/01903/v1.3.2#"

  @c14n_exclusive "http://www.w3.org/2001/10/xml-exc-c14n#"
  @transform_envelope "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  @digest_sha256 "http://www.w3.org/2001/04/xmlenc#sha256"

  # Signature method URIs per RFC 4051 / XMLDsig-more.
  @sig_rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @sig_rsa_pss_sha256 "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"

  @reference_xades_signed_properties_type "http://uri.etsi.org/01903#SignedProperties"

  @doc "URI namespace for the XML Signature `ds:` prefix (W3C XMLDSig)."
  def ds_ns, do: @ds_ns

  @doc "URI namespace for the XAdES `xades:` prefix."
  def xades_ns, do: @xades_ns

  @doc "Canonicalisation method URI for Exclusive XML C14N 1.0."
  def c14n_exclusive_uri, do: @c14n_exclusive

  @doc "Digest method URI for SHA-256."
  def digest_sha256_uri, do: @digest_sha256

  @doc "Transform URI for the `enveloped-signature` rewrite."
  def transform_envelope_uri, do: @transform_envelope

  @doc """
  Returns the XML Signature URI for a given JOSE alg atom.

      iex> Pkcs11ex.XML.Builder.signature_method_uri(:RS256)
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

      iex> Pkcs11ex.XML.Builder.signature_method_uri(:PS256)
      "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
  """
  @spec signature_method_uri(atom()) :: String.t()
  def signature_method_uri(:RS256), do: @sig_rsa_sha256
  def signature_method_uri(:PS256), do: @sig_rsa_pss_sha256

  @doc """
  Map an XML Signature URI back to a JOSE alg atom. Inverse of
  `signature_method_uri/1`.
  """
  @spec alg_from_signature_method_uri(String.t()) :: {:ok, atom()} | {:error, term()}
  def alg_from_signature_method_uri(@sig_rsa_sha256), do: {:ok, :RS256}
  def alg_from_signature_method_uri(@sig_rsa_pss_sha256), do: {:ok, :PS256}
  def alg_from_signature_method_uri(other), do: {:error, {:unsupported_signature_method, other}}

  @doc """
  Build a `<ds:Reference>` element targeting a fragment of the
  enveloping document. `:transforms` is a list of transform URIs
  applied left-to-right; the typical XAdES B-B set is
  `[envelope, exc_c14n]` for the data reference and `[exc_c14n]`
  for the SignedProperties reference.
  """
  @spec reference(String.t(), [String.t()], binary(), keyword()) :: String.t()
  def reference(uri, transforms, digest_value_b64, opts \\ []) do
    type_attr =
      case Keyword.get(opts, :type) do
        nil -> ""
        type -> ~s( Type="#{escape_attr(type)}")
      end

    transforms_xml =
      transforms
      |> Enum.map_join("", fn algo ->
        ~s(<ds:Transform Algorithm="#{escape_attr(algo)}"></ds:Transform>)
      end)

    transforms_block =
      if transforms == [] do
        ""
      else
        "<ds:Transforms>" <> transforms_xml <> "</ds:Transforms>"
      end

    ~s(<ds:Reference#{type_attr} URI="#{escape_attr(uri)}">) <>
      transforms_block <>
      ~s(<ds:DigestMethod Algorithm="#{@digest_sha256}"></ds:DigestMethod>) <>
      ~s(<ds:DigestValue>#{digest_value_b64}</ds:DigestValue>) <>
      "</ds:Reference>"
  end

  @doc """
  Build a `<ds:SignedInfo>` element wrapping the supplied
  references. The `:alg` selects the `<ds:SignatureMethod>` URI.
  """
  @spec signed_info([String.t()], atom()) :: String.t()
  def signed_info(references_xml, alg) do
    ~s(<ds:SignedInfo xmlns:ds="#{@ds_ns}">) <>
      ~s(<ds:CanonicalizationMethod Algorithm="#{@c14n_exclusive}"></ds:CanonicalizationMethod>) <>
      ~s(<ds:SignatureMethod Algorithm="#{signature_method_uri(alg)}"></ds:SignatureMethod>) <>
      Enum.join(references_xml, "") <>
      "</ds:SignedInfo>"
  end

  @doc """
  Build the full `<ds:Signature>` envelope. Ready to splice into the
  document at the chosen insertion point.

  Args:
    * `signed_info_xml` — the `<ds:SignedInfo>` block produced by
      `signed_info/2`. Used **verbatim** (after exc-c14n) so that
      the signature is computed over the same bytes the
      verifier sees.
    * `signature_value_b64` — base64 of the raw signature.
    * `x509_chain_b64` — list of base64-encoded DER certs. Leaf first.
    * `qualifying_properties_xml` — the XAdES `<xades:QualifyingProperties>`
      element produced by `Pkcs11ex.XML.XAdES`.
    * `:signature_id` — the `Id` attribute on `<ds:Signature>`.
      Required for XAdES-LT compatibility; v1 just emits a fresh
      one if not supplied.
  """
  @spec signature(String.t(), binary(), [binary()], String.t(), keyword()) :: String.t()
  def signature(signed_info_xml, signature_value_b64, x509_chain_b64, qualifying_properties_xml, opts \\ []) do
    signature_id = Keyword.get(opts, :signature_id, "Signature-#{random_id()}")

    cert_elements =
      x509_chain_b64
      |> Enum.map_join("", fn cert_b64 ->
        ~s(<ds:X509Certificate>#{cert_b64}</ds:X509Certificate>)
      end)

    ~s(<ds:Signature xmlns:ds="#{@ds_ns}" Id="#{escape_attr(signature_id)}">) <>
      signed_info_xml <>
      ~s(<ds:SignatureValue>#{signature_value_b64}</ds:SignatureValue>) <>
      "<ds:KeyInfo><ds:X509Data>" <>
      cert_elements <>
      "</ds:X509Data></ds:KeyInfo>" <>
      "<ds:Object>" <>
      qualifying_properties_xml <>
      "</ds:Object>" <>
      "</ds:Signature>"
  end

  @doc "URI tag for the standard XAdES SignedProperties reference Type attribute."
  def reference_xades_signed_properties_type, do: @reference_xades_signed_properties_type

  @doc "Helper: 8-byte hex random id suitable for XML Id attributes."
  @spec random_id() :: String.t()
  def random_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp escape_attr(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(~s("), "&quot;")
  end
end
