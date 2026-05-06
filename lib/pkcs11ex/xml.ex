defmodule Pkcs11ex.XML do
  @moduledoc """
  XML-DSig + XAdES B-B format adapter.

  ## Sign

      Pkcs11ex.XML.sign(xml_bytes,
        module: pkcs11_module,
        slot_id: slot_id,
        pin: "1234",
        key_label: "platform-signing-key",
        alg: :PS256,
        x5c: [leaf_der, intermediate_der]
      )

  Returns the original XML with an enveloped `<ds:Signature>`
  element spliced in before the root's closing tag. The output is a
  XAdES B-B signature with `<xades:SigningCertificateV2>`,
  `<xades:SigningTime>`, and the canonical
  `Exclusive XML Canonicalization 1.0` C14N method on every
  `<ds:Reference>` and the `<ds:SignedInfo>` element itself.

  Pipeline:

    1. Parse the input XML (xmerl).
    2. Generate fresh `signature_id` and `signed_properties_id`.
    3. Build the XAdES `<xades:QualifyingProperties>` block via
       `Pkcs11ex.XML.XAdES`. SHA-256 the leaf cert into
       `<xades:CertDigest>`; DER-encode the RFC 5035 IssuerSerial
       into `<xades:IssuerSerialV2>`.
    4. Canonicalise `<xades:SignedProperties>` (subtree only) with
       exc-c14n → SHA-256 → second `<ds:Reference>` digest.
    5. Canonicalise the input document with exc-c14n → SHA-256 →
       data `<ds:Reference>` digest. The enveloped-signature
       transform is conceptually applied; at sign time there is no
       Signature in the document yet so the transform is a no-op,
       leaving the canonical form unchanged.
    6. Build `<ds:SignedInfo>` with both references.
    7. Canonicalise `<ds:SignedInfo>` with exc-c14n. Those bytes
       are the to-be-signed input.
    8. Sign via `Pkcs11ex.sign_bytes/2` (PKCS#11 → HSM).
       **Software signing never enters the path.**
    9. Build the full `<ds:Signature>` element and splice it into
       the source XML before the root's closing tag.

  ## v1 limitations

    * Enveloped signatures only. Detached and enveloping XML-DSig
      modes are post-v1.
    * `:PS256` and `:RS256`. PS256 emits the
      `sha256-rsa-MGF1` signature method URI per RFC 4051;
      receivers should use SHA-256 / MGF1-SHA-256 / sLen=32 to
      match the HSM-produced signature.
    * Single `<ds:Reference>` URI is empty (whole-document). The
      `:reference_uri` opt is reserved for a future fragment-signing
      mode.
    * `verify/2` lands in step 4b.1.6.

  ## Architectural invariants

    * x5c is **untrusted input** until verify runs the
      configured `Pkcs11ex.Policy` (allowlist gate).
    * Signature math always runs in the HSM via
      `Pkcs11ex.sign_bytes/2`. Software signing is never invoked.
  """

  alias Pkcs11ex.Algorithm
  alias Pkcs11ex.X509
  alias Pkcs11ex.XML.{Builder, Canonicalizer, XAdES}

  @type sign_result :: {:ok, binary()} | {:error, term()}
  @type verify_result :: {:ok, subject_id :: term()} | {:error, term()}

  @doc """
  Sign an XML document with XML-DSig + XAdES B-B.
  """
  @spec sign(binary() | iodata(), keyword()) :: sign_result()
  def sign(doc, opts) when is_list(opts) do
    xml = IO.iodata_to_binary(doc)

    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, _adapter} <- Algorithm.lookup(alg),
         {:ok, x5c_der_list} <- fetch_x5c(opts),
         {:ok, leaf} <- X509.from_der(hd(x5c_der_list)),
         {:ok, root} <- Canonicalizer.parse(xml),
         {:ok, doc_canonical} <- Canonicalizer.canonicalize(root),
         data_digest = :crypto.hash(:sha256, doc_canonical),
         signature_id = "Signature-" <> Builder.random_id(),
         signed_props_id = "xades-" <> Builder.random_id(),
         signing_time = Keyword.get(opts, :signing_time, DateTime.utc_now()),
         {:ok, qp_xml} <-
           XAdES.qualifying_properties(
             signature_id: signature_id,
             signed_properties_id: signed_props_id,
             leaf_cert: leaf,
             signing_time: signing_time
           ),
         {:ok, sp_canonical} <- canonicalize_signed_properties(qp_xml),
         sp_digest = :crypto.hash(:sha256, sp_canonical),
         data_ref =
           Builder.reference(
             "",
             [Builder.transform_envelope_uri(), Builder.c14n_exclusive_uri()],
             Base.encode64(data_digest)
           ),
         sp_ref =
           Builder.reference(
             "##{signed_props_id}",
             [Builder.c14n_exclusive_uri()],
             Base.encode64(sp_digest),
             type: Builder.reference_xades_signed_properties_type()
           ),
         signed_info_xml = Builder.signed_info([data_ref, sp_ref], alg),
         {:ok, si_root} <- Canonicalizer.parse(signed_info_xml),
         {:ok, si_canonical} <- Canonicalizer.canonicalize(si_root),
         signer_opts = signer_opts(opts, alg),
         {:ok, raw_sig} <-
           Pkcs11ex.sign_bytes(si_canonical, [{:encoding_context, :der} | signer_opts]),
         cert_b64_list = Enum.map(x5c_der_list, &Base.encode64/1),
         signature_xml =
           Builder.signature(
             signed_info_xml,
             Base.encode64(raw_sig),
             cert_b64_list,
             qp_xml,
             signature_id: signature_id
           ),
         {:ok, signed_xml} <- splice_signature(xml, root, signature_xml) do
      {:ok, signed_xml}
    end
  end

  @doc """
  Verify a signed XML document. Implementation lands in Phase 4b.1.6.
  """
  @spec verify(binary() | iodata(), keyword()) :: verify_result()
  def verify(_doc, _opts \\ []), do: {:error, :not_implemented_in_v1}

  # ---------- internals ----------

  defp fetch_alg(opts), do: {:ok, Keyword.get(opts, :alg, :PS256)}

  defp check_alg_allowed(alg) do
    allowed = Application.get_env(:pkcs11ex, :allowed_algs, [:PS256])

    cond do
      alg == :none -> {:error, :disallowed_alg}
      alg in allowed -> :ok
      true -> {:error, :disallowed_alg}
    end
  end

  defp fetch_x5c(opts) do
    case Keyword.fetch(opts, :x5c) do
      {:ok, der} when is_binary(der) ->
        {:ok, [der]}

      {:ok, ders} when is_list(ders) ->
        if Enum.all?(ders, &is_binary/1) and ders != [],
          do: {:ok, ders},
          else: {:error, :invalid_x5c}

      _ ->
        {:error, :missing_x5c}
    end
  end

  defp signer_opts(opts, alg) do
    cleaned =
      Keyword.drop(opts, [
        :x5c,
        :signing_time,
        :encoding_context,
        :reference_uri,
        :c14n_method,
        :digest_method,
        :inclusive_namespaces
      ])

    Keyword.put(cleaned, :alg, alg)
  end

  # Parse the QP XML, locate the `<xades:SignedProperties>` subtree,
  # and canonicalise it via exc-c14n. The verifier does the same —
  # extracts `<xades:SignedProperties>` from the doc and feeds the
  # canonical bytes to SHA-256.
  defp canonicalize_signed_properties(qp_xml) do
    with {:ok, qp_root} <- Canonicalizer.parse(qp_xml),
         {:ok, sp_node} <- find_signed_properties(qp_root) do
      Canonicalizer.canonicalize(sp_node)
    end
  end

  defp find_signed_properties({:xmlElement, _, _, _, _, _, _, _, content, _, _, _}) do
    case Enum.find(content, &signed_properties?/1) do
      nil -> {:error, {:xml, :signed_properties_not_found}}
      node -> {:ok, node}
    end
  end

  defp signed_properties?({:xmlElement, name, _, _, _, _, _, _, _, _, _, _}) do
    name_str = Atom.to_string(name)
    String.ends_with?(name_str, "SignedProperties")
  end

  defp signed_properties?(_), do: false

  # Splice the `<ds:Signature>` element into the document before the
  # root's closing tag. The root name comes from the parsed xmerl
  # tree; we locate the last occurrence of `</root>` (or the
  # self-closing `<root/>` form) in the source and insert before it.
  defp splice_signature(xml, root, signature_xml) do
    root_name = elem(root, 1) |> Atom.to_string()
    closing_tag = "</#{root_name}>"

    case :binary.matches(xml, closing_tag) do
      [] ->
        # Maybe self-closing root: `<root/>`.
        self_closing = "<#{root_name}/>"

        case :binary.match(xml, self_closing) do
          {pos, len} ->
            prefix = binary_part(xml, 0, pos)

            opening_tag =
              "<#{root_name}>"

            suffix = binary_part(xml, pos + len, byte_size(xml) - pos - len)

            {:ok, prefix <> opening_tag <> signature_xml <> closing_tag <> suffix}

          :nomatch ->
            {:error, {:xml, :root_tag_not_found}}
        end

      matches ->
        {pos, len} = List.last(matches)
        prefix = binary_part(xml, 0, pos)
        suffix = binary_part(xml, pos + len, byte_size(xml) - pos - len)
        {:ok, prefix <> signature_xml <> closing_tag <> suffix}
    end
  end
end
