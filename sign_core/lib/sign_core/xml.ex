defmodule SignCore.XML do
  @moduledoc """
  XML-DSig + XAdES B-B format adapter.

  ## Sign

      SignCore.XML.sign(xml_bytes,
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
       `SignCore.XML.XAdES`. SHA-256 the leaf cert into
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
      configured `SignCore.Policy` (allowlist gate).
    * Signature math always runs in the HSM via
      `Pkcs11ex.sign_bytes/2`. Software signing is never invoked.
  """

  alias SignCore.Algorithm
  alias SignCore.X509
  alias SignCore.XML.{Builder, Canonicalizer, XAdES}

  @ds_local_signature "Signature"
  @ds_local_signed_info "SignedInfo"
  @ds_local_signature_method "SignatureMethod"
  @ds_local_signature_value "SignatureValue"
  @ds_local_key_info "KeyInfo"
  @ds_local_x509_data "X509Data"
  @ds_local_x509_cert "X509Certificate"
  @ds_local_object "Object"
  @ds_local_reference "Reference"
  @ds_local_digest_value "DigestValue"
  @xades_local_qp "QualifyingProperties"
  @xades_local_sp "SignedProperties"
  @xades_local_cert_digest "CertDigest"
  @xades_local_issuer_serial_v2 "IssuerSerialV2"
  @xades_local_signing_time "SigningTime"

  @type sign_result :: {:ok, binary()} | {:error, term()}
  @type verify_result :: {:ok, subject_id :: term()} | {:error, term()}

  @doc """
  Sign an XML document with XML-DSig + XAdES B-B.
  """
  @spec sign(binary() | iodata(), keyword()) :: sign_result()
  def sign(doc, opts) when is_list(opts) do
    xml = IO.iodata_to_binary(doc)
    start_meta = base_telemetry_meta(opts)

    :telemetry.span([:pkcs11ex, :sign], start_meta, fn ->
      result = sign_inner(xml, opts)
      stop_meta = Map.merge(start_meta, sign_stop_meta(result))
      {result, stop_meta}
    end)
  end

  defp sign_inner(xml, opts) do
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
         {:ok, signer} <- fetch_signer(opts),
         signer_opts = signer_opts(opts, alg),
         {:ok, raw_sig} <-
           SignCore.Signer.sign(signer, si_canonical, [{:encoding_context, :der} | signer_opts]),
         {:ok, qp_xml_final} <- maybe_attach_signature_timestamp(qp_xml, raw_sig, opts),
         cert_b64_list = Enum.map(x5c_der_list, &Base.encode64/1),
         signature_xml =
           Builder.signature(
             signed_info_xml,
             Base.encode64(raw_sig),
             cert_b64_list,
             qp_xml_final,
             signature_id: signature_id
           ),
         {:ok, signed_xml} <- splice_signature(xml, root, signature_xml) do
      {:ok, signed_xml}
    end
  end

  @doc """
  Verify a XAdES B-B-signed XML document.

  Returns `{:ok, subject_id}` where `subject_id` is whatever the
  configured `SignCore.Policy.validate/3` returned. The verify
  pipeline runs in this order — every step is a checkpoint that
  can refuse the signature with the documented error class:

    1. Parse the signed XML. Locate the (single) `<ds:Signature>`
       element. v1 refuses multi-signature documents.
    2. Extract the embedded `<ds:KeyInfo>` x5c chain.
    3. **Allowlist gate (architectural invariant).** Synthesise a
       JOSE-style header and route it through the configured
       `SignCore.Policy` — `resolve/2` then `validate/3`. The
       chain is **untrusted input** until both succeed. No
       cryptographic check has happened yet.
    4. Verify the XAdES `<xades:SigningCertificateV2>` actually
       binds the leaf cert from `<ds:KeyInfo>`:
       `SHA-256(leaf_der)` must match `<xades:CertDigest>`, and
       `<xades:IssuerSerialV2>` must match the leaf's issuer +
       serial.
    5. Recompute the data `<ds:Reference>` digest: apply the
       enveloped-signature transform (remove `<Signature>` from
       the doc), exc-c14n the result, SHA-256.
    6. Recompute the SignedProperties `<ds:Reference>` digest:
       canonicalise the `<xades:SignedProperties>` subtree,
       SHA-256.
    7. Canonicalise `<ds:SignedInfo>` (subtree extraction with
       inherited-default-namespace clear) and verify the math
       against the leaf's SPKI.

  Failures from step 3 short-circuit before any signature math, so
  callers cannot use `verify/2` as a CPU-bound oracle on
  attacker-supplied certificates.
  """
  @spec verify(binary() | iodata(), keyword()) :: verify_result()
  def verify(doc, opts \\ [])

  def verify(doc, opts) when is_list(opts) do
    xml = IO.iodata_to_binary(doc)
    start_meta = base_telemetry_meta(opts)

    :telemetry.span([:pkcs11ex, :verify], start_meta, fn ->
      result = verify_inner(xml, opts)
      stop_meta = Map.merge(start_meta, verify_stop_meta(result, byte_size(xml)))
      {result, stop_meta}
    end)
  end

  defp verify_inner(xml, opts) do
    with {:ok, root} <- Canonicalizer.parse(xml),
         {:ok, sig_node} <- locate_signature(root),
         {:ok, ctx} <- collect_signature_context(sig_node),
         {:ok, header} <- header_from_chain(ctx.x5c_ders),
         policy = Keyword.get(opts, :trust_policy, configured_policy()),
         {:ok, cert, chain} <- policy.resolve(header, opts),
         {:ok, subject_id} <-
           policy.validate(cert, chain, Keyword.get(opts, :policy_opts, [])),
         :ok <- check_xades_cert_binding(ctx, cert),
         :ok <- check_signing_time_in_validity(ctx, cert, opts),
         :ok <- check_data_reference(xml, root, sig_node, ctx),
         :ok <- check_signed_properties_reference(ctx),
         :ok <- verify_signature_math(ctx, cert) do
      {:ok, subject_id}
    end
  end

  # XAdES `<xades:SigningTime>` cross-check against cert validity.
  # Same rationale as the PAdES PDF check: a signing time outside the
  # leaf's not-before / not-after window means the cert wasn't actually
  # valid when the signature was claimed to be made.
  #
  # Opt-out via `verify(..., check_signing_time: false)`. Default-on.
  # When `<xades:SigningTime>` is absent (uncommon for XAdES B-B but
  # not strictly forbidden by the spec), we skip unless
  # `require_signing_time: true`.
  defp check_signing_time_in_validity(ctx, cert, opts) do
    case Keyword.get(opts, :check_signing_time, true) do
      false ->
        :ok

      _ ->
        case extract_signing_time(ctx.signed_properties_node) do
          {:ok, signing_time} ->
            X509.check_validity(cert, signing_time)

          :missing ->
            if Keyword.get(opts, :require_signing_time, false) do
              {:error, :missing_signing_time}
            else
              :ok
            end

          {:error, _} = err ->
            err
        end
    end
  end

  defp extract_signing_time(sp_node) do
    case collect_descendants(sp_node, @xades_local_signing_time) do
      [] ->
        :missing

      [st_node | _] ->
        iso = st_node |> text_content() |> String.trim()

        case DateTime.from_iso8601(iso) do
          {:ok, dt, _offset} -> {:ok, dt}
          _ -> {:error, :xades_signing_time_unparseable}
        end
    end
  end

  # ---------- internals ----------

  # `:alg` is required across all format adapters (`SignCore.PDF`,
  # `SignCore.JWS`, `Pkcs11ex.sign_bytes/2` all reject missing). XML
  # used to default silently to `:PS256` — an inconsistency that let
  # caller typos (`:algg`) slip through. Now matches the rest of the
  # surface: explicit or error.
  defp fetch_alg(opts) do
    case Keyword.fetch(opts, :alg) do
      {:ok, alg} when is_atom(alg) -> {:ok, alg}
      _ -> {:error, :missing_alg}
    end
  end

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

  defp fetch_signer(opts) do
    case Keyword.fetch(opts, :signer) do
      {:ok, signer} -> {:ok, signer}
      :error -> {:error, :missing_signer}
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
        :inclusive_namespaces,
        :tsa_url,
        :tsa_timeout
      ])

    Keyword.put(cleaned, :alg, alg)
  end

  # XAdES B-T (ETSI EN 319 132-1 §5.4.1): when `:tsa_url` is set,
  # request an RFC 3161 TimeStampToken whose hash covers the
  # canonicalised `<ds:SignatureValue>` element bytes (NOT the raw
  # signature) and append a `<xades:UnsignedProperties>` block with
  # `<xades:SignatureTimeStamp>` to the QualifyingProperties.
  defp maybe_attach_signature_timestamp(qp_xml, raw_sig, opts) do
    case Keyword.get(opts, :tsa_url) do
      nil ->
        {:ok, qp_xml}

      tsa_url ->
        if Code.ensure_loaded?(Pkcs11ex.Audit.Anchor.RFC3161) do
          do_attach_signature_timestamp(qp_xml, raw_sig, tsa_url, opts)
        else
          {:error, {:bt_failed, :pkcs11ex_audit_not_loaded}}
        end
    end
  end

  @compile {:no_warn_undefined, [Pkcs11ex.Audit.Anchor.RFC3161]}

  defp do_attach_signature_timestamp(qp_xml, raw_sig, tsa_url, opts) do
    timeout = Keyword.get(opts, :tsa_timeout, 10_000)
    rfc3161 = Pkcs11ex.Audit.Anchor.RFC3161
    timestamp_id = "ts-" <> Builder.random_id()

    with {:ok, sig_value_canonical} <- canonical_signature_value(raw_sig),
         digest = :crypto.hash(:sha256, sig_value_canonical),
         {:ok, %{der: req_der}} <- apply(rfc3161, :build_request, [digest]),
         {:ok, body} <- apply(rfc3161, :fetch_token, [tsa_url, req_der, [timeout: timeout]]),
         {:ok, tst_der} <- apply(rfc3161, :extract_token, [body]),
         {:ok, up_block} <-
           XAdES.unsigned_signature_timestamp(tst_der: tst_der, timestamp_id: timestamp_id),
         {:ok, qp_with_up} <- XAdES.splice_unsigned_properties(qp_xml, up_block) do
      {:ok, qp_with_up}
    else
      {:error, reason} -> {:error, {:bt_failed, reason}}
    end
  end

  # Build the canonical bytes of the standalone `<ds:SignatureValue>`
  # element exactly as a verifier would produce by extracting the
  # element from the signed doc and canonicalising it (after clearing
  # any inherited default namespace via `canonicalize_subtree`).
  #
  # Returns `{:error, {:xml, reason}}` if parse / canonicalisation
  # fails — never raises, so the surrounding B-T pipeline can route
  # the failure through its `:bt_failed` wrapper cleanly.
  defp canonical_signature_value(raw_sig) do
    elem_xml = Builder.signature_value(Base.encode64(raw_sig))

    with {:ok, node} <- Canonicalizer.parse(elem_xml),
         {:ok, canonical} <- Canonicalizer.canonicalize(node) do
      {:ok, canonical}
    end
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
    String.ends_with?(elem_name_to_binary(name), "SignedProperties")
  end

  defp signed_properties?(_), do: false

  # ---------- verify-side helpers ----------

  defp locate_signature(root) do
    sigs = collect_descendants(root, @ds_local_signature)

    case sigs do
      [] -> {:error, :no_signature_element}
      [one] -> {:ok, one}
      _ -> {:error, :multiple_signatures_unsupported_in_v1}
    end
  end

  defp collect_signature_context(sig_node) do
    with {:ok, signed_info} <- find_child_by_local(sig_node, @ds_local_signed_info),
         {:ok, sig_value_node} <- find_child_by_local(sig_node, @ds_local_signature_value),
         {:ok, key_info} <- find_child_by_local(sig_node, @ds_local_key_info),
         {:ok, x509_data} <- find_child_by_local(key_info, @ds_local_x509_data),
         {:ok, x5c_ders} <- collect_x509_certs(x509_data),
         {:ok, alg} <- extract_signature_alg(signed_info),
         {:ok, refs} <- collect_references(signed_info),
         {:ok, sp_node} <- locate_signed_properties(sig_node),
         {:ok, raw_sig} <- decode_signature_value(sig_value_node),
         {:ok, si_canonical} <- Canonicalizer.canonicalize_subtree(signed_info),
         {:ok, sp_canonical} <- Canonicalizer.canonicalize_subtree(sp_node),
         {:ok, cert_digest} <- extract_cert_digest(sig_node),
         {:ok, issuer_serial_v2} <- extract_issuer_serial_v2(sig_node) do
      ctx = %{
        signed_info_node: signed_info,
        signed_info_canonical: si_canonical,
        sig_value_raw: raw_sig,
        x5c_ders: x5c_ders,
        alg: alg,
        references: refs,
        signed_properties_node: sp_node,
        signed_properties_canonical: sp_canonical,
        cert_digest: cert_digest,
        issuer_serial_v2_der: issuer_serial_v2
      }

      {:ok, ctx}
    end
  end

  defp header_from_chain([]), do: {:error, :missing_x5c}

  defp header_from_chain(certs) when is_list(certs) do
    {:ok, %{"x5c" => Enum.map(certs, &Base.encode64/1)}}
  end

  defp configured_policy do
    Application.get_env(:pkcs11ex, :trust_policy, SignCore.Policy.PinnedRegistry)
  end

  # ---------- telemetry helpers ----------

  defp base_telemetry_meta(opts) do
    %{
      format: :xml,
      alg: Keyword.get(opts, :alg, :PS256),
      encoding_context: :der,
      slot_ref: opts_slot_ref(opts),
      key_ref: opts_key_ref(opts)
    }
  end

  defp opts_slot_ref(opts) do
    case Keyword.get(opts, :signer) do
      %{slot_ref: ref} when not is_nil(ref) -> ref
      {slot_ref, _key_ref} -> slot_ref
      atom when is_atom(atom) and not is_nil(atom) -> atom
      _ -> Keyword.get(opts, :slot_ref) || Keyword.get(opts, :slot_id)
    end
  end

  defp opts_key_ref(opts) do
    case Keyword.get(opts, :signer) do
      %{key_ref: ref} when not is_nil(ref) -> ref
      {_slot_ref, key_ref} -> key_ref
      _ -> Keyword.get(opts, :key_ref) || Keyword.get(opts, :key_label)
    end
  end

  defp sign_stop_meta({:ok, signed_xml}) when is_binary(signed_xml),
    do: %{byte_count: byte_size(signed_xml)}

  defp sign_stop_meta({:error, reason}),
    do: %{error_class: error_class(reason), error_reason: reason}

  defp verify_stop_meta({:ok, subject_id}, byte_count),
    do: %{subject_id: subject_id, byte_count: byte_count}

  defp verify_stop_meta({:error, reason}, byte_count),
    do: %{
      byte_count: byte_count,
      error_class: error_class(reason),
      error_reason: reason
    }

  defp error_class({:c14n, _}), do: :xml
  defp error_class({:malformed_xml, _}), do: :xml
  defp error_class({:bt_failed, _}), do: :xml
  defp error_class({:xml, _}), do: :xml
  defp error_class({:missing_xades_opt, _}), do: :xml
  defp error_class({:xades_missing_cert_digest, _}), do: :xml
  defp error_class({:xades_missing_issuer_serial_v2, _}), do: :xml
  defp error_class({:unsupported_signature_method, _}), do: :xml

  defp error_class(reason)
       when reason in [
              :no_signature_element,
              :multiple_signatures_unsupported_in_v1,
              :digest_mismatch,
              :xades_cert_digest_mismatch,
              :xades_issuer_serial_mismatch,
              :unsupported_canonicalization
            ],
       do: :xml

  # `:input` covers cross-format input-validation reasons that aren't
  # specific to PDF/XML/JWS. Previously misattributed to `:jws` because
  # the atoms (`:missing_x5c`, etc.) originated in the JWS module.
  defp error_class(reason)
       when reason in [:missing_x5c, :invalid_x5c, :missing_alg, :disallowed_alg],
       do: :input

  defp error_class(reason)
       when reason in [
              :unknown_signer,
              :hint_mismatch,
              :untrusted_signer,
              :cert_expired,
              :cert_not_yet_valid,
              :cert_validity_unparseable,
              :chain_invalid,
              :incomplete_chain,
              :missing_signing_time
            ],
       do: :trust_policy

  defp error_class(:xades_signing_time_unparseable), do: :xml

  defp error_class(:signature_invalid), do: :crypto
  defp error_class({:unsupported_signature_algorithm, _}), do: :crypto
  defp error_class(_), do: :unknown

  defp check_xades_cert_binding(ctx, %X509{der: leaf_der}) do
    expected_digest = :crypto.hash(:sha256, leaf_der)

    cond do
      ctx.cert_digest != expected_digest ->
        {:error, :xades_cert_digest_mismatch}

      true ->
        case build_expected_issuer_serial_v2(leaf_der) do
          {:ok, expected_der} when expected_der == ctx.issuer_serial_v2_der ->
            :ok

          {:ok, _} ->
            {:error, :xades_issuer_serial_mismatch}

          {:error, _} = err ->
            err
        end
    end
  end

  defp build_expected_issuer_serial_v2(leaf_der) do
    {:ok, leaf} = X509.from_der(leaf_der)
    XAdES.build_issuer_serial_v2_der(leaf)
  end

  # Apply the enveloped-signature transform: remove the <Signature>
  # element from the document, then exc-c14n the result, SHA-256.
  defp check_data_reference(_xml, root, sig_node, ctx) do
    expected_digest = digest_for_reference_uri(ctx.references, "")
    doc_with_sig_removed = strip_signature(root, sig_node)

    with {:ok, canonical} <- Canonicalizer.canonicalize(doc_with_sig_removed) do
      actual = :crypto.hash(:sha256, canonical)

      if actual == expected_digest do
        :ok
      else
        {:error, :digest_mismatch}
      end
    end
  end

  defp check_signed_properties_reference(ctx) do
    sp_id = elem_id(ctx.signed_properties_node)
    expected_digest = digest_for_reference_uri(ctx.references, "##{sp_id}")
    actual = :crypto.hash(:sha256, ctx.signed_properties_canonical)

    if actual == expected_digest do
      :ok
    else
      {:error, :digest_mismatch}
    end
  end

  defp verify_signature_math(%{alg: :PS256} = ctx, %X509{public_key: pk}) do
    if :public_key.verify(ctx.signed_info_canonical, :sha256, ctx.sig_value_raw, pk,
         rsa_padding: :rsa_pkcs1_pss_padding,
         rsa_pss_saltlen: 32,
         rsa_mgf1_md: :sha256
       ) do
      :ok
    else
      {:error, :signature_invalid}
    end
  end

  defp verify_signature_math(%{alg: :RS256} = ctx, %X509{public_key: pk}) do
    if :public_key.verify(ctx.signed_info_canonical, :sha256, ctx.sig_value_raw, pk) do
      :ok
    else
      {:error, :signature_invalid}
    end
  end

  defp verify_signature_math(%{alg: alg}, _cert),
    do: {:error, {:unsupported_signature_algorithm, alg}}

  # ---------- xmerl tree helpers ----------

  defp collect_descendants(
         {:xmlElement, _, _, _, _, _, _, _, content, _, _, _} = node,
         local_name
       ) do
    self_match = if local_name?(node, local_name), do: [node], else: []

    children =
      content
      |> Enum.flat_map(fn child ->
        case child do
          {:xmlElement, _, _, _, _, _, _, _, _, _, _, _} ->
            collect_descendants(child, local_name)

          _ ->
            []
        end
      end)

    self_match ++ children
  end

  defp collect_descendants(_, _), do: []

  defp find_child_by_local({:xmlElement, _, _, _, _, _, _, _, content, _, _, _}, local_name) do
    case Enum.find(content, fn
           {:xmlElement, _, _, _, _, _, _, _, _, _, _, _} = e -> local_name?(e, local_name)
           _ -> false
         end) do
      nil -> {:error, {:xml, {:child_not_found, local_name}}}
      node -> {:ok, node}
    end
  end

  defp local_name?({:xmlElement, name, _, _, _, _, _, _, _, _, _, _}, local) do
    name_str = elem_name_to_binary(name)
    name_str == local or String.ends_with?(name_str, ":" <> local)
  end

  defp local_name?(_, _), do: false

  # xmerl element names are typically atoms (`:"ds:Signature"` for
  # namespaced names) but can also be charlists or binaries depending
  # on parser opts. Same treatment as `attr_name_to_binary/1`.
  defp elem_name_to_binary(name) when is_atom(name), do: Atom.to_string(name)
  defp elem_name_to_binary(name) when is_list(name), do: List.to_string(name)
  defp elem_name_to_binary(name) when is_binary(name), do: name

  defp collect_x509_certs(x509_data_node) do
    cert_nodes = collect_descendants(x509_data_node, @ds_local_x509_cert)

    if cert_nodes == [] do
      {:error, :missing_x5c}
    else
      cert_nodes
      |> Enum.reduce_while({:ok, []}, fn n, {:ok, acc} ->
        cleaned = n |> text_content() |> String.replace(~r/\s+/, "")

        case Base.decode64(cleaned) do
          {:ok, der} -> {:cont, {:ok, [der | acc]}}
          :error -> {:halt, {:error, :invalid_x5c}}
        end
      end)
      |> case do
        {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
        err -> err
      end
    end
  end

  # Strip XML whitespace and try to base64-decode. Sender-supplied
  # untrusted input — must NOT raise; surface as a tagged error so
  # the verify pipeline's `with` chain handles it cleanly.
  defp decode_b64_text(node, error_tag) do
    cleaned = node |> text_content() |> String.replace(~r/\s+/, "")

    case Base.decode64(cleaned) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, error_tag}
    end
  end

  defp extract_signature_alg(signed_info_node) do
    case find_child_by_local(signed_info_node, @ds_local_signature_method) do
      {:ok, sm_node} ->
        algo = attr_value(sm_node, "Algorithm")
        Builder.alg_from_signature_method_uri(algo || "")

      err ->
        err
    end
  end

  defp collect_references(signed_info_node) do
    refs = collect_descendants(signed_info_node, @ds_local_reference)

    refs
    |> Enum.reduce_while({:ok, []}, fn r, {:ok, acc} ->
      digest_result =
        case find_child_by_local(r, @ds_local_digest_value) do
          {:ok, n} -> decode_b64_text(n, :invalid_reference_digest)
          _ -> {:ok, nil}
        end

      case digest_result do
        {:ok, digest_value} ->
          ref = %{uri: attr_value(r, "URI") || "", digest_value: digest_value}
          {:cont, {:ok, [ref | acc]}}

        {:error, _} = err ->
          {:halt, err}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      err -> err
    end
  end

  defp locate_signed_properties(sig_node) do
    case collect_descendants(sig_node, @xades_local_sp) do
      [sp] -> {:ok, sp}
      [] -> {:error, {:xml, :signed_properties_not_found}}
      _ -> {:error, {:xml, :multiple_signed_properties}}
    end
  end

  defp decode_signature_value(sig_value_node) do
    decode_b64_text(sig_value_node, :invalid_signature_value)
  end

  defp extract_cert_digest(sig_node) do
    case collect_descendants(sig_node, @xades_local_cert_digest) do
      [cd_node] ->
        case find_child_by_local(cd_node, @ds_local_digest_value) do
          {:ok, dv_node} ->
            decode_b64_text(dv_node, :xades_invalid_cert_digest)

          err ->
            err
        end

      _ ->
        {:error, {:xades_missing_cert_digest, nil}}
    end
  end

  defp extract_issuer_serial_v2(sig_node) do
    case collect_descendants(sig_node, @xades_local_issuer_serial_v2) do
      [is_node] ->
        decode_b64_text(is_node, :xades_invalid_issuer_serial_v2)

      _ ->
        {:error, {:xades_missing_issuer_serial_v2, nil}}
    end
  end

  defp digest_for_reference_uri(refs, uri) do
    case Enum.find(refs, fn r -> r.uri == uri end) do
      nil -> nil
      r -> r.digest_value
    end
  end

  defp elem_id({:xmlElement, _, _, _, _, _, _, attrs, _, _, _, _}) do
    find_attr_value(attrs, "Id")
  end

  defp attr_value({:xmlElement, _, _, _, _, _, _, attrs, _, _, _, _}, attr_name) do
    find_attr_value(attrs, attr_name)
  end

  # xmerl returns attribute names as either atoms or charlists depending
  # on parser opts and namespace handling. Pre-fix this code only handled
  # atoms — charlist-named attributes silently returned nil, causing
  # downstream `:digest_mismatch` failures with no clear cause. Normalise
  # both shapes to a binary before comparing.
  defp find_attr_value(attrs, name) do
    case Enum.find(attrs, fn
           {:xmlAttribute, attr_name, _, _, _, _, _, _, _, _} ->
             attr_name_to_binary(attr_name) == name
         end) do
      {:xmlAttribute, _, _, _, _, _, _, _, value, _} -> IO.iodata_to_binary([value])
      _ -> nil
    end
  end

  defp attr_name_to_binary(name) when is_atom(name), do: Atom.to_string(name)
  defp attr_name_to_binary(name) when is_list(name), do: List.to_string(name)
  defp attr_name_to_binary(name) when is_binary(name), do: name

  defp text_content({:xmlElement, _, _, _, _, _, _, _, content, _, _, _}) do
    content
    |> Enum.flat_map(fn
      {:xmlText, _, _, _, value, _} -> [value]
      _ -> []
    end)
    |> IO.iodata_to_binary()
  end

  defp text_content(_), do: ""

  # Walk the parsed tree, returning a copy with `target_node`
  # excised from its parent's content list. Used to apply the
  # enveloped-signature transform.
  defp strip_signature(node, target_node) do
    case node do
      {:xmlElement, _, _, _, _, _, _, _, content, _, _, _} ->
        new_content =
          content
          |> Enum.reject(fn child -> child === target_node end)
          |> Enum.map(fn child -> strip_signature(child, target_node) end)

        put_elem(node, 8, new_content)

      _ ->
        node
    end
  end

  # Splice the `<ds:Signature>` element into the document before the
  # root's closing tag. The root name comes from the parsed xmerl
  # tree. We locate the last occurrence of `</root>` (or the
  # self-closing `<root/>` form) in the source — but filtering out
  # any match that falls inside an XML comment (`<!-- ... -->`) or
  # CDATA section (`<![CDATA[ ... ]]>`), where the literal text
  # `</root>` is legal but not a real closing tag.
  #
  # Without that filtering, a comment containing the root's name
  # could shift `List.last/1` onto the wrong byte position.
  # Well-formed XML can't carry the unescaped `<` outside comments
  # or CDATA, so this filter covers the realistic threat surface.
  defp splice_signature(xml, root, signature_xml) do
    root_name = elem(root, 1) |> Atom.to_string()
    closing_tag = "</#{root_name}>"
    excluded = collect_excluded_ranges(xml)

    case last_match_outside(xml, closing_tag, excluded) do
      {:ok, pos, len} ->
        prefix = binary_part(xml, 0, pos)
        suffix = binary_part(xml, pos + len, byte_size(xml) - pos - len)
        {:ok, prefix <> signature_xml <> closing_tag <> suffix}

      :error ->
        # Fall back to self-closing root: `<root/>`. Replace it with
        # `<root>` + signature + `</root>` (and preserve the suffix).
        self_closing = "<#{root_name}/>"

        case last_match_outside(xml, self_closing, excluded) do
          {:ok, pos, len} ->
            prefix = binary_part(xml, 0, pos)
            opening_tag = "<#{root_name}>"
            suffix = binary_part(xml, pos + len, byte_size(xml) - pos - len)
            {:ok, prefix <> opening_tag <> signature_xml <> closing_tag <> suffix}

          :error ->
            {:error, {:xml, :root_tag_not_found}}
        end
    end
  end

  # Last `:binary.match/2` position of `pattern` in `xml` whose start
  # offset does NOT fall inside any of the `excluded` byte ranges.
  # Returns `{:ok, pos, len}` or `:error` if every match is excluded.
  defp last_match_outside(xml, pattern, excluded) do
    xml
    |> :binary.matches(pattern)
    |> Enum.reject(fn {pos, _len} ->
      Enum.any?(excluded, fn {start, end_} -> pos >= start and pos < end_ end)
    end)
    |> List.last()
    |> case do
      nil -> :error
      {pos, len} -> {:ok, pos, len}
    end
  end

  # Collect the byte ranges occupied by XML comments and CDATA sections.
  # Anything between `<!--` and `-->` is a comment; anything between
  # `<![CDATA[` and `]]>` is character data. The parser ignores both at
  # the structural level, so any pattern matching inside them must not
  # be treated as a real element marker.
  #
  # Comments cannot nest (XML 1.0 §2.5), so a forward sweep finding
  # non-overlapping start/end pairs is correct. CDATA likewise can't
  # nest. Mixed comments-inside-CDATA or CDATA-inside-comments are
  # parsed verbatim as part of the outer block — the outer range
  # subsumes the inner pattern.
  defp collect_excluded_ranges(xml) do
    collect_ranges(xml, "<!--", "-->", 0, []) ++
      collect_ranges(xml, "<![CDATA[", "]]>", 0, [])
  end

  defp collect_ranges(xml, start_marker, end_marker, offset, acc) do
    rest = binary_part(xml, offset, byte_size(xml) - offset)

    case :binary.match(rest, start_marker) do
      :nomatch ->
        Enum.reverse(acc)

      {start_pos, start_len} ->
        after_start_in_rest = start_pos + start_len
        body = binary_part(rest, after_start_in_rest, byte_size(rest) - after_start_in_rest)

        case :binary.match(body, end_marker) do
          :nomatch ->
            # Unterminated comment / CDATA — treat the rest of the
            # document as inside the block. Conservative; matches what
            # a real parser would do.
            abs_start = offset + start_pos
            Enum.reverse([{abs_start, byte_size(xml)} | acc])

          {end_pos_rel, end_len} ->
            abs_start = offset + start_pos
            abs_end = offset + after_start_in_rest + end_pos_rel + end_len
            collect_ranges(xml, start_marker, end_marker, abs_end, [{abs_start, abs_end} | acc])
        end
    end
  end
end
