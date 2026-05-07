defmodule SignCore.PDF do
  @moduledoc """
  PAdES (PDF Advanced Electronic Signature) format adapter — Phase 4a.

  ## Sign

      SignCore.PDF.sign(pdf_bytes,
        module: pkcs11_module,
        slot_id: slot_id,
        pin: "1234",
        key_label: "platform-signing-key",
        alg: :PS256,
        x5c: [leaf_der, intermediate_der, root_der]
      )

  Returns a binary containing the original PDF plus an incremental
  update with a `/Sig` field whose `/Contents` is the CMS SignedData
  produced by the HSM. The output validates as PAdES B-B against
  Poppler `pdfsig` and BouncyCastle `verifypdf`.

  Pipeline:

    1. `SignCore.PDF.Writer.prepare/2` allocates the incremental
       update with a fixed-width `/Contents` placeholder. Returns
       `signed_input` — the bytes the CMS will hash.
    2. SHA-256 over `signed_input` becomes the
       `messageDigest` PKCS#9 attribute. `signed_attrs` (content-type,
       message-digest, signing-time) are DER-encoded as a SET-OF.
    3. The DER-encoded `signed_attrs` is the to-be-signed input. It
       routes through `Pkcs11ex.sign_bytes/2` → Layer 2 → NIF →
       cryptoki → HSM. **Software signing is never used.**
    4. `SignCore.CMS.SignedData.build/3` assembles the ContentInfo with
       the HSM-produced raw signature, the supplied `:x5c` chain, and
       the appropriate signature-algorithm OID for the requested
       `:alg`.
    5. `SignCore.PDF.Writer.inject_signature/2` splices the CMS DER
       into the placeholder.

  ## v1 limitations

    * `:PS256` and `:RS256` only. (`:PS256` emits the canonical
      RSASSA-PSS-params for SHA-256 / MGF1-SHA-256 / sLen=32, which
      OpenSSL and BouncyCastle accept.)
    * The base PDF must not already carry an `/AcroForm`; re-signing
      a PDF with form fields is a Phase 4b enhancement.
    * Visible signature appearance streams are out of scope.
    * `verify/2` is part of step 9 in the Phase 4a punch-list and
      currently still returns `:not_implemented_in_v1`.
  """

  alias SignCore.Algorithm
  alias SignCore.CMS.{Parsed, SignedAttributes, SignedData, UnsignedAttributes}
  alias SignCore.PDF.{Reader, Writer}
  alias SignCore.X509

  @typedoc "Result of `sign/2`. Failure carries the responsible class as the wrapper."
  @type sign_result :: {:ok, binary()} | {:error, term()}

  @typedoc "Result of `verify/2`. Currently always `:not_implemented_in_v1`."
  @type verify_result :: {:ok, subject_id :: term()} | {:error, term()}

  @doc """
  Sign a PDF with PAdES B-B.

  Required options:

    * `:x5c` — the signing chain. Either a single leaf DER or a
      list `[leaf_der, intermediate_der, ..., root_der]`. The first
      element MUST correspond to the HSM key being used.
    * Plus the PKCS#11 keying opts (`:module`, `:slot_id`, `:pin`,
      `:key_label`, or the canonical `:signer` form) — these are
      forwarded verbatim to `Pkcs11ex.sign_bytes/2`.

  Optional:

    * `:alg` — `:PS256` (default) or `:RS256`.
    * `:signing_time` — `DateTime.t()` used both for the CMS
      `signing-time` attribute and the PDF `/M` entry. Defaults to
      `DateTime.utc_now/0`.
    * `:placeholder_size`, `:reason`, `:location`, `:contact_info` —
      forwarded to `SignCore.PDF.Writer.prepare/2`.

  Errors propagate from each pipeline stage; see `docs/specs/api.md`
  §4.1 for the full taxonomy.
  """
  @spec sign(binary(), keyword()) :: sign_result()
  def sign(pdf_bytes, opts) when is_binary(pdf_bytes) and is_list(opts) do
    start_meta = base_telemetry_meta(:pdf, opts)

    :telemetry.span([:pkcs11ex, :sign], start_meta, fn ->
      result = sign_inner(pdf_bytes, opts)
      stop_meta = Map.merge(start_meta, sign_stop_meta(result))
      {result, stop_meta}
    end)
  end

  defp sign_inner(pdf_bytes, opts) do
    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, _adapter} <- Algorithm.lookup(alg),
         {:ok, x5c_der_list} <- fetch_x5c(opts),
         {:ok, prepared} <- Writer.prepare(pdf_bytes, writer_opts(opts)),
         {:ok, cms_der} <- build_cms(prepared, x5c_der_list, alg, opts) do
      Writer.inject_signature(prepared, cms_der)
    end
  end

  @doc """
  Verify a PAdES-signed PDF.

  Returns `{:ok, subject_id}` where `subject_id` is whatever the
  configured `SignCore.Policy.validate/3` returned. The verify
  pipeline runs in this order — every step is a checkpoint that can
  refuse the signature with the documented error class:

    1. Locate the (single) `/Sig` dict in the file: extract
       `/ByteRange [a b c d]` and `/Contents <hex>`. v1 refuses PDFs
       carrying more than one `/Sig` (multi-signature is post-v1).
    2. **Append-attack detection.** Refuse if `c + d` does not equal
       the file's total byte length — bytes beyond the signed range
       can carry an attacker-crafted incremental update that the
       original signature cannot cover by definition. Surfaces as
       `:incremental_update_after_signature`.
    3. Strip the trailing zero-padding from the hex-decoded
       `/Contents` blob using the CMS SEQUENCE length prefix; parse
       the result via `SignCore.CMS.SignedData.parse/1`.
    4. **Allowlist gate (architectural invariant).** Synthesise a
       JOSE-style header from the embedded `x5c` chain and run it
       through the configured `SignCore.Policy` —
       `policy.resolve/2` then `policy.validate/3`. The candidate
       chain is **untrusted input** until both succeed. No
       cryptographic check has happened yet.
    5. Reconstruct `signed_input` = `pdf[a..a+b) ++ pdf[c..c+d)`,
       hash with SHA-256, compare against the CMS `messageDigest`
       PKCS#9 attribute. A mismatch surfaces as
       `:message_digest_mismatch` and is the canonical
       tampered-byte signal — any modification inside the signed
       byte range invalidates the digest before the math runs.
    6. Mathematically verify the embedded raw signature over the
       DER-encoded `signedAttrs` against the leaf's SPKI. Failure is
       `:signature_invalid`.

  Failures from step 4 short-circuit before any signature math, so
  callers cannot use `verify/2` as a CPU-bound oracle on attacker-
  supplied certificates. Failures from step 2 short-circuit even
  earlier, so an append-attack PDF is refused before any CMS work.
  """
  @spec verify(binary(), keyword()) :: verify_result()
  def verify(pdf_bytes, opts \\ [])

  def verify(pdf_bytes, opts) when is_binary(pdf_bytes) and is_list(opts) do
    start_meta = base_telemetry_meta(:pdf, opts)

    :telemetry.span([:pkcs11ex, :verify], start_meta, fn ->
      result = verify_inner(pdf_bytes, opts)
      stop_meta = Map.merge(start_meta, verify_stop_meta(result, byte_size(pdf_bytes)))
      {result, stop_meta}
    end)
  end

  defp verify_inner(pdf_bytes, opts) do
    with {:ok, byte_range, cms_der} <- locate_signature(pdf_bytes),
         :ok <- check_no_unsigned_trailing_bytes(pdf_bytes, byte_range),
         {:ok, parsed} <- SignedData.parse(cms_der),
         {:ok, header} <- header_from_chain(parsed.certificates),
         policy = Keyword.get(opts, :trust_policy, configured_policy()),
         {:ok, cert, chain} <- policy.resolve(header, opts),
         {:ok, subject_id} <-
           policy.validate(cert, chain, Keyword.get(opts, :policy_opts, [])),
         :ok <- check_signing_time_in_validity(parsed, cert, opts),
         :ok <- check_message_digest(pdf_bytes, byte_range, parsed.message_digest),
         :ok <- verify_signature_math(parsed, cert) do
      {:ok, subject_id}
    end
  end

  # CMS `signing-time` (PKCS#9) is the time recorded by the signer.
  # PAdES verifiers cross-check it against the leaf cert's validity
  # window — a signing-time outside that window means the cert
  # claimed to be unexpired-at-signing was actually expired (or
  # not-yet-valid). Standards-compliant PAdES B-B requires this; we
  # ran without it pre-fix and accepted such signatures silently.
  #
  # Opt-out via `verify(..., check_signing_time: false)` for legacy
  # interop. Default-on. When the CMS carries no `signing-time`
  # attribute (rare; some signers omit it), we skip the check —
  # there's nothing to compare against. Operators who want to
  # *require* the attribute can pass `require_signing_time: true`.
  defp check_signing_time_in_validity(parsed, cert, opts) do
    case Keyword.get(opts, :check_signing_time, true) do
      false ->
        :ok

      _ ->
        case parsed.signing_time do
          %DateTime{} = signing_time ->
            X509.check_validity(cert, signing_time)

          nil ->
            if Keyword.get(opts, :require_signing_time, false) do
              {:error, :missing_signing_time}
            else
              :ok
            end
        end
    end
  end

  # ---------- internals ----------

  defp build_cms(%Writer{signed_input: signed_input}, x5c_der_list, alg, opts) do
    digest = :crypto.hash(:sha256, signed_input)
    signing_time = Keyword.get(opts, :signing_time, DateTime.utc_now())

    with {:ok, signed_attrs} <-
           SignedAttributes.build(digest: digest, signing_time: signing_time),
         {:ok, tbs} <- SignedAttributes.to_be_signed(signed_attrs),
         {:ok, signer} <- fetch_signer(opts),
         signer_opts = signer_opts(opts, alg),
         {:ok, raw_signature} <-
           SignCore.Signer.sign(signer, tbs, [{:encoding_context, :der} | signer_opts]),
         {:ok, unsigned_attrs} <- maybe_fetch_signature_timestamp(raw_signature, opts),
         {:ok, cms_der} <-
           SignedData.build(signed_attrs, raw_signature,
             certificates: x5c_der_list,
             signature_algorithm: cms_signature_algorithm(alg),
             unsigned_attrs: unsigned_attrs
           ) do
      {:ok, cms_der}
    end
  end

  defp fetch_signer(opts) do
    case Keyword.fetch(opts, :signer) do
      {:ok, signer} -> {:ok, signer}
      :error -> {:error, :missing_signer}
    end
  end

  # PAdES B-T: when `:tsa_url` is supplied, request an RFC 3161
  # TimeStampToken over SHA-256 of the *raw signature bytes* (the
  # SignerInfo's `signature` field, per RFC 3161 §3.3.4) and embed
  # it as the `id-aa-signatureTimeStampToken` unsigned attribute.
  # The timestamp is *not* covered by the signature math — it
  # anchors the moment the signature existed against a third-party
  # clock.
  defp maybe_fetch_signature_timestamp(raw_signature, opts) do
    case Keyword.get(opts, :tsa_url) do
      nil ->
        {:ok, :asn1_NOVALUE}

      tsa_url ->
        if Code.ensure_loaded?(Pkcs11ex.Audit.Anchor.RFC3161) do
          do_fetch_signature_timestamp(raw_signature, tsa_url, opts)
        else
          {:error, {:bt_failed, :pkcs11ex_audit_not_loaded}}
        end
    end
  end

  @compile {:no_warn_undefined, [Pkcs11ex.Audit.Anchor.RFC3161]}

  defp do_fetch_signature_timestamp(raw_signature, tsa_url, opts) do
    timeout = Keyword.get(opts, :tsa_timeout, 10_000)
    digest = :crypto.hash(:sha256, raw_signature)
    rfc3161 = Pkcs11ex.Audit.Anchor.RFC3161

    with {:ok, %{der: req_der}} <- apply(rfc3161, :build_request, [digest]),
         {:ok, body} <- apply(rfc3161, :fetch_token, [tsa_url, req_der, [timeout: timeout]]),
         {:ok, tst} <- apply(rfc3161, :extract_token, [body]) do
      {:ok, [UnsignedAttributes.signature_timestamp(tst)]}
    else
      {:error, reason} -> {:error, {:bt_failed, reason}}
    end
  end

  # `:alg` is required across all format adapters (`SignCore.JWS`,
  # `SignCore.XML`, `Pkcs11ex.sign_bytes/2` all reject missing). PDF
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

  defp writer_opts(opts) do
    Keyword.take(opts, [:placeholder_size, :reason, :location, :contact_info, :signing_time])
  end

  # PDF-only opts are dropped; everything else flows to Layer 2 sign_bytes.
  # `:alg` is re-supplied here because sign_bytes needs it but the caller
  # already passed it via the same opts list.
  defp signer_opts(opts, alg) do
    cleaned =
      Keyword.drop(opts, [
        :x5c,
        :placeholder_size,
        :reason,
        :location,
        :contact_info,
        :signing_time,
        :encoding_context,
        :tsa_url,
        :tsa_timeout
      ])

    Keyword.put(cleaned, :alg, alg)
  end

  defp cms_signature_algorithm(:PS256), do: :rsa_pss_sha256
  defp cms_signature_algorithm(:RS256), do: :rsa_sha256

  # ---------- verify-side helpers ----------

  # Locates the (single) PAdES signature in `pdf` by walking the merged
  # xref via `SignCore.PDF.Reader`, finding indirect objects whose dict
  # carries `/Type /Sig`, and parsing `/ByteRange` and `/Contents` from
  # within that bounded dict body. Whitespace-tolerant regexes are safe
  # here because the dict body is already isolated — content streams,
  # comments, and superseded older revisions can't pollute the matches.
  #
  # No-Sig-objects → `:no_signature`. More than one → the v1 rejection
  # `:multiple_signatures_unsupported_in_v1`. PDFs whose xref couldn't
  # be parsed (xref-stream-only PDFs, malformed trailers) surface as
  # `{:malformed_pdf, _}` from the Reader.
  defp locate_signature(pdf) do
    case Reader.signature_dicts(pdf) do
      {:ok, []} ->
        {:error, :no_signature}

      {:ok, [_, _ | _]} ->
        {:error, :multiple_signatures_unsupported_in_v1}

      {:ok, [{_num, dict_body}]} ->
        parse_signature_dict(dict_body)

      {:error, {:malformed_pdf, _} = err} ->
        # An unsigned PDF with no /Sig anywhere is the canonical "no
        # signature" case. The reader can also fail upstream of that
        # (no xref, no startxref) — for the verify surface we still
        # report `:no_signature`, since the operator's primary
        # question is "did this verify?" and a syntactically invalid
        # PDF answers no.
        case err do
          {:malformed_pdf, :startxref_not_found} -> {:error, :no_signature}
          _ -> {:error, err}
        end
    end
  end

  defp parse_signature_dict(dict_body) do
    with {:ok, byte_range} <- parse_byte_range(dict_body),
         {:ok, hex} <- parse_contents(dict_body),
         {:ok, padded} <- decode_contents_hex(hex),
         {:ok, cms_der} <- strip_trailing_zero_padding(padded) do
      {:ok, byte_range, cms_der}
    end
  end

  defp parse_byte_range(dict_body) do
    case Regex.run(
           ~r/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/,
           dict_body,
           capture: :all_but_first
         ) do
      [a, b, c, d] ->
        {:ok, Enum.map([a, b, c, d], &String.to_integer/1)}

      _ ->
        {:error, :malformed_signature_contents}
    end
  end

  defp parse_contents(dict_body) do
    # /Contents is a hex string per PAdES B-B (the SubFilter
    # /adbe.pkcs7.detached requires it). Whitespace inside the hex
    # is permitted by PDF (§7.3.4.3) but our Writer never emits any;
    # we still strip whitespace from inside the brackets to tolerate
    # third-party PDFs that include line breaks.
    case Regex.run(~r/\/Contents\s*<([\s0-9A-Fa-f]+)>/, dict_body, capture: :all_but_first) do
      [hex_with_ws] ->
        {:ok, String.replace(hex_with_ws, ~r/\s+/, "")}

      _ ->
        {:error, :malformed_signature_contents}
    end
  end

  defp decode_contents_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :malformed_signature_contents}
    end
  end

  # CMS DER is left-aligned in the placeholder; trailing bytes are
  # `0x00` filler. The SEQUENCE length prefix tells us where the DER
  # actually ends. Malformed length bytes are surfaced as
  # `:malformed_signature_contents` rather than passing the padded
  # blob through to the parser, which would surface a confusing
  # downstream error class.
  defp strip_trailing_zero_padding(<<0x30, rest::binary>> = full) do
    case der_length(rest) do
      {:ok, len, len_octets} ->
        total = 1 + len_octets + len
        {:ok, binary_part(full, 0, min(total, byte_size(full)))}

      :error ->
        {:error, :malformed_signature_contents}
    end
  end

  defp strip_trailing_zero_padding(_other), do: {:error, :malformed_signature_contents}

  defp der_length(<<0::1, len::7, _rest::binary>>), do: {:ok, len, 1}

  defp der_length(<<1::1, n::7, rest::binary>>) when n > 0 and n <= 4 do
    case rest do
      <<bytes::binary-size(n), _::binary>> ->
        len = :binary.decode_unsigned(bytes, :big)
        {:ok, len, 1 + n}

      _ ->
        :error
    end
  end

  defp der_length(_), do: :error

  defp header_from_chain([]), do: {:error, :missing_x5c}

  defp header_from_chain(certs) when is_list(certs) do
    {:ok,
     %{
       "x5c" => Enum.map(certs, fn %X509{der: der} -> Base.encode64(der) end)
     }}
  end

  # PAdES /ByteRange must cover everything except the hex placeholder.
  # If `c + d < byte_size(pdf)`, additional bytes were appended after
  # the signed revision — the canonical "incremental update after
  # signature" attack. We refuse before anything else looks at the
  # CMS payload, since the appended bytes can carry an attacker-
  # crafted incremental update that the original signature cannot
  # cover by definition.
  defp check_no_unsigned_trailing_bytes(pdf, [_a, _b, c, d]) do
    if c + d == byte_size(pdf) do
      :ok
    else
      {:error, :incremental_update_after_signature}
    end
  end

  defp check_message_digest(_pdf, _byte_range, nil),
    do: {:error, {:missing_attribute, :message_digest}}

  defp check_message_digest(pdf, [a, b, c, d], expected) when is_binary(expected) do
    if a + b > byte_size(pdf) or c + d > byte_size(pdf) do
      {:error, :byte_range_out_of_bounds}
    else
      actual = :crypto.hash(:sha256, binary_part(pdf, a, b) <> binary_part(pdf, c, d))

      if actual == expected do
        :ok
      else
        {:error, :message_digest_mismatch}
      end
    end
  end

  defp verify_signature_math(
         %Parsed{signature_algorithm: :rsa_pss_sha256} = parsed,
         %X509{public_key: pk}
       ) do
    if :public_key.verify(parsed.to_be_signed, :sha256, parsed.signature, pk,
         rsa_padding: :rsa_pkcs1_pss_padding,
         rsa_pss_saltlen: 32,
         rsa_mgf1_md: :sha256
       ) do
      :ok
    else
      {:error, :signature_invalid}
    end
  end

  defp verify_signature_math(
         %Parsed{signature_algorithm: :rsa_sha256} = parsed,
         %X509{public_key: pk}
       ) do
    if :public_key.verify(parsed.to_be_signed, :sha256, parsed.signature, pk) do
      :ok
    else
      {:error, :signature_invalid}
    end
  end

  defp verify_signature_math(%Parsed{signature_algorithm: alg}, _cert),
    do: {:error, {:unsupported_signature_algorithm, alg}}

  defp configured_policy do
    Application.get_env(:pkcs11ex, :trust_policy, SignCore.Policy.PinnedRegistry)
  end

  # ---------- telemetry helpers ----------

  # Common metadata shape, populated at span start and re-merged at
  # stop. Keeps `:slot_ref`, `:key_ref`, `:alg`, `:format`, and
  # `:encoding_context` in line with the contract documented in
  # `docs/specs/api.md` §4.2.
  defp base_telemetry_meta(format, opts) do
    %{
      format: format,
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

  defp sign_stop_meta({:ok, signed_pdf}) when is_binary(signed_pdf),
    do: %{byte_count: byte_size(signed_pdf)}

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

  # Map an error tuple onto the error_class taxonomy in api.md §4.1.
  # The class atom is the one named in the table's "Class" column —
  # callers pivot dashboards on it.
  defp error_class({:malformed_pdf, _}), do: :pdf
  defp error_class({:writer, _}), do: :pdf
  defp error_class({:bt_failed, _}), do: :pdf
  defp error_class({:cms_codec, _, _}), do: :cms
  defp error_class({:not_signed_data, _}), do: :cms
  defp error_class({:multi_value_attribute, _}), do: :cms
  defp error_class({:missing_attribute, _}), do: :cms
  defp error_class({:unsupported_signature_algorithm, _}), do: :cms
  defp error_class({:unsupported_digest_algorithm, _}), do: :cms

  defp error_class(reason)
       when reason in [
              :no_signature,
              :multiple_signatures_unsupported_in_v1,
              :malformed_signature_contents,
              :byte_range_out_of_bounds,
              :message_digest_mismatch,
              :incremental_update_after_signature
            ],
       do: :pdf

  # `:input` covers cross-format input-validation reasons that aren't
  # specific to PDF/XML/JWS. Previously misattributed to `:jws` because
  # the atoms (`:missing_x5c`, etc.) originated in the JWS module —
  # but for a PDF, a missing cert chain is a CMS / input concern, not
  # a JWS concern.
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

  defp error_class(:signature_invalid), do: :crypto
  defp error_class(_), do: :unknown
end
