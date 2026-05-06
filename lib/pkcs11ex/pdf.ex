defmodule Pkcs11ex.PDF do
  @moduledoc """
  PAdES (PDF Advanced Electronic Signature) format adapter — Phase 4a.

  ## Sign

      Pkcs11ex.PDF.sign(pdf_bytes,
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

    1. `Pkcs11ex.PDF.Writer.prepare/2` allocates the incremental
       update with a fixed-width `/Contents` placeholder. Returns
       `signed_input` — the bytes the CMS will hash.
    2. SHA-256 over `signed_input` becomes the
       `messageDigest` PKCS#9 attribute. `signed_attrs` (content-type,
       message-digest, signing-time) are DER-encoded as a SET-OF.
    3. The DER-encoded `signed_attrs` is the to-be-signed input. It
       routes through `Pkcs11ex.sign_bytes/2` → Layer 2 → NIF →
       cryptoki → HSM. **Software signing is never used.**
    4. `Pkcs11ex.CMS.SignedData.build/3` assembles the ContentInfo with
       the HSM-produced raw signature, the supplied `:x5c` chain, and
       the appropriate signature-algorithm OID for the requested
       `:alg`.
    5. `Pkcs11ex.PDF.Writer.inject_signature/2` splices the CMS DER
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

  alias Pkcs11ex.Algorithm
  alias Pkcs11ex.CMS.{Parsed, SignedAttributes, SignedData}
  alias Pkcs11ex.PDF.Writer
  alias Pkcs11ex.X509

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
      forwarded to `Pkcs11ex.PDF.Writer.prepare/2`.

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
  configured `Pkcs11ex.Policy.validate/3` returned. The verify
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
       the result via `Pkcs11ex.CMS.SignedData.parse/1`.
    4. **Allowlist gate (architectural invariant).** Synthesise a
       JOSE-style header from the embedded `x5c` chain and run it
       through the configured `Pkcs11ex.Policy` —
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
         :ok <- check_message_digest(pdf_bytes, byte_range, parsed.message_digest),
         :ok <- verify_signature_math(parsed, cert) do
      {:ok, subject_id}
    end
  end

  # ---------- internals ----------

  defp build_cms(%Writer{signed_input: signed_input}, x5c_der_list, alg, opts) do
    digest = :crypto.hash(:sha256, signed_input)
    signing_time = Keyword.get(opts, :signing_time, DateTime.utc_now())

    with {:ok, signed_attrs} <-
           SignedAttributes.build(digest: digest, signing_time: signing_time),
         {:ok, tbs} <- SignedAttributes.to_be_signed(signed_attrs),
         signer_opts = signer_opts(opts, alg),
         {:ok, raw_signature} <-
           Pkcs11ex.sign_bytes(tbs, [{:encoding_context, :der} | signer_opts]),
         {:ok, cms_der} <-
           SignedData.build(signed_attrs, raw_signature,
             certificates: x5c_der_list,
             signature_algorithm: cms_signature_algorithm(alg)
           ) do
      {:ok, cms_der}
    end
  end

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
        :encoding_context
      ])

    Keyword.put(cleaned, :alg, alg)
  end

  defp cms_signature_algorithm(:PS256), do: :rsa_pss_sha256
  defp cms_signature_algorithm(:RS256), do: :rsa_sha256

  # ---------- verify-side helpers ----------

  defp locate_signature(pdf) do
    byte_ranges =
      Regex.scan(~r/\/ByteRange \[(\d+) (\d+) (\d+) (\d+)\]/, pdf, capture: :all_but_first)

    contents = Regex.scan(~r/\/Contents <([0-9A-Fa-f]+)>/, pdf, capture: :all_but_first)

    cond do
      byte_ranges == [] or contents == [] ->
        {:error, :no_signature}

      length(byte_ranges) > 1 or length(contents) > 1 ->
        {:error, :multiple_signatures_unsupported_in_v1}

      true ->
        [[a_str, b_str, c_str, d_str]] = byte_ranges
        [[hex]] = contents
        byte_range = Enum.map([a_str, b_str, c_str, d_str], &String.to_integer/1)

        case Base.decode16(hex, case: :mixed) do
          {:ok, padded} ->
            cms_der = strip_trailing_zero_padding(padded)
            {:ok, byte_range, cms_der}

          :error ->
            {:error, :malformed_signature_contents}
        end
    end
  end

  # CMS DER is left-aligned in the placeholder; trailing bytes are
  # `0x00` filler. The SEQUENCE length prefix tells us where the DER
  # actually ends.
  defp strip_trailing_zero_padding(<<0x30, rest::binary>> = full) do
    case der_length(rest) do
      {:ok, len, len_octets} ->
        total = 1 + len_octets + len
        binary_part(full, 0, min(total, byte_size(full)))

      :error ->
        full
    end
  end

  defp strip_trailing_zero_padding(other), do: other

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
    Application.get_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.PinnedRegistry)
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
      {slot_ref, _key_ref} -> slot_ref
      atom when is_atom(atom) and not is_nil(atom) -> atom
      _ -> Keyword.get(opts, :slot_ref) || Keyword.get(opts, :slot_id)
    end
  end

  defp opts_key_ref(opts) do
    case Keyword.get(opts, :signer) do
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

  defp error_class(reason) when reason in [:missing_x5c, :invalid_x5c, :disallowed_alg], do: :jws

  defp error_class(reason)
       when reason in [
              :unknown_signer,
              :hint_mismatch,
              :untrusted_signer,
              :cert_expired,
              :cert_not_yet_valid,
              :chain_invalid,
              :incomplete_chain
            ],
       do: :trust_policy

  defp error_class(:signature_invalid), do: :crypto
  defp error_class(_), do: :unknown
end
