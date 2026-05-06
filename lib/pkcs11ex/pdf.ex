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
  alias Pkcs11ex.CMS.{SignedAttributes, SignedData}
  alias Pkcs11ex.PDF.Writer

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
  Verify a PAdES-signed PDF. Implementation lands in Phase 4a step 9.
  """
  @spec verify(iodata(), keyword()) :: verify_result()
  def verify(_signed_pdf, _opts \\ []), do: {:error, :not_implemented_in_v1}

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
end
