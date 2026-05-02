defmodule Pkcs11ex.JWS do
  @moduledoc """
  JWS Detached (RFC 7797) format adapter.

  Builds and parses JWS strings of the shape `base64url(header)..base64url(signature)`
  — the empty middle segment is the detached payload marker. The protected
  header always carries `alg`, `b64: false`, `crit: ["b64"]`, and `x5c`.

  ## Sign opts (Phase 1 surface)

  Until the slot supervisor lands, the caller passes the PKCS#11 signer info
  flat alongside JWS-specific options:

      Pkcs11ex.JWS.sign(payload,
        # Signer (Layer 2 forwarded)
        module: module,
        slot_id: slot_id,
        pin: pin,
        key_label: "platform-signing-key",
        alg: :PS256,
        # JWS-specific
        x5c: leaf_der_binary,                     # or [leaf_der, intermediate_der, ...]
        extra_headers: %{"kid" => "platform-1"}   # optional
      )

  Once the slot supervisor lands the surface will reduce to
  `signer: {slot_ref, key_ref}` and `x5c` will be auto-fetched from the slot's
  configured `:cert_label`.

  ## Verify

  `verify/3` does **software-side** mathematical verification via OTP
  `:public_key`. Verification is a public-key operation — no PKCS#11 access
  needed. Trust resolution flows through `Pkcs11ex.Policy`; the signer's
  certificate from `x5c` is treated as untrusted input until the policy
  matches it against an allowlist (specs.md §7.1).
  """

  alias Pkcs11ex.{Algorithm, X509}

  @reserved_header_keys ["alg", "b64", "crit", "x5c"]

  @type jws :: binary()
  @type payload :: iodata()

  # ---------- Sign ----------

  @doc """
  Build a detached JWS over `payload` and return the wire-format string.

  See the moduledoc for the option surface in Phase 1.
  """
  @spec sign(payload(), keyword()) :: {:ok, jws()} | {:error, term()}
  def sign(payload, opts) when is_list(opts) do
    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, _adapter} <- Algorithm.lookup(alg),
         {:ok, x5c_der_list} <- fetch_x5c(opts),
         {:ok, header_b64u} <- build_protected_header(alg, x5c_der_list, opts),
         payload_bin = IO.iodata_to_binary(payload),
         signing_input = <<header_b64u::binary, ?., payload_bin::binary>>,
         signer_opts = signer_opts(opts),
         {:ok, sig_bytes} <-
           Pkcs11ex.sign_bytes(signing_input, [{:encoding_context, :jose} | signer_opts]),
         sig_b64u = Base.url_encode64(sig_bytes, padding: false),
         jws = <<header_b64u::binary, ?., ?., sig_b64u::binary>>,
         :ok <- maybe_audit(jws, payload_bin, alg, opts) do
      {:ok, jws}
    end
  end

  # ---------- Audit hook ----------

  # Off by default — only fires when `:audit_to` is set. The PIN / signer ref
  # / payload hash all flow into the entry; the JWS itself is recorded so
  # the chain is sufficient on its own (no need to retain the original
  # detached payload to reconstruct what was signed at audit time, since
  # the JWS payload hash binds it).
  defp maybe_audit(_jws, _payload_bin, _alg, opts) when not is_list(opts), do: :ok

  defp maybe_audit(jws, payload_bin, alg, opts) do
    case Keyword.get(opts, :audit_to) do
      nil ->
        :ok

      %Pkcs11ex.Audit{} = audit ->
        do_audit(audit, jws, payload_bin, alg, opts)
    end
  end

  defp do_audit(audit, jws, payload_bin, alg, opts) do
    base = %{
      kind: :jws_signed,
      jws: jws,
      alg: alg,
      signer: audit_signer_id(opts),
      payload_hash: :crypto.hash(:sha256, payload_bin),
      signed_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }

    payload =
      case Keyword.get(opts, :audit_extra) do
        extra when is_map(extra) -> Map.merge(base, extra)
        _ -> base
      end

    case Pkcs11ex.Audit.append(audit, payload) do
      {:ok, _entry} -> :ok
      {:error, reason} -> {:error, {:audit_failed, reason}}
    end
  end

  # Pick the most descriptive identity available from the sign opts:
  #   - :signer (the spec'd canonical form: atom or {slot_ref, key_ref}); else
  #   - flat {slot_id, key_label} from the legacy explicit-opts path.
  defp audit_signer_id(opts) do
    case Keyword.get(opts, :signer) do
      nil -> {Keyword.get(opts, :slot_id), Keyword.get(opts, :key_label)}
      ref -> ref
    end
  end

  # ---------- Verify ----------

  @doc """
  Verify a detached JWS over `payload`.

  Returns `{:ok, subject_id}` on success, where `subject_id` is whatever the
  configured `Pkcs11ex.Policy.validate/3` returned. Returns `{:error, reason}`
  for any of the failure modes documented in `api.md` §4.1.
  """
  @spec verify(jws(), payload(), keyword()) :: {:ok, term()} | {:error, term()}
  def verify(jws, payload, opts \\ []) when is_binary(jws) do
    with {:ok, header_b64u, sig_b64u} <- split_jws(jws),
         {:ok, header_json} <- decode_b64url(header_b64u),
         {:ok, header} <- decode_json(header_json),
         :ok <- validate_b64_crit(header),
         {:ok, alg_str} <- fetch_header_alg(header),
         alg = String.to_atom(alg_str),
         :ok <- check_alg_allowed(alg),
         {:ok, adapter} <- Algorithm.lookup(alg),
         {:ok, sig_raw} <- decode_b64url(sig_b64u),
         {:ok, sig} <- adapter.decode_signature(sig_raw, :jose),
         policy = Keyword.get(opts, :trust_policy, configured_policy()),
         {:ok, cert, chain} <- policy.resolve(header, opts),
         :ok <- validate_alg_compat(adapter, cert),
         {:ok, subject_id} <- policy.validate(cert, chain, Keyword.get(opts, :policy_opts, [])),
         payload_bin = IO.iodata_to_binary(payload),
         signing_input = <<header_b64u::binary, ?., payload_bin::binary>>,
         :ok <- verify_signature(adapter, signing_input, sig, cert) do
      {:ok, subject_id}
    end
  end

  # ---------- Internals: header construction ----------

  defp build_protected_header(alg, x5c_der_list, opts) do
    extras = Keyword.get(opts, :extra_headers, %{})

    cond do
      not is_map(extras) ->
        {:error, :invalid_extra_headers}

      Enum.any?(extras, fn {k, _} -> stringify(k) in @reserved_header_keys end) ->
        {:error, :reserved_header_overlap}

      true ->
        # x5c per RFC 7515 §4.1.6: standard base64 (no line breaks), DER bytes.
        x5c_b64 = Enum.map(x5c_der_list, &Base.encode64/1)

        header =
          extras
          |> stringify_keys()
          |> Map.merge(%{
            "alg" => Atom.to_string(alg),
            "b64" => false,
            "crit" => ["b64"],
            "x5c" => x5c_b64
          })

        json = Jason.encode!(header)
        {:ok, Base.url_encode64(json, padding: false)}
    end
  end

  defp stringify_keys(map) do
    Enum.into(map, %{}, fn {k, v} -> {stringify(k), v} end)
  end

  defp stringify(k) when is_atom(k), do: Atom.to_string(k)
  defp stringify(k) when is_binary(k), do: k

  # ---------- Internals: parsing ----------

  defp split_jws(jws) do
    case String.split(jws, ".", parts: 3) do
      [header, "", signature] when header != "" and signature != "" ->
        {:ok, header, signature}

      _ ->
        {:error, :malformed_jws}
    end
  end

  defp decode_b64url(s) do
    case Base.url_decode64(s, padding: false) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :malformed_jws}
    end
  end

  defp decode_json(bin) do
    case Jason.decode(bin) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> {:error, :malformed_jws}
    end
  end

  defp validate_b64_crit(header) do
    # RFC 7797 §6 — verifiers that don't understand `b64` MUST reject. Implementing
    # `b64: false` as the only supported mode means we *require* it to be set
    # AND included in `crit`; rejecting both alternates makes the contract clear.
    crit = Map.get(header, "crit", [])
    b64 = Map.get(header, "b64")

    cond do
      b64 != false -> {:error, :b64_crit_violation}
      not is_list(crit) -> {:error, :b64_crit_violation}
      "b64" not in crit -> {:error, :b64_crit_violation}
      true -> :ok
    end
  end

  defp fetch_header_alg(%{"alg" => alg}) when is_binary(alg), do: {:ok, alg}
  defp fetch_header_alg(_), do: {:error, :missing_required_header}

  # ---------- Internals: signature verification ----------

  defp verify_signature(Pkcs11ex.Algorithm.PS256, signing_input, signature, %X509{public_key: pk}) do
    # PS256: RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32. Software path via
    # OTP :public_key — verify is public-key math, no PKCS#11 needed.
    opts = [
      {:rsa_padding, :rsa_pkcs1_pss_padding},
      {:rsa_pss_saltlen, 32},
      {:rsa_mgf1_md, :sha256}
    ]

    if :public_key.verify(signing_input, :sha256, signature, pk, opts) do
      :ok
    else
      {:error, :signature_invalid}
    end
  rescue
    # :public_key raises on type mismatches (e.g. EC key with PSS opts)
    _ -> {:error, :signature_invalid}
  end

  defp verify_signature(adapter, _signing_input, _signature, _cert) do
    {:error, {:unsupported_alg, adapter.alg()}}
  end

  defp validate_alg_compat(adapter, %X509{public_key: pk}) do
    case classify_key(pk) do
      :rsa -> if :rsa in adapter.compatible_key_types(), do: :ok, else: {:error, :incompatible_alg}
      :ec -> if :ec in adapter.compatible_key_types(), do: :ok, else: {:error, :incompatible_alg}
      _ -> {:error, :incompatible_alg}
    end
  end

  defp classify_key({:RSAPublicKey, _, _}), do: :rsa
  defp classify_key({{:ECPoint, _}, _}), do: :ec
  defp classify_key(_), do: :unknown

  # ---------- Internals: shared with Layer 2 ----------

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

  defp signer_opts(opts) do
    # Forward every PKCS#11-related opt to Layer 2 sign_bytes; drop JWS-only ones.
    Keyword.drop(opts, [
      :x5c,
      :extra_headers,
      :trust_policy,
      :policy_opts,
      :encoding_context,
      :audit_to,
      :audit_extra
    ])
  end

  defp configured_policy do
    Application.get_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.PinnedRegistry)
  end
end
