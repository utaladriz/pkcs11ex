defmodule SignCore.JWS do
  @moduledoc """
  JWS format adapter — detached (RFC 7797) by default, attached
  (RFC 7515) opt-in.

  ## Wire formats

      <header_b64u>..<sig_b64u>            # detached (default, RFC 7797)
      <header_b64u>.<payload_b64u>.<sig>   # attached (opt-in, RFC 7515)

  Detached form sets `b64: false` + `crit: ["b64"]` in the
  protected header and uses the raw payload bytes (not base64url'd)
  in the signing input. Attached form follows standard RFC 7515
  framing — payload is base64url-encoded into the middle segment.

  ## Sign

      SignCore.JWS.sign(payload,
        signer: %SomeSigner{...},          # any SignCore.Signer impl
        alg: :PS256,
        x5c: leaf_der_binary,              # or [leaf_der, intermediate_der, ...]
        attached: false,                   # default — detached
        extra_headers: %{"kid" => "platform-1"}   # optional
      )

  ### Optional `:x5c` with `:kid`

  When `:extra_headers` carries a `kid`, `:x5c` becomes optional —
  the verifier will look up the cert by `kid` (via `:kid_certs` opt
  on `verify/3` or a kid-aware policy). RFC 7515 §4.1.4.

  ## Verify

      SignCore.JWS.verify(jws, payload, opts \\\\ [])

  Auto-detects detached vs attached from the wire format. For
  detached, `payload` is required. For attached, `payload` may be
  `nil` (extracted from the middle segment) or supplied (cross-
  checked against the embedded payload — `:payload_mismatch` if
  they differ).

  Verification is **software-side** via OTP `:public_key`. No
  PKCS#11 access needed. Trust resolution flows through
  `SignCore.Policy` (see `:trust_policy` opt) or via `:kid_certs`
  for kid-only flows. The signer's certificate from `x5c` is
  treated as untrusted input until the policy or kid lookup
  resolves it (specs.md §7.1).
  """

  alias SignCore.{Algorithm, X509}

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
    attached = Keyword.get(opts, :attached, false)

    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, _adapter} <- Algorithm.lookup(alg),
         {:ok, x5c_der_list} <- fetch_x5c(opts),
         {:ok, header_b64u} <- build_protected_header(alg, x5c_der_list, attached, opts),
         payload_bin = IO.iodata_to_binary(payload),
         {payload_segment, signing_input} = build_payload_segments(payload_bin, header_b64u, attached),
         {:ok, signer} <- fetch_signer(opts),
         signer_opts = signer_opts(opts),
         {:ok, sig_bytes} <-
           SignCore.Signer.sign(signer, signing_input, [
             {:encoding_context, :jose},
             {:alg, alg} | signer_opts
           ]),
         sig_b64u = Base.url_encode64(sig_bytes, padding: false),
         jws = <<header_b64u::binary, ?., payload_segment::binary, ?., sig_b64u::binary>>,
         :ok <- maybe_audit(jws, payload_bin, alg, opts) do
      {:ok, jws}
    end
  end

  # RFC 7797 §3 — detached: `b64: false`, signing input includes the raw
  # payload bytes, wire-format middle segment is empty.
  # RFC 7515 — attached: middle segment is `base64url(payload)`, signing
  # input is `<header_b64>.<payload_b64>`.
  defp build_payload_segments(payload_bin, header_b64u, _attached = true) do
    payload_b64 = Base.url_encode64(payload_bin, padding: false)
    {payload_b64, <<header_b64u::binary, ?., payload_b64::binary>>}
  end

  defp build_payload_segments(payload_bin, header_b64u, _attached = false) do
    {"", <<header_b64u::binary, ?., payload_bin::binary>>}
  end

  # ---------- Audit hook ----------

  # `pkcs11ex_audit` is an optional dep. When the lib isn't loaded — the app
  # didn't pull it in or this is a verify-only deployment — the `Pkcs11ex.Audit`
  # module won't exist at all. We dispatch via `apply/3` (no compile-time
  # symbol reference) and gate on `Code.ensure_loaded?/1` so:
  #
  #   - `:audit_to` absent           → skip silently, return :ok.
  #   - `:audit_to` set, lib missing → return :pkcs11ex_audit_not_loaded so
  #                                    the caller knows the JWS was produced
  #                                    but not recorded.
  #   - `:audit_to` set, lib loaded  → call `Pkcs11ex.Audit.append/3`.
  #
  # The `@compile {:no_warn_undefined, ...}` suppresses the inevitable
  # "module not loaded" warning that the Elixir compiler would otherwise
  # emit during compile of a pkcs11ex consumer that doesn't include
  # pkcs11ex_audit.

  @compile {:no_warn_undefined, [Pkcs11ex.Audit]}

  defp maybe_audit(_jws, _payload_bin, _alg, opts) when not is_list(opts), do: :ok

  defp maybe_audit(jws, payload_bin, alg, opts) do
    case Keyword.get(opts, :audit_to) do
      nil ->
        :ok

      audit ->
        if Code.ensure_loaded?(Pkcs11ex.Audit) do
          do_audit(audit, jws, payload_bin, alg, opts)
        else
          {:error, {:audit_failed, :pkcs11ex_audit_not_loaded}}
        end
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

    case apply(Pkcs11ex.Audit, :append, [audit, payload]) do
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
      %{slot_ref: ref, key_ref: kref} when not is_nil(ref) -> {ref, kref}
      ref -> ref
    end
  end

  # ---------- Verify ----------

  @doc """
  Verify a JWS, detached or attached.

  Auto-detects from the wire format:

    * **Detached** (RFC 7797 — `<header>..<sig>`): the empty middle
      segment marks the payload as supplied externally. The
      `payload` argument is required.
    * **Attached** (RFC 7515 — `<header>.<payload>.<sig>`): the
      payload is encoded in the middle segment. The `payload`
      argument is optional; if supplied, it is cross-checked
      against the embedded payload (`:payload_mismatch` if they
      differ).

  Returns `{:ok, subject_id}` on success.

  ## Identity resolution

  By default, the embedded `x5c` chain is routed through the
  configured `SignCore.Policy` (`resolve/2` then `validate/3`).
  For kid-only JWS (no `x5c` in the header), supply `:kid_certs`
  as a `%{kid_string => leaf_der}` map to look up the leaf cert
  by `kid` directly:

      SignCore.JWS.verify(jws, payload, kid_certs: %{"acme-2025" => leaf_der})

  When `:kid_certs` resolves a cert, `policy.resolve/2` is
  bypassed but `policy.validate/3` still runs to derive the
  `subject_id`.
  """
  @spec verify(jws(), payload() | nil, keyword()) :: {:ok, term()} | {:error, term()}
  def verify(jws, payload \\ nil, opts \\ [])

  def verify(jws, payload, opts) when is_binary(jws) and is_list(opts) do
    with {:ok, header_b64u, payload_segment, sig_b64u} <- split_jws(jws),
         {:ok, header_json} <- decode_b64url(header_b64u),
         {:ok, header} <- decode_json(header_json),
         {:ok, mode} <- detect_mode(payload_segment),
         :ok <- validate_b64_crit_for_mode(header, mode),
         {:ok, payload_bin} <- resolve_payload(mode, payload, payload_segment),
         {:ok, alg_str} <- fetch_header_alg(header),
         alg = String.to_atom(alg_str),
         :ok <- check_alg_allowed(alg),
         {:ok, adapter} <- Algorithm.lookup(alg),
         {:ok, sig_raw} <- decode_b64url(sig_b64u),
         {:ok, sig} <- adapter.decode_signature(sig_raw, :jose),
         {:ok, cert, chain} <- resolve_signer(header, opts),
         :ok <- validate_alg_compat(adapter, cert),
         {:ok, subject_id} <-
           configured_policy_for(opts).validate(
             cert,
             chain,
             Keyword.get(opts, :policy_opts, [])
           ),
         signing_input = build_signing_input(mode, header_b64u, payload_bin, payload_segment),
         :ok <- verify_signature(adapter, signing_input, sig, cert) do
      {:ok, subject_id}
    end
  end

  defp detect_mode(""), do: {:ok, :detached}
  defp detect_mode(_payload_segment), do: {:ok, :attached}

  # Detached form — the middle segment is empty; use the external `payload` arg.
  defp resolve_payload(:detached, nil, _segment), do: {:error, :missing_payload}

  defp resolve_payload(:detached, payload, _segment),
    do: {:ok, IO.iodata_to_binary(payload)}

  # Attached form — extract from middle segment. If caller passed an
  # external payload, cross-check; flag mismatches.
  defp resolve_payload(:attached, nil, segment), do: decode_b64url(segment)

  defp resolve_payload(:attached, payload, segment) do
    with {:ok, embedded} <- decode_b64url(segment) do
      external = IO.iodata_to_binary(payload)
      if embedded == external, do: {:ok, embedded}, else: {:error, :payload_mismatch}
    end
  end

  defp build_signing_input(:detached, header_b64u, payload_bin, _segment),
    do: <<header_b64u::binary, ?., payload_bin::binary>>

  defp build_signing_input(:attached, header_b64u, _payload_bin, segment),
    do: <<header_b64u::binary, ?., segment::binary>>

  # b64/crit are RFC 7797 detached markers — only required (and only
  # validated) when the JWS is detached. Attached JWS uses standard
  # RFC 7515 framing, no b64 field.
  defp validate_b64_crit_for_mode(header, :detached), do: validate_b64_crit(header)
  defp validate_b64_crit_for_mode(_header, :attached), do: :ok

  # Identity resolution: kid-based lookup if `:kid_certs` is supplied
  # AND the header carries a `kid` that matches; otherwise fall through
  # to the configured policy.
  defp resolve_signer(header, opts) do
    case kid_lookup(header, opts) do
      {:ok, leaf_der} ->
        with {:ok, cert} <- SignCore.X509.from_der(leaf_der) do
          {:ok, cert, []}
        end

      :no_kid_match ->
        policy = configured_policy_for(opts)
        policy.resolve(header, opts)
    end
  end

  defp kid_lookup(header, opts) do
    with %{} = kid_certs <- Keyword.get(opts, :kid_certs),
         kid when is_binary(kid) <- Map.get(header, "kid"),
         leaf_der when is_binary(leaf_der) <- Map.get(kid_certs, kid) do
      {:ok, leaf_der}
    else
      _ -> :no_kid_match
    end
  end

  defp configured_policy_for(opts),
    do: Keyword.get(opts, :trust_policy, configured_policy())

  # ---------- Internals: header construction ----------

  defp build_protected_header(alg, x5c_der_list, attached, opts) do
    extras = Keyword.get(opts, :extra_headers, %{})

    cond do
      not is_map(extras) ->
        {:error, :invalid_extra_headers}

      Enum.any?(extras, fn {k, _} -> stringify(k) in @reserved_header_keys end) ->
        {:error, :reserved_header_overlap}

      true ->
        base = %{"alg" => Atom.to_string(alg)}

        # RFC 7797 detached markers — attached form drops them.
        base = if attached, do: base, else: Map.merge(base, %{"b64" => false, "crit" => ["b64"]})

        # x5c per RFC 7515 §4.1.6: base64 (no line breaks), DER bytes.
        # Omit the field when caller is using kid-only identification
        # (x5c_der_list is empty in that case).
        base =
          case x5c_der_list do
            [] -> base
            ders -> Map.put(base, "x5c", Enum.map(ders, &Base.encode64/1))
          end

        header = extras |> stringify_keys() |> Map.merge(base)
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
      [header, payload, signature] when header != "" and signature != "" ->
        # `payload` is "" for detached, base64url for attached.
        {:ok, header, payload, signature}

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

  defp verify_signature(SignCore.Algorithm.PS256, signing_input, signature, %X509{public_key: pk}) do
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
      :rsa ->
        if :rsa in adapter.compatible_key_types(), do: :ok, else: {:error, :incompatible_alg}

      :ec ->
        if :ec in adapter.compatible_key_types(), do: :ok, else: {:error, :incompatible_alg}

      _ ->
        {:error, :incompatible_alg}
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

      :error ->
        # x5c is optional when the caller supplies a `kid` in
        # `:extra_headers` — verifiers look up the cert by `kid`
        # via their policy or `:kid_certs` opt instead. RFC 7515 §4.1.4.
        case extra_headers_kid(opts) do
          nil -> {:error, :missing_x5c}
          _kid -> {:ok, []}
        end
    end
  end

  defp extra_headers_kid(opts) do
    case Keyword.get(opts, :extra_headers) do
      %{} = h ->
        Enum.find_value(h, fn
          {k, v} when is_binary(v) -> if stringify(k) == "kid", do: v, else: nil
          _ -> nil
        end)

      _ ->
        nil
    end
  end

  defp fetch_signer(opts) do
    case Keyword.fetch(opts, :signer) do
      {:ok, signer} -> {:ok, signer}
      :error -> {:error, :missing_signer}
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
    Application.get_env(:pkcs11ex, :trust_policy, SignCore.Policy.PinnedRegistry)
  end
end
