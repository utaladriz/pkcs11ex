defmodule Pkcs11ex do
  @moduledoc """
  Hardware-backed digital signatures for Elixir, via PKCS#11.

  This module hosts the **Layer 2** signing primitives — format-agnostic
  `sign_bytes`, `verify_bytes`, `digest`, and `digest_stream`. Format adapters
  (`SignCore.JWS`, `SignCore.PDF`, `SignCore.XML`) build on top.

  See `docs/specs/specs.md` for architecture and `docs/specs/api.md` for the
  full public API specification.

  ## Surface

  Two paths into a sign:

    * **Signer-ref (`:signer`, recommended)** — `signer: {slot_ref, key_ref}`
      resolves through the running `Pkcs11ex.Slot.Server` for that slot,
      which holds the persistent session, applies the configured
      `pin_callback`, and routes through the single-session-pinned model
      from `specs.md` §5.2. Atom shorthand: `signer: :key_ref` resolves
      against `default_slot` from `Pkcs11ex.Application.config/0`.

    * **Explicit (legacy / one-shot)** — pass `module:`, `slot_id:`,
      `key_label:`, and (for token slots) `pin:` directly. Opens a fresh
      session per call. Useful for scripts and tests; production should
      prefer `:signer`.
  """

  alias SignCore.Algorithm
  alias Pkcs11ex.Native

  @type sign_opts :: [
          module: Native.module_resource(),
          slot_id: non_neg_integer(),
          pin: binary() | nil,
          key_label: String.t(),
          alg: atom(),
          encoding_context: :jose | :der
        ]

  @type verify_opts :: [
          module: Native.module_resource(),
          slot_id: non_neg_integer(),
          key_label: String.t(),
          alg: atom(),
          encoding_context: :jose | :der
        ]

  @doc """
  Sign `data` with a hardware-backed key.

  ## Required options
    * `:module` — a `Pkcs11ex.Native` module resource (from `Native.module_load/1`).
    * `:slot_id` — `CK_SLOT_ID` (non-negative integer).
    * `:key_label` — `CKA_LABEL` of the private key on the slot.
    * `:alg` — algorithm atom (e.g., `:PS256`). Must be in the configured
      `:allowed_algs` allowlist; any value outside the allowlist is rejected
      before the NIF is called.

  ## Optional options
    * `:pin` — User PIN for token slots; omit for cloud HSMs that don't require login.
    * `:encoding_context` — `:jose` or `:der`; defaults to `:der`. Controls the
      wire-format encoding of the returned signature for algorithms whose
      encoding differs by context (e.g., ES256 — irrelevant for PS256).
  """
  @spec sign_bytes(iodata(), sign_opts()) :: {:ok, binary()} | {:error, term()}
  def sign_bytes(data, opts) when is_list(opts) do
    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, adapter} <- Algorithm.lookup(alg),
         {:ok, mechanism} <- mechanism_string(adapter, :sign),
         {:ok, raw} <- dispatch_sign(opts, adapter, mechanism, IO.iodata_to_binary(data)),
         ctx <- Keyword.get(opts, :encoding_context, :der),
         {:ok, encoded} <- adapter.encode_signature(raw, ctx) do
      {:ok, encoded}
    end
  end

  @doc """
  Verify a `signature` over `data` using a hardware-backed public key.

  Required options: `:module`, `:slot_id`, `:key_label`, `:alg`.
  Optional: `:encoding_context` (default `:der`).
  """
  @spec verify_bytes(iodata(), binary(), verify_opts()) :: :ok | {:error, term()}
  def verify_bytes(data, signature, opts) when is_binary(signature) and is_list(opts) do
    with {:ok, alg} <- fetch_alg(opts),
         :ok <- check_alg_allowed(alg),
         {:ok, adapter} <- Algorithm.lookup(alg),
         {:ok, mechanism} <- mechanism_string(adapter, :verify),
         ctx <- Keyword.get(opts, :encoding_context, :der),
         {:ok, raw} <- adapter.decode_signature(signature, ctx),
         {:ok, true} <- run_verify(opts, mechanism, IO.iodata_to_binary(data), raw) do
      :ok
    else
      {:error, _} = err -> err
    end
  end

  @doc """
  Returns the version reported by the native bridge.

  Smoke test for the Rustler NIF wiring; returns the `Cargo.toml` package
  version of `pkcs11ex_nif`.
  """
  @spec native_version() :: String.t()
  def native_version, do: Native.version()

  # ---------- Internals ----------

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

  defp mechanism_string(adapter, :sign), do: {:ok, Atom.to_string(adapter.signing_mechanism())}
  defp mechanism_string(adapter, :verify), do: {:ok, Atom.to_string(adapter.verifying_mechanism())}

  # Choose between the persistent-session signer-ref path (preferred) and the
  # legacy explicit-opts path (per-call session). Signer-ref wins when present.
  defp dispatch_sign(opts, adapter, mechanism, data) do
    cond do
      Keyword.has_key?(opts, :signer) ->
        sign_via_signer(opts, adapter, data)

      Keyword.has_key?(opts, :module) ->
        run_sign(opts, mechanism, data)

      true ->
        {:error, :no_signer_specified}
    end
  end

  defp sign_via_signer(opts, adapter, data) do
    with {:ok, %{slot_ref: slot_ref, key_label: key_label}} <- resolve_signer(opts) do
      sign_opts = Keyword.take(opts, [:pin])

      Pkcs11ex.Slot.sign(slot_ref, key_label, adapter.signing_mechanism(), data, sign_opts)
    end
  end

  defp resolve_signer(opts) do
    case Keyword.fetch!(opts, :signer) do
      {slot_ref, key_ref} when is_atom(slot_ref) and is_atom(key_ref) ->
        resolve_signer_pair(slot_ref, key_ref)

      key_ref when is_atom(key_ref) ->
        case default_slot() do
          nil -> {:error, :no_default_slot}
          slot_ref -> resolve_signer_pair(slot_ref, key_ref)
        end

      other ->
        {:error, {:invalid_signer, other}}
    end
  end

  defp resolve_signer_pair(slot_ref, key_ref) do
    with {:ok, slot_config} <- Pkcs11ex.Slot.Server.get_config(slot_ref),
         keys = slot_config[:keys] || [],
         {:ok, key_entry} <- fetch_key(keys, key_ref),
         {:ok, key_label} <- key_label_from_entry(key_entry) do
      {:ok, %{slot_ref: slot_ref, key_ref: key_ref, key_label: key_label}}
    end
  end

  defp fetch_key(keys, key_ref) do
    case Keyword.fetch(keys, key_ref) do
      {:ok, entry} -> {:ok, entry}
      :error -> {:error, {:key_not_found, key_ref}}
    end
  end

  defp key_label_from_entry(entry) do
    case {entry[:label], entry[:id]} do
      {label, _} when is_binary(label) -> {:ok, label}
      {_, id} when is_binary(id) -> {:ok, id}
      _ -> {:error, :key_has_no_label_or_id}
    end
  end

  defp default_slot do
    Pkcs11ex.Application.config().default_slot
  rescue
    # Application not started — for example in plain-script use of the
    # legacy path without the supervisor. Atom-shorthand :signer requires
    # config; tuple form does not.
    _ -> nil
  end

  defp run_sign(opts, mechanism, data) do
    module = Keyword.fetch!(opts, :module)
    slot_id = Keyword.fetch!(opts, :slot_id)
    pin = Keyword.get(opts, :pin, "") || ""
    key_label = Keyword.fetch!(opts, :key_label)

    case Native.sign(module, slot_id, pin, mechanism, key_label, data) do
      {:ok, sig} when is_binary(sig) -> {:ok, sig}
      # Rustler 0.37 encodes Rust `Vec<u8>` returns as Erlang lists (not binaries).
      # Normalize here so callers always see a binary.
      {:ok, sig} when is_list(sig) -> {:ok, IO.iodata_to_binary(sig)}
      sig when is_binary(sig) -> {:ok, sig}
      sig when is_list(sig) -> {:ok, IO.iodata_to_binary(sig)}
      {:error, _} = err -> err
    end
  end

  defp run_verify(opts, mechanism, data, signature) do
    module = Keyword.fetch!(opts, :module)
    slot_id = Keyword.fetch!(opts, :slot_id)
    key_label = Keyword.fetch!(opts, :key_label)

    case Native.verify(module, slot_id, mechanism, key_label, data, signature) do
      {:ok, true} -> {:ok, true}
      true -> {:ok, true}
      {:error, _} = err -> err
    end
  end
end
