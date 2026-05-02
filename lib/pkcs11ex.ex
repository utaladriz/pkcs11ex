defmodule Pkcs11ex do
  @moduledoc """
  Hardware-backed digital signatures for Elixir, via PKCS#11.

  This module hosts the **Layer 2** signing primitives — format-agnostic
  `sign_bytes`, `verify_bytes`, `digest`, and `digest_stream`. Format adapters
  (`Pkcs11ex.JWS`, `Pkcs11ex.PDF`, `Pkcs11ex.XML`) build on top.

  See `docs/specs/specs.md` for architecture and `docs/specs/api.md` for the
  full public API specification.

  ## Phase 1 surface

  The current implementation requires explicit `:module`, `:slot_id`,
  `:key_label`, and (for token slots) `:pin` options. Config-driven
  `signer_ref` resolution lands in a later step once the slot supervisor and
  PIN-callback machinery are in place.
  """

  alias Pkcs11ex.Algorithm
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
         {:ok, raw} <- run_sign(opts, mechanism, IO.iodata_to_binary(data)),
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
