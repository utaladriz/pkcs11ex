defmodule Pkcs11ex.Slot do
  @moduledoc """
  Public operational surface for configured slots.

  Each slot in `config :pkcs11ex, :slots` maps to a `Pkcs11ex.Slot.Server`
  GenServer started under `Pkcs11ex.SlotSupervisor`. This module exposes the
  caller-facing API.

  ## Phase 2 step 1 surface

  Sign / verify here are the slot-aware path with **persistent sessions** —
  one PKCS#11 session per slot, reused across calls. Compare with
  `Pkcs11ex.sign_bytes/2` / `verify_bytes/4` which take an explicit module +
  slot_id and open a new session per call (the Phase 1 path).

  Step 3 unifies these by routing `Pkcs11ex.sign_bytes/2` through this module
  whenever a `:signer` opt is provided.
  """

  alias Pkcs11ex.Slot.Server

  @typedoc "State exposed by `status/1`."
  @type state :: :uninitialized | :open | :logged_in

  @doc """
  Sign `data` with `key_label` on `slot_ref`. The PIN is taken from `opts[:pin]`
  if the slot isn't already logged in. Subsequent calls reuse the logged-in
  session.

  Mechanism is the algorithm's PKCS#11 mechanism atom (e.g.,
  `:ck_sha256_rsa_pkcs_pss` for PS256 — see `SignCore.Algorithm.PS256.signing_mechanism/0`).
  """
  @spec sign(atom(), String.t(), atom(), iodata(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  defdelegate sign(slot_ref, key_label, mechanism, data, opts \\ []), to: Server

  @doc "Verify a signature on `slot_ref`."
  @spec verify(atom(), String.t(), atom(), iodata(), binary(), keyword()) ::
          :ok | {:error, term()}
  defdelegate verify(slot_ref, key_label, mechanism, data, signature, opts \\ []), to: Server

  @doc """
  Explicit one-shot login. Use this when bypassing a configured `pin_callback`
  (e.g., in scripts or tests). The PIN is consumed once; the next sign call
  reuses the logged-in session.
  """
  @spec login(atom(), binary()) :: :ok | {:error, term()}
  defdelegate login(slot_ref, pin), to: Server

  @doc "Returns the slot's current state (`:uninitialized`, `:open`, or `:logged_in`)."
  @spec status(atom()) :: state()
  defdelegate status(slot_ref), to: Server

  @doc """
  Explicit logout. Closes the PKCS#11 user session but keeps the underlying
  session resource open for reuse (next sign call will need a PIN again).
  """
  @spec logout(atom()) :: :ok | {:error, term()}
  defdelegate logout(slot_ref), to: Server

  @doc "List all running slot servers along with their state."
  @spec list() :: [%{ref: atom(), state: state()}]
  def list do
    Registry.select(Pkcs11ex.Slot.Registry, [{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])
    |> Enum.map(fn {ref, _pid} -> %{ref: ref, state: status(ref)} end)
  end
end
