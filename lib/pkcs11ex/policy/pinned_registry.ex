defmodule Pkcs11ex.Policy.PinnedRegistry do
  @moduledoc """
  Default `Pkcs11ex.Policy` implementation: SPKI pinning.

  Trust is rooted in an explicit allowlist mapping
  `SHA-256(SubjectPublicKeyInfo)` (hex, lowercase) → an application-defined
  `subject_id`. Onboarding a counterparty is `put/2`; off-boarding is
  `delete/1`. There is no chain validation, no CA, no revocation protocol —
  the registry IS the source of truth, and removing an entry is the
  revocation primitive.

  SPKI pin (vs. whole-cert pin) survives routine certificate re-issuance with
  the same key; rotations of the key require an explicit re-pin.

  ## Configuration

      config :pkcs11ex, Pkcs11ex.Policy.PinnedRegistry,
        pins: [
          {"a3f1...d29c", :acme_corp},
          {"7e2b...4810", :beta_inc}
        ]

  Initial pins are loaded once at supervisor start. Runtime updates go
  through `put/2` and `delete/1`, which serialize through the registry's
  `GenServer` to keep the ETS table single-writer.

  Reads (`resolve/2`, `validate/3`, `list/0`, `lookup/1`) hit the ETS table
  directly with no GenServer round-trip — they're hot path.
  """

  use GenServer

  @behaviour Pkcs11ex.Policy

  alias Pkcs11ex.X509

  @table __MODULE__

  @type spki_hex :: String.t()
  @type subject_id :: term()

  # ---------- Public API ----------

  @doc false
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Adds or updates a pin. `subject_id` is whatever the application uses to
  identify the counterparty downstream — typically an atom or a struct.

  Hex digest is normalized to lowercase before storage.
  """
  @spec put(spki_hex(), subject_id()) :: :ok | {:error, :invalid_spki_hex}
  def put(spki_hex, subject_id) when is_binary(spki_hex) do
    case normalize_hex(spki_hex) do
      {:ok, hex} -> GenServer.call(__MODULE__, {:put, hex, subject_id})
      :error -> {:error, :invalid_spki_hex}
    end
  end

  @doc "Removes a pin. Returns `:ok` whether or not the entry existed."
  @spec delete(spki_hex()) :: :ok | {:error, :invalid_spki_hex}
  def delete(spki_hex) when is_binary(spki_hex) do
    case normalize_hex(spki_hex) do
      {:ok, hex} -> GenServer.call(__MODULE__, {:delete, hex})
      :error -> {:error, :invalid_spki_hex}
    end
  end

  @doc "Returns the full list of `{spki_hex, subject_id}` entries."
  @spec list() :: [{spki_hex(), subject_id()}]
  def list do
    case :ets.whereis(@table) do
      :undefined -> []
      _ -> :ets.tab2list(@table)
    end
  end

  @doc """
  Looks up a single pin without going through the policy interface.

  Returns `{:ok, subject_id}` or `:error`. Hex digest is matched
  case-insensitively (callers usually pass lowercase, but uppercase from
  e.g. `Base.encode16/1` works).
  """
  @spec lookup(spki_hex()) :: {:ok, subject_id()} | :error
  def lookup(spki_hex) when is_binary(spki_hex) do
    with {:ok, hex} <- normalize_hex(spki_hex),
         tid when tid != :undefined <- :ets.whereis(@table),
         [{^hex, sid}] <- :ets.lookup(@table, hex) do
      {:ok, sid}
    else
      _ -> :error
    end
  end

  # ---------- Pkcs11ex.Policy callbacks ----------

  @impl Pkcs11ex.Policy
  def resolve(%{"x5c" => [b64_der | _rest]} = _header, _opts) when is_binary(b64_der) do
    with {:ok, der} <- decode_x5c_b64(b64_der),
         {:ok, cert} <- X509.from_der(der),
         spki <- X509.spki_sha256(cert),
         {:ok, _subject_id} <- lookup(spki) do
      {:ok, cert, []}
    else
      :error -> {:error, :unknown_signer}
      {:error, _} = err -> err
    end
  end

  def resolve(_header, _opts), do: {:error, :unknown_signer}

  @impl Pkcs11ex.Policy
  def validate(%X509{} = cert, _chain, _opts) do
    spki = X509.spki_sha256(cert)

    case lookup(spki) do
      {:ok, subject_id} -> {:ok, subject_id}
      :error -> {:error, :untrusted_signer}
    end
  end

  # ---------- GenServer callbacks ----------

  @impl GenServer
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :protected, :set, read_concurrency: true])
    load_initial_pins(table)
    {:ok, %{table: table}}
  end

  @impl GenServer
  def handle_call({:put, hex, subject_id}, _from, state) do
    :ets.insert(state.table, {hex, subject_id})
    {:reply, :ok, state}
  end

  def handle_call({:delete, hex}, _from, state) do
    :ets.delete(state.table, hex)
    {:reply, :ok, state}
  end

  # ---------- Internals ----------

  defp load_initial_pins(table) do
    case Application.get_env(:pkcs11ex, __MODULE__) do
      nil ->
        :ok

      kw when is_list(kw) ->
        kw
        |> Keyword.get(:pins, [])
        |> Enum.each(fn
          {spki_hex, subject_id} when is_binary(spki_hex) ->
            case normalize_hex(spki_hex) do
              {:ok, hex} -> :ets.insert(table, {hex, subject_id})
              :error -> :ok
            end
        end)
    end
  end

  defp normalize_hex(spki_hex) do
    lower = String.downcase(spki_hex)

    if byte_size(lower) == 64 and Regex.match?(~r/^[0-9a-f]{64}$/, lower) do
      {:ok, lower}
    else
      :error
    end
  end

  defp decode_x5c_b64(b64) do
    # x5c per RFC 7515 §4.1.6 is standard base64 (not base64url).
    case Base.decode64(b64) do
      {:ok, der} -> {:ok, der}
      :error -> {:error, :invalid_x5c_b64}
    end
  end
end
