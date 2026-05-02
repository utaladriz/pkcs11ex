defmodule Pkcs11ex.Slot.Pool do
  @moduledoc """
  Round-robin dispatcher for multi-session slot pools.

  A slot configured with `session_pool_size: N > 1` runs N independent
  `Pkcs11ex.Slot.Server` workers, each holding its own PKCS#11 session.
  Sign/verify calls round-robin across workers so unrelated requests run
  concurrently rather than serializing through one mailbox.

  ## When pooling helps

  Cloud HSMs (e.g., GCP Cloud HSM via libkmsp11) make every operation a
  remote call. A single GenServer mailbox + single session means request
  N+1 waits for request N's network round-trip. With `session_pool_size:
  4`, four signs land on four sessions in parallel — practical 4× lower
  tail latency for bursty workloads.

  ## When pooling does NOT help and is forbidden

  PIN-protected token slots: login state lives on the session, not on
  the token. With multiple sessions, every worker would need to login
  independently — fine for `pin_callback`-driven flows but error-prone
  for explicit `login/2`, and the configured-PIN tests across the
  library all assume one logged-in session per slot.

  Cross-field config validation enforces `session_pool_size: 1` (the
  default) for `type: :token` slots.

  ## Concurrency model

  ETS-backed counter (named table, write_concurrency on). Round-robin via
  `:ets.update_counter/4` — atomic, lock-free in the BEAM ETS path. No
  GenServer round-trip on the hot path; only `register/2` (called once
  at slot startup) holds the GenServer.
  """

  use GenServer

  @table :pkcs11ex_slot_pool

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    table =
      case :ets.whereis(@table) do
        :undefined ->
          :ets.new(@table, [
            :set,
            :public,
            :named_table,
            {:read_concurrency, true},
            {:write_concurrency, true}
          ])

        existing ->
          existing
      end

    {:ok, %{table: table}}
  end

  @doc """
  Register a slot's pool size. Idempotent — re-registering with the same
  size is a no-op; with a different size, overwrites.

  Called once per slot from `Pkcs11ex.SlotSupervisor.init/1`.
  """
  @spec register(atom(), pos_integer()) :: :ok
  def register(slot_ref, size) when is_atom(slot_ref) and is_integer(size) and size >= 1 do
    :ets.insert(@table, {{:size, slot_ref}, size})
    :ok
  end

  @doc """
  Pool size for `slot_ref`. Defaults to 1 (single-worker, no pool) when
  the slot hasn't been registered — keeps the dispatch path uniform for
  ad-hoc test setups that start a `Slot.Server` without registering a
  pool size.
  """
  @spec pool_size(atom()) :: pos_integer()
  def pool_size(slot_ref) when is_atom(slot_ref) do
    case :ets.lookup(@table, {:size, slot_ref}) do
      [{_, size}] -> size
      [] -> 1
    end
  end

  @doc """
  Returns the next worker index in the range `1..pool_size(slot_ref)`,
  using atomic round-robin.

  For `pool_size = 1`, always returns `1` without touching ETS — the
  fast path for non-pooled slots.
  """
  @spec next_worker_index(atom()) :: pos_integer()
  def next_worker_index(slot_ref) when is_atom(slot_ref) do
    case pool_size(slot_ref) do
      1 ->
        1

      size ->
        # update_counter with default-tuple atomically creates the counter
        # if missing. Returns post-increment value, so subtract 1 to map
        # to 0-based indexing then mod into the 1..size range.
        n =
          :ets.update_counter(
            @table,
            {:counter, slot_ref},
            1,
            {{:counter, slot_ref}, 0}
          )

        rem(n - 1, size) + 1
    end
  end
end
