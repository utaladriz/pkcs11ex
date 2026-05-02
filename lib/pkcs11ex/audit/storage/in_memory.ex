defmodule Pkcs11ex.Audit.Storage.InMemory do
  @moduledoc """
  In-memory audit log storage. Agent-backed; serializes appends through
  the agent's mailbox.

  > #### Not durable {: .warning}
  >
  > Suitable for tests, scripts, and one-off introspection. Production
  > deployments should plug a durable adapter (Postgres, SQLite,
  > append-only file with fsync, etc.).

  Start one Agent per audit log:

      {:ok, _} = Pkcs11ex.Audit.Storage.InMemory.start_link(name: :my_log)
      audit = Pkcs11ex.Audit.new(Pkcs11ex.Audit.Storage.InMemory, :my_log)
      {:ok, _entry} = Pkcs11ex.Audit.append(audit, %{...})
  """

  use Agent

  @behaviour Pkcs11ex.Audit.Storage

  alias Pkcs11ex.Audit.Entry

  # ---------- Lifecycle ----------

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    Agent.start_link(fn -> initial_state() end, name: name)
  end

  defp initial_state, do: %{by_seq: %{}, head: nil}

  @doc """
  **Test-only** — direct mutation of an entry already in the store.
  Used by chain-tamper-detection tests. Production code never calls this.
  """
  def __overwrite_for_test__(name, %Entry{seq: seq} = entry) do
    Agent.update(name, fn state ->
      %{state | by_seq: Map.put(state.by_seq, seq, entry)}
    end)
  end

  # ---------- Pkcs11ex.Audit.Storage callbacks ----------

  @impl true
  def append(name, %Entry{seq: seq} = entry) do
    Agent.update(name, fn state ->
      %{state | by_seq: Map.put(state.by_seq, seq, entry), head: entry}
    end)

    :ok
  end

  @impl true
  def head(name) do
    case Agent.get(name, & &1.head) do
      nil -> {:error, :empty}
      entry -> {:ok, entry}
    end
  end

  @impl true
  def at(name, seq) when is_integer(seq) and seq > 0 do
    case Agent.get(name, &Map.get(&1.by_seq, seq)) do
      nil -> {:error, :not_found}
      entry -> {:ok, entry}
    end
  end

  @impl true
  def all(name) do
    Agent.get(name, fn state ->
      state.by_seq
      |> Map.values()
      |> Enum.sort_by(& &1.seq)
    end)
  end
end
