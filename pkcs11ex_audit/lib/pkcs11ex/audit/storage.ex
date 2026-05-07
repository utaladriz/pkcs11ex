defmodule Pkcs11ex.Audit.Storage do
  @moduledoc """
  Pluggable storage backend for `Pkcs11ex.Audit`.

  Audit entries can be persisted anywhere — Postgres, SQLite, S3 with
  Object Lock, append-only files, etc. The library ships
  `Pkcs11ex.Audit.Storage.InMemory` for tests and dev; production
  deployments implement this behaviour against their own durable store.

  ## Concurrency contract

  Implementations MUST guarantee that `append/2` is atomic with respect
  to `head/1` reads — `Pkcs11ex.Audit.append/3` reads `head` to compute
  the next sequence + prev_hash, then calls `append`. If two processes
  race that pattern, the storage must serialize them (via a process,
  database transaction, etc.) to keep sequence numbers contiguous.

  The InMemory adapter uses a single `Agent` to serialize naturally.
  """

  alias Pkcs11ex.Audit.Entry

  @type storage_handle :: term()

  @doc "Append `entry` as the new head."
  @callback append(storage_handle(), Entry.t()) :: :ok | {:error, term()}

  @doc "Return the most recently appended entry."
  @callback head(storage_handle()) :: {:ok, Entry.t()} | {:error, :empty}

  @doc "Look up an entry by its `:seq`."
  @callback at(storage_handle(), pos_integer()) :: {:ok, Entry.t()} | {:error, :not_found}

  @doc """
  Iterate the log in order (seq=1 → head). Implementations may stream;
  callers that walk the whole log (e.g., `Pkcs11ex.Audit.verify/1`) treat
  the return as `t:Enumerable.t/0`.
  """
  @callback all(storage_handle()) :: Enumerable.t()
end
