defmodule Pkcs11ex.Audit do
  @moduledoc """
  Append-only hash-chained audit log.

  > #### Future extraction {: .info}
  >
  > Per `docs/specs/specs.md` §9 Phase 5, audit lives in a sister
  > library `pkcs11ex_audit`. This namespace ships inside `pkcs11ex` for
  > now to keep the working session moving; the public API
  > (`Pkcs11ex.Audit`, `Pkcs11ex.Audit.Entry`, `Pkcs11ex.Audit.Storage`)
  > is what gets extracted, with the same module names.

  ## What this is

  A tamper-evident log: each entry's `:content_hash` includes the
  previous entry's hash as a prefix. Walking the chain end-to-end and
  recomputing each hash detects any modification — `verify/1` does that
  walk and reports the first divergence.

  Storage is pluggable (`Pkcs11ex.Audit.Storage` behaviour). The library
  ships `Pkcs11ex.Audit.Storage.InMemory` for dev/tests; production
  deployments plug a durable adapter (Postgres, SQLite, append-only
  files, S3 with Object Lock, etc.).

  ## What this is NOT

    * **Authenticated**. The chain proves "no entry was modified after
      insertion" given an honest verifier holding the head hash. It does
      NOT prove "the operator didn't replay/truncate the whole chain
      from a saved state." External anchoring (RFC 3161 trusted
      timestamping over the chain head) is the answer to that — Phase 5
      step 2.
    * **Encrypted**. Payload is stored in cleartext per the storage
      adapter's contract. Apps that need confidentiality encrypt the
      payload before calling `append/3`.
    * **A signing primitive**. The "chain root signed by the platform
      key" pattern lives a layer above; this module is the substrate.

  ## Usage

      {:ok, _} = Pkcs11ex.Audit.Storage.InMemory.start_link(name: :sigs)
      audit = Pkcs11ex.Audit.new(Pkcs11ex.Audit.Storage.InMemory, :sigs)

      {:ok, entry} =
        Pkcs11ex.Audit.append(audit, %{
          jws: jws,
          subject_id: :acme_corp,
          key_ref: {:platform, :signing}
        })

      :ok = Pkcs11ex.Audit.verify(audit)
  """

  alias Pkcs11ex.Audit.{CanonicalEncoding, Entry}

  @genesis_hash <<0::256>>

  # Single-byte tag prepended to every canonical-bytes block before
  # it's fed into SHA-256. Bumping this requires a parallel verify
  # path that branches on the tag; old entries stored under v1 stay
  # verifiable forever. v1 = `Pkcs11ex.Audit.CanonicalEncoding.encode_v1/1`.
  @hash_format_version 1

  defstruct [:storage_module, :storage_handle]

  @type t :: %__MODULE__{
          storage_module: module(),
          storage_handle: term()
        }

  @type append_opts :: [
          inserted_at: DateTime.t()
        ]

  @doc "Construct an audit reference around a running storage process / handle."
  @spec new(module(), term()) :: t()
  def new(storage_module, storage_handle) when is_atom(storage_module) do
    %__MODULE__{storage_module: storage_module, storage_handle: storage_handle}
  end

  @doc """
  Append `payload` as a new entry. Returns the constructed `Entry`.

  Reads the current head, computes `content_hash`, and asks the storage
  to persist. Storage adapters are expected to serialize concurrent
  appends (see `Pkcs11ex.Audit.Storage` moduledoc).
  """
  @spec append(t(), term(), append_opts()) :: {:ok, Entry.t()} | {:error, term()}
  def append(%__MODULE__{} = audit, payload, opts \\ []) do
    # Always truncate to second precision regardless of whether the caller
    # supplied :inserted_at. The hash binding uses the ISO-8601 string of
    # this value; sub-second precision in caller-supplied DateTimes would
    # round-trip lossy through any storage adapter that downcasts (Postgres
    # `timestamp(0)`, SQLite without explicit microsecond storage), making
    # `verify/1` fail with :content_hash_mismatch on otherwise-clean chains.
    inserted_at =
      (opts[:inserted_at] || DateTime.utc_now())
      |> DateTime.truncate(:second)

    {seq, prev_hash} =
      case audit.storage_module.head(audit.storage_handle) do
        {:ok, head} -> {head.seq + 1, head.content_hash}
        {:error, :empty} -> {1, @genesis_hash}
      end

    try do
      content_hash = compute_hash(prev_hash, seq, payload, inserted_at)

      entry = %Entry{
        seq: seq,
        prev_hash: prev_hash,
        content_hash: content_hash,
        payload: payload,
        inserted_at: inserted_at
      }

      case audit.storage_module.append(audit.storage_handle, entry) do
        :ok -> {:ok, entry}
        {:error, _} = err -> err
      end
    rescue
      e in ArgumentError -> {:error, {:invalid_payload, Exception.message(e)}}
    end
  end

  @doc """
  Walk the chain head-to-tail. Recomputes each `content_hash` and checks
  the `prev_hash` linkage. Returns `:ok` on a clean chain,
  `{:error, :empty_chain}` for a chain with no entries, or
  `{:error, {reason, seq}}` at the first divergence.

  An empty chain returns `:empty_chain` (not `:ok`) so callers can
  distinguish "nothing to verify" from "everything verified clean."
  Database-wipe attacks reduce a populated chain to empty; treating
  empty as success would silently obscure that. RFC 3161 anchoring
  (see `anchor_head/3`) is the cross-cutting answer to truncation,
  but `verify/1` should at least surface the truncation-shaped state.

  Reasons for a divergent chain:
    * `:seq_gap` — `seq` doesn't follow the previous entry's `seq + 1`.
    * `:prev_hash_mismatch` — `prev_hash` doesn't match the previous
      entry's `content_hash`.
    * `:content_hash_mismatch` — recomputed hash differs from the stored
      one (the entry's `payload` or `inserted_at` was tampered with).
  """
  @spec verify(t()) ::
          :ok | {:error, :empty_chain | {atom(), pos_integer()}}
  def verify(%__MODULE__{} = audit) do
    case audit.storage_module.head(audit.storage_handle) do
      {:error, :empty} -> {:error, :empty_chain}
      {:ok, _head} -> walk_chain(audit)
    end
  end

  defp walk_chain(audit) do
    audit.storage_module.all(audit.storage_handle)
    |> Enum.reduce_while({@genesis_hash, 1}, fn entry, {prev, expected_seq} ->
      cond do
        entry.seq != expected_seq ->
          {:halt, {:error, {:seq_gap, entry.seq}}}

        entry.prev_hash != prev ->
          {:halt, {:error, {:prev_hash_mismatch, entry.seq}}}

        compute_hash(prev, entry.seq, entry.payload, entry.inserted_at) != entry.content_hash ->
          {:halt, {:error, {:content_hash_mismatch, entry.seq}}}

        true ->
          {:cont, {entry.content_hash, expected_seq + 1}}
      end
    end)
    |> case do
      # The error tuple is itself a 2-tuple, so it must come before the
      # success pattern — otherwise `{_prev, _next_seq}` swallows it.
      {:error, _} = err -> err
      {_prev, _next_seq} -> :ok
    end
  end

  @doc """
  Anchor the current chain head against an RFC 3161 Time-Stamping
  Authority. Reads the head, sends its `content_hash` to the TSA, stores
  the returned TimeStampToken (TST) as a new audit entry whose payload
  carries the anchored seq + hash + opaque TST bytes.

  This addresses the "operator-replay/truncate" gap of a bare hash chain
  by binding the chain state to a TSA-attested time. The TST itself is
  a CMS SignedData; auditors verify its signature against the TSA's
  cert chain (out of scope for this library — store the bytes, hand to
  whoever audits).

  ## Required

    * `tsa_url` — the TSA's HTTP endpoint (e.g.,
      `"http://timestamp.digicert.com"`).

  ## Optional opts

    * `:timeout` — milliseconds, default 10_000.

  ## Returns

  `{:ok, anchor_entry}` on success, where `anchor_entry.payload` is a
  map `%{kind: :rfc3161_anchor, anchored_seq, anchored_hash, nonce, tst}`.
  Returns `{:error, :empty_chain}` if there's nothing to anchor.
  """
  @spec anchor_head(t(), String.t(), keyword()) :: {:ok, Entry.t()} | {:error, term()}
  def anchor_head(%__MODULE__{} = audit, tsa_url, opts \\ []) do
    with {:ok, head_entry} <- audit.storage_module.head(audit.storage_handle),
         {:ok, request} <- Pkcs11ex.Audit.Anchor.RFC3161.build_request(head_entry.content_hash),
         {:ok, tst} <- Pkcs11ex.Audit.Anchor.RFC3161.fetch_token(tsa_url, request.der, opts) do
      append(audit, %{
        kind: :rfc3161_anchor,
        anchored_seq: head_entry.seq,
        anchored_hash: head_entry.content_hash,
        nonce: request.nonce,
        tsa_url: tsa_url,
        tst: tst
      })
    else
      {:error, :empty} -> {:error, :empty_chain}
      {:error, _} = err -> err
    end
  end

  @doc "Convenience wrapper around the storage's `head/1`."
  @spec head(t()) :: {:ok, Entry.t()} | {:error, :empty}
  def head(%__MODULE__{} = audit), do: audit.storage_module.head(audit.storage_handle)

  @doc "Convenience wrapper around the storage's `at/2`."
  @spec at(t(), pos_integer()) :: {:ok, Entry.t()} | {:error, :not_found}
  def at(%__MODULE__{} = audit, seq) when is_integer(seq) and seq > 0,
    do: audit.storage_module.at(audit.storage_handle, seq)

  # ---------- Internals ----------

  # The hash binding includes everything that defines the entry's identity
  # at insertion time, encoded via the format-versioned canonical encoder
  # in `Pkcs11ex.Audit.CanonicalEncoding`. The leading byte is the format
  # version tag (currently 1) so a future encoding change can coexist
  # with old chains by branching on the tag at verify time.
  #
  # ISO-8601 of `inserted_at` (not the DateTime struct's internal
  # representation) is what enters the hash, so the binding is stable
  # across timezone-DB updates and DateTime struct-shape changes.
  defp compute_hash(prev_hash, seq, payload, inserted_at) do
    canonical =
      CanonicalEncoding.encode_v1({seq, payload, DateTime.to_iso8601(inserted_at)})

    :crypto.hash(:sha256, prev_hash <> <<@hash_format_version::8>> <> canonical)
  end
end
