defmodule Pkcs11ex.Audit.Entry do
  @moduledoc """
  A single entry in a hash-chained append-only audit log.

  Fields:
    * `:seq` — monotonically increasing position. The first entry is `1`.
    * `:prev_hash` — `content_hash` of the previous entry. The genesis
      entry uses 32 zero bytes.
    * `:content_hash` — `SHA-256(prev_hash || canonical(seq, payload, inserted_at))`
      where `canonical/3` is `:erlang.term_to_binary(term, [:deterministic])`.
      Recomputable from `:prev_hash`, `:seq`, `:payload`, `:inserted_at` —
      `Pkcs11ex.Audit.verify/1` does exactly that walk.
    * `:payload` — application-defined. The library logs whatever you
      hand it. For signature audit, typically a map with the JWS string,
      signer subject_id from policy, key_ref, and any extra context.
    * `:inserted_at` — `DateTime.t()` in UTC, second-precision (the hash
      uses ISO-8601 string of this).
  """

  @enforce_keys [:seq, :prev_hash, :content_hash, :payload, :inserted_at]
  defstruct [:seq, :prev_hash, :content_hash, :payload, :inserted_at]

  @type t :: %__MODULE__{
          seq: pos_integer(),
          prev_hash: <<_::256>>,
          content_hash: <<_::256>>,
          payload: term(),
          inserted_at: DateTime.t()
        }
end
