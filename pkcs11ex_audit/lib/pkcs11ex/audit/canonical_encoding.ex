defmodule Pkcs11ex.Audit.CanonicalEncoding do
  @moduledoc """
  Stable canonical-bytes encoder for audit-chain hash inputs.

  ## Why this exists

  `Pkcs11ex.Audit` binds each entry's `content_hash` to a canonical
  byte representation of its inputs. The previous implementation used
  `:erlang.term_to_binary/2` with the `:deterministic` flag — that
  flag fixes intra-version map-key ordering, but the **External Term
  Format itself is not stable across Erlang/OTP releases.** A routine
  OTP upgrade can therefore re-encode the same logical term to
  different bytes, which invalidates every previously stored
  `content_hash` and breaks `Pkcs11ex.Audit.verify/1` for the entire
  chain. The audit library exists to be tamper-evident across time;
  resting on an unstable encoding undermines exactly that claim.

  This module is the documented replacement: a small, explicit byte
  format I control, versioned at the front so any future format
  change can coexist with old chains by branching on the version
  byte.

  ## Format v1 — wire layout

      <type tag, 1 byte> <type-specific payload>

  Where the type tags are:

      0x00 — nil
      0x01 — true
      0x02 — false
      0x03 — atom        : <len:32-big> <utf8 bytes of `Atom.to_string/1`>
      0x04 — integer     : <sign:8 (0 = >=0, 1 = <0)> <len:32-big> <big-endian magnitude>
      0x05 — binary      : <len:32-big> <bytes>
      0x06 — list        : <len:32-big of encoded body> <encoded element 1> <encoded element 2> ...
      0x07 — map         : <len:32-big of encoded body> <encoded (k,v) pairs sorted by encoded-key bytes>
      0x08 — tuple       : <len:32-big of encoded body> <encoded element 1> <encoded element 2> ...
      0x09 — DateTime    : <len:32-big> <utf8 bytes of `DateTime.to_iso8601/1`>

  Maps are encoded with their `(encoded_key, encoded_value)` pairs
  sorted by the byte representation of the encoded keys, breaking
  ties lexicographically. This is the canonicalisation discipline
  that makes the encoding stable across map-key insertion order.

  Floats are deliberately rejected: float representation has too many
  cross-platform footguns (NaN, denormals, signed zero) to be safely
  hashed. Callers needing to log a float should convert to a string
  or a fixed-precision integer first.

  Anything that's not one of the supported types raises
  `ArgumentError`. The audit library catches it at the entry point
  (`Pkcs11ex.Audit.append/3`) and surfaces it as
  `{:error, {:invalid_payload, term}}`.

  ## Format versioning

  `Pkcs11ex.Audit.compute_hash/4` prefixes the canonical bytes with a
  single-byte format tag (`@hash_format_version` in `audit.ex`).
  Future format revisions bump the tag; verify-time hash recomputation
  reads the tag from the stored entry's `:hash_format` field (if
  added later) or assumes v1 (current default). Old entries hashed
  under format v1 stay verifiable forever — that's the point of
  versioning.
  """

  @doc """
  Encode `term` to canonical v1 bytes. See moduledoc for the format.

  Raises `ArgumentError` for unsupported types (floats, references,
  PIDs, ports, functions, structs other than `DateTime`).
  """
  @spec encode_v1(term()) :: binary()
  def encode_v1(term)

  def encode_v1(nil), do: <<0x00>>
  def encode_v1(true), do: <<0x01>>
  def encode_v1(false), do: <<0x02>>

  def encode_v1(atom) when is_atom(atom) do
    bytes = Atom.to_string(atom)
    <<0x03, byte_size(bytes)::32-big, bytes::binary>>
  end

  def encode_v1(n) when is_integer(n) do
    sign = if n < 0, do: 0x01, else: 0x00
    mag = :binary.encode_unsigned(abs(n), :big)
    <<0x04, sign::8, byte_size(mag)::32-big, mag::binary>>
  end

  def encode_v1(bin) when is_binary(bin) do
    <<0x05, byte_size(bin)::32-big, bin::binary>>
  end

  def encode_v1(list) when is_list(list) do
    body =
      list
      |> Enum.map(&encode_v1/1)
      |> IO.iodata_to_binary()

    <<0x06, byte_size(body)::32-big, body::binary>>
  end

  # DateTime is a struct (a map under the hood) — handle it before the
  # generic map clause so it gets canonicalised as its ISO-8601 string
  # rather than as a 9-key map.
  def encode_v1(%DateTime{} = dt) do
    iso = DateTime.to_iso8601(dt)
    <<0x09, byte_size(iso)::32-big, iso::binary>>
  end

  def encode_v1(%_{} = struct) do
    raise ArgumentError,
          "audit canonical encoding: structs other than DateTime are not supported (got #{inspect(struct.__struct__)}). " <>
            "Convert to a map or a binary representation before passing to the audit log."
  end

  def encode_v1(map) when is_map(map) do
    body =
      map
      |> Enum.map(fn {k, v} -> {encode_v1(k), encode_v1(v)} end)
      |> Enum.sort_by(fn {ke, _} -> ke end)
      |> Enum.map(fn {ke, ve} -> [ke, ve] end)
      |> IO.iodata_to_binary()

    <<0x07, byte_size(body)::32-big, body::binary>>
  end

  def encode_v1(tuple) when is_tuple(tuple) do
    body =
      tuple
      |> Tuple.to_list()
      |> Enum.map(&encode_v1/1)
      |> IO.iodata_to_binary()

    <<0x08, byte_size(body)::32-big, body::binary>>
  end

  def encode_v1(other) do
    raise ArgumentError,
          "audit canonical encoding: unsupported term type for #{inspect(other)}. " <>
            "Supported: nil, booleans, atoms, integers, binaries, lists, maps, tuples, DateTime. " <>
            "Floats and reference-bearing terms (PIDs, ports, refs, fns) are deliberately rejected " <>
            "because their representations are not stable across BEAM versions / platforms."
  end
end
