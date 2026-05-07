defmodule Pkcs11ex.Audit.CanonicalEncodingTest do
  @moduledoc """
  Pin the byte-level v1 format with explicit vectors. The whole point
  of this encoder is that its output is stable across Erlang/OTP
  releases, BEAM upgrades, and machine restarts. Any drift in these
  vectors means the audit-chain hash binding silently broke — which
  invalidates every previously stored `content_hash`.

  When you intentionally bump the format, copy these tests into a v2
  suite, change the bytes there, and leave v1 here so old chains stay
  verifiable.
  """

  use ExUnit.Case, async: true

  alias Pkcs11ex.Audit.CanonicalEncoding

  describe "encode_v1/1 — primitives" do
    test "nil is one byte", do: assert CanonicalEncoding.encode_v1(nil) == <<0x00>>
    test "true is one byte", do: assert CanonicalEncoding.encode_v1(true) == <<0x01>>
    test "false is one byte", do: assert CanonicalEncoding.encode_v1(false) == <<0x02>>

    test "empty atom :\"\" encodes as tag + zero-length" do
      assert CanonicalEncoding.encode_v1(:"") == <<0x03, 0::32>>
    end

    test "atom :PS256 encodes as tag + 5 + utf8 bytes" do
      assert CanonicalEncoding.encode_v1(:PS256) ==
               <<0x03, 5::32, "PS256"::binary>>
    end

    test "integer 0 encodes as tag + sign(0) + length 1 + 0x00" do
      # `:binary.encode_unsigned(0, :big)` returns the single byte
      # <<0>> (not the empty binary), so the encoded magnitude
      # always has at least one byte.
      assert CanonicalEncoding.encode_v1(0) == <<0x04, 0x00, 1::32, 0x00>>
    end

    test "integer 256 encodes as tag + sign(0) + length 2 + big-endian" do
      assert CanonicalEncoding.encode_v1(256) ==
               <<0x04, 0x00, 2::32, 0x01, 0x00>>
    end

    test "integer -1 encodes as tag + sign(1) + length 1 + magnitude" do
      assert CanonicalEncoding.encode_v1(-1) == <<0x04, 0x01, 1::32, 0x01>>
    end

    test "binary \"hi\" encodes as tag + length 2 + bytes" do
      assert CanonicalEncoding.encode_v1("hi") == <<0x05, 2::32, "hi"::binary>>
    end

    test "DateTime encodes as tag + ISO-8601 string" do
      dt = ~U[2024-01-15 10:00:00Z]
      iso = "2024-01-15T10:00:00Z"
      assert CanonicalEncoding.encode_v1(dt) ==
               <<0x09, byte_size(iso)::32, iso::binary>>
    end
  end

  describe "encode_v1/1 — collections" do
    test "empty list encodes as tag + zero-length body" do
      assert CanonicalEncoding.encode_v1([]) == <<0x06, 0::32>>
    end

    test "list [1, 2] encodes as tag + body length + concatenated elements" do
      one = CanonicalEncoding.encode_v1(1)
      two = CanonicalEncoding.encode_v1(2)
      body = one <> two

      assert CanonicalEncoding.encode_v1([1, 2]) ==
               <<0x06, byte_size(body)::32>> <> body
    end

    test "tuple {:a, :b} encodes as tag + body length + concatenated elements" do
      a = CanonicalEncoding.encode_v1(:a)
      b = CanonicalEncoding.encode_v1(:b)
      body = a <> b

      assert CanonicalEncoding.encode_v1({:a, :b}) ==
               <<0x08, byte_size(body)::32>> <> body
    end

    test "map with two keys produces same bytes regardless of insertion order" do
      a = %{a: 1, b: 2}
      b = %{b: 2, a: 1}
      assert CanonicalEncoding.encode_v1(a) == CanonicalEncoding.encode_v1(b)
    end

    test "map encoding sorts pairs by encoded-key bytes" do
      # Atom keys :a (0x03 1::32 "a") and :b (0x03 1::32 "b") sort
      # lexicographically — the ordering is deterministic and tested
      # at the byte level.
      key_a = CanonicalEncoding.encode_v1(:a)
      val_1 = CanonicalEncoding.encode_v1(1)
      key_b = CanonicalEncoding.encode_v1(:b)
      val_2 = CanonicalEncoding.encode_v1(2)

      body = key_a <> val_1 <> key_b <> val_2

      assert CanonicalEncoding.encode_v1(%{a: 1, b: 2}) ==
               <<0x07, byte_size(body)::32>> <> body
    end

    test "nested maps encode deterministically" do
      payload = %{
        jws: "eyJ...",
        subject_id: :acme_corp,
        key_ref: {:platform, :signing},
        signed_at: ~U[2024-01-15 10:00:00Z]
      }

      a = CanonicalEncoding.encode_v1(payload)
      b = CanonicalEncoding.encode_v1(payload)
      assert a == b
      assert is_binary(a)
      assert byte_size(a) > 0
    end
  end

  describe "encode_v1/1 — rejection of unsupported types" do
    test "floats raise ArgumentError" do
      assert_raise ArgumentError, ~r/Floats and reference-bearing terms/, fn ->
        CanonicalEncoding.encode_v1(1.5)
      end
    end

    test "references raise ArgumentError" do
      assert_raise ArgumentError, fn ->
        CanonicalEncoding.encode_v1(make_ref())
      end
    end

    test "pids raise ArgumentError" do
      assert_raise ArgumentError, fn ->
        CanonicalEncoding.encode_v1(self())
      end
    end

    test "non-DateTime structs raise ArgumentError" do
      assert_raise ArgumentError, ~r/structs other than DateTime/, fn ->
        CanonicalEncoding.encode_v1(%Pkcs11ex.Audit.Entry{
          seq: 1,
          prev_hash: <<0::256>>,
          content_hash: <<0::256>>,
          payload: nil,
          inserted_at: ~U[2024-01-15 10:00:00Z]
        })
      end
    end
  end

  describe "encode_v1/1 — known good vectors" do
    # These vectors LOCK the byte format. If any of them change in
    # a future PR, the audit-chain hash binding has silently broken
    # for every existing stored `content_hash`. Bump the format
    # version (and add a v2 module) before changing these.

    test "vector: integer 1 → 7 bytes" do
      # tag(0x04) + sign(0x00) + length(1::32) + magnitude(0x01)
      assert CanonicalEncoding.encode_v1(1) ==
               <<0x04, 0x00, 0, 0, 0, 1, 0x01>>
    end

    test "vector: binary <<>> (empty) → 5 bytes" do
      # tag(0x05) + length(0::32)
      assert CanonicalEncoding.encode_v1("") == <<0x05, 0, 0, 0, 0>>
    end

    test "vector: tuple {1, 2} pinned" do
      expected =
        <<
          # tuple tag
          0x08,
          # body length: 14 (two 7-byte int encodings)
          0,
          0,
          0,
          14,
          # encode_v1(1)
          0x04,
          0x00,
          0,
          0,
          0,
          1,
          0x01,
          # encode_v1(2)
          0x04,
          0x00,
          0,
          0,
          0,
          1,
          0x02
        >>

      assert CanonicalEncoding.encode_v1({1, 2}) == expected
    end
  end
end
