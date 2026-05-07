defmodule Pkcs11ex.AuditTest do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Audit
  alias Pkcs11ex.Audit.Entry
  alias Pkcs11ex.Audit.Storage.InMemory

  setup do
    name = :"audit_test_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({InMemory, name: name})
    {:ok, audit: Audit.new(InMemory, name), storage_name: name}
  end

  describe "append/3" do
    test "first entry has seq 1 and prev_hash of 32 zero bytes", %{audit: audit} do
      assert {:ok, %Entry{seq: 1, prev_hash: <<0::256>>}} = Audit.append(audit, "first")
    end

    test "subsequent entries have monotonically increasing seq", %{audit: audit} do
      {:ok, e1} = Audit.append(audit, "first")
      {:ok, e2} = Audit.append(audit, "second")
      {:ok, e3} = Audit.append(audit, "third")

      assert e1.seq == 1
      assert e2.seq == 2
      assert e3.seq == 3
    end

    test "each entry's prev_hash equals the previous entry's content_hash", %{audit: audit} do
      {:ok, e1} = Audit.append(audit, "first")
      {:ok, e2} = Audit.append(audit, "second")
      {:ok, e3} = Audit.append(audit, "third")

      assert e1.prev_hash == <<0::256>>
      assert e2.prev_hash == e1.content_hash
      assert e3.prev_hash == e2.content_hash
    end

    test "content_hash is 32 bytes (SHA-256 output)", %{audit: audit} do
      {:ok, entry} = Audit.append(audit, "x")
      assert byte_size(entry.content_hash) == 32
    end

    test "stores arbitrary payload terms", %{audit: audit} do
      payload = %{
        jws: "eyJ...",
        subject_id: :acme_corp,
        key_ref: {:platform, :signing}
      }

      assert {:ok, %Entry{payload: ^payload}} = Audit.append(audit, payload)
    end

    test "explicit :inserted_at is honored", %{audit: audit} do
      ts = ~U[2024-01-15 10:00:00Z]
      assert {:ok, %Entry{inserted_at: ^ts}} = Audit.append(audit, "x", inserted_at: ts)
    end

    test "caller-supplied :inserted_at is truncated to second precision", %{audit: audit} do
      # Sub-second precision in the caller's DateTime would round-trip
      # lossy through any storage adapter that downcasts (Postgres
      # `timestamp(0)`, SQLite without explicit microsecond storage),
      # making `verify/1` fail with :content_hash_mismatch on
      # otherwise-clean chains. `append/3` truncates unconditionally.
      sub_second = ~U[2024-01-15 10:00:00.123456Z]
      assert {:ok, %Entry{inserted_at: stored}} = Audit.append(audit, "x", inserted_at: sub_second)
      assert stored == ~U[2024-01-15 10:00:00Z]
      assert :ok = Audit.verify(audit)
    end

    test "rejects payloads containing unsupported types", %{audit: audit} do
      # Floats, refs, PIDs, ports, fns are explicitly rejected by the
      # canonical encoder because their representations are not stable
      # across BEAM versions / platforms. The audit library surfaces
      # this as `{:error, {:invalid_payload, _}}` rather than letting
      # the ArgumentError escape.
      assert {:error, {:invalid_payload, _msg}} = Audit.append(audit, %{value: 1.5})
      assert {:error, {:invalid_payload, _msg}} = Audit.append(audit, make_ref())
    end
  end

  describe "head/1, at/2" do
    test "head/1 returns :empty before any append", %{audit: audit} do
      assert {:error, :empty} = Audit.head(audit)
    end

    test "head/1 returns the most recent entry after appends", %{audit: audit} do
      {:ok, _} = Audit.append(audit, "a")
      {:ok, _} = Audit.append(audit, "b")
      {:ok, e3} = Audit.append(audit, "c")

      assert {:ok, ^e3} = Audit.head(audit)
    end

    test "at/2 looks up by seq", %{audit: audit} do
      {:ok, e1} = Audit.append(audit, "a")
      {:ok, e2} = Audit.append(audit, "b")

      assert {:ok, ^e1} = Audit.at(audit, 1)
      assert {:ok, ^e2} = Audit.at(audit, 2)
      assert {:error, :not_found} = Audit.at(audit, 99)
    end
  end

  describe "verify/1" do
    test ":ok on a clean chain", %{audit: audit} do
      Audit.append(audit, "a")
      Audit.append(audit, "b")
      Audit.append(audit, "c")

      assert :ok = Audit.verify(audit)
    end

    test "{:error, :empty_chain} on an empty chain", %{audit: audit} do
      # An empty chain is distinct from "everything verified clean" —
      # database-wipe attacks reduce a populated chain to empty, and a
      # silent :ok would obscure that. Callers can pattern-match the
      # distinction to decide whether the absence is expected.
      assert {:error, :empty_chain} = Audit.verify(audit)
    end

    test "detects tampering with payload", %{audit: audit, storage_name: name} do
      {:ok, _} = Audit.append(audit, "a")
      {:ok, e2} = Audit.append(audit, "b")
      {:ok, _} = Audit.append(audit, "c")

      # Mutate seq=2's payload while leaving its content_hash unchanged.
      tampered = %{e2 | payload: "TAMPERED"}
      InMemory.__overwrite_for_test__(name, tampered)

      assert {:error, {:content_hash_mismatch, 2}} = Audit.verify(audit)
    end

    test "detects tampering with prev_hash", %{audit: audit, storage_name: name} do
      {:ok, _} = Audit.append(audit, "a")
      {:ok, e2} = Audit.append(audit, "b")
      {:ok, _} = Audit.append(audit, "c")

      tampered = %{e2 | prev_hash: <<1::256>>}
      InMemory.__overwrite_for_test__(name, tampered)

      assert {:error, {:prev_hash_mismatch, 2}} = Audit.verify(audit)
    end

    test "tamper at the head is also detected", %{audit: audit, storage_name: name} do
      {:ok, _} = Audit.append(audit, "a")
      {:ok, _} = Audit.append(audit, "b")
      {:ok, e3} = Audit.append(audit, "c")

      tampered = %{e3 | payload: "TAIL TAMPER"}
      InMemory.__overwrite_for_test__(name, tampered)

      assert {:error, {:content_hash_mismatch, 3}} = Audit.verify(audit)
    end
  end
end
