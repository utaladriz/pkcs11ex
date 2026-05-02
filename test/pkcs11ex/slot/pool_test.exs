defmodule Pkcs11ex.Slot.PoolTest do
  @moduledoc """
  Unit tests for the round-robin dispatcher. Doesn't touch any real
  Slot.Servers — just exercises the ETS counter math.

  The Pool GenServer + ETS table are started by Pkcs11ex.Application,
  so these tests can call directly into the public API.
  """

  use ExUnit.Case, async: false

  alias Pkcs11ex.Slot.Pool

  describe "pool_size/1" do
    test "defaults to 1 for unregistered slots" do
      assert Pool.pool_size(:never_registered_slot) == 1
    end

    test "returns the registered size" do
      ref = unique_ref()
      assert :ok = Pool.register(ref, 4)
      assert Pool.pool_size(ref) == 4
    end

    test "re-register overwrites" do
      ref = unique_ref()
      Pool.register(ref, 2)
      Pool.register(ref, 3)
      assert Pool.pool_size(ref) == 3
    end
  end

  describe "next_worker_index/1" do
    test "always returns 1 for unregistered slots (fast path)" do
      ref = unique_ref()
      Enum.each(1..10, fn _ -> assert Pool.next_worker_index(ref) == 1 end)
    end

    test "always returns 1 for size=1 slots (no counter increment)" do
      ref = unique_ref()
      Pool.register(ref, 1)
      Enum.each(1..10, fn _ -> assert Pool.next_worker_index(ref) == 1 end)
    end

    test "round-robins through the pool size" do
      ref = unique_ref()
      Pool.register(ref, 3)

      # Twelve calls cycle through 1,2,3,1,2,3,...
      indices = for _ <- 1..12, do: Pool.next_worker_index(ref)
      assert indices == [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]
    end

    test "indices stay within 1..size under concurrent load" do
      ref = unique_ref()
      Pool.register(ref, 4)

      results =
        1..200
        |> Task.async_stream(fn _ -> Pool.next_worker_index(ref) end,
          max_concurrency: 32,
          ordered: false
        )
        |> Enum.map(fn {:ok, idx} -> idx end)

      assert Enum.all?(results, &(&1 in 1..4))
      # All four buckets should be represented (otherwise round-robin is broken).
      assert results |> Enum.uniq() |> Enum.sort() == [1, 2, 3, 4]
      # Distribution should be roughly even — within 50 of 200/4 = 50 each.
      counts = Enum.frequencies(results)
      Enum.each(counts, fn {_, n} -> assert n in 30..70 end)
    end
  end

  defp unique_ref do
    :"pool_test_#{System.unique_integer([:positive])}"
  end
end
