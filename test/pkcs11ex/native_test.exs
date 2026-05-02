defmodule Pkcs11ex.NativeTest do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Native

  describe "version/0" do
    test "returns the crate version string" do
      version = Native.version()
      assert is_binary(version)
      assert version =~ ~r/^\d+\.\d+\.\d+/
    end
  end

  describe "module_load/1 — failure paths" do
    test "returns :driver_load_failed for a non-existent path" do
      assert {:error, {:driver_load_failed, msg}} = Native.module_load("/no/such/driver.so")
      assert is_binary(msg)
    end

    test "returns :driver_load_failed when the file is not a valid PKCS#11 module" do
      tmp = Path.join(System.tmp_dir!(), "pkcs11ex_invalid_#{System.unique_integer([:positive])}.so")
      File.write!(tmp, "not a real shared library")
      on_exit(fn -> File.rm(tmp) end)

      assert {:error, {tag, _msg}} = Native.module_load(tmp)
      assert tag in [:driver_load_failed, :pkcs11_error]
    end
  end

  describe "module_load_pinned/2 — pinning gate" do
    test "returns :driver_pin_mismatch on hash mismatch (file not dlopen'd)" do
      tmp = Path.join(System.tmp_dir!(), "pkcs11ex_pinned_#{System.unique_integer([:positive])}.so")
      File.write!(tmp, "doesn't matter what bytes")
      on_exit(fn -> File.rm(tmp) end)

      bogus = String.duplicate("0", 64)

      assert {:error, {:driver_pin_mismatch, ^bogus, actual}} =
               Native.module_load_pinned(tmp, bogus)

      # actual should be the real SHA-256 of the file, lowercase hex
      assert String.length(actual) == 64
      assert actual == String.downcase(actual)
    end

    test "is case-insensitive on the configured pin" do
      tmp = Path.join(System.tmp_dir!(), "pkcs11ex_pinned_case_#{System.unique_integer([:positive])}.so")
      File.write!(tmp, "case insensitivity test")
      on_exit(fn -> File.rm(tmp) end)

      lower = :crypto.hash(:sha256, File.read!(tmp)) |> Base.encode16(case: :lower)
      upper = String.upcase(lower)

      # Hash matches but the file isn't a real PKCS#11 lib, so dlopen will fail.
      # Either error tag is acceptable here — the point is that the pinning
      # check accepted the upper-case digest.
      assert {:error, {tag, _}} = Native.module_load_pinned(tmp, upper)
      assert tag in [:driver_load_failed, :pkcs11_error]
    end
  end

  describe "list_slots/1 against SoftHSM2" do
    @describetag :softhsm

    setup do
      driver = Pkcs11ex.Test.SoftHSM.driver_path()
      {:ok, module} = Native.module_load(driver)
      {:ok, module: module}
    end

    test "returns a list of SlotInfo maps", %{module: module} do
      assert {:ok, slots} = Native.list_slots(module)
      assert is_list(slots)

      Enum.each(slots, fn slot ->
        assert is_struct(slot, Pkcs11ex.Native.SlotInfo)
        assert is_integer(slot.slot_id) and slot.slot_id >= 0
        assert is_binary(slot.description)
        assert is_binary(slot.manufacturer)
        assert is_boolean(slot.token_present)
      end)
    end
  end
end
