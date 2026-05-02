defmodule Pkcs11exTest do
  use ExUnit.Case, async: true

  doctest Pkcs11ex

  describe "Rustler bridge" do
    test "native_version/0 reaches the NIF and returns the crate version" do
      version = Pkcs11ex.native_version()
      assert is_binary(version)
      assert version =~ ~r/^\d+\.\d+\.\d+/
    end
  end
end
