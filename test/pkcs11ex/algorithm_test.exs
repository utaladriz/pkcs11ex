defmodule Pkcs11ex.AlgorithmTest do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Algorithm

  describe "lookup/1" do
    test "resolves a registered built-in" do
      assert {:ok, Pkcs11ex.Algorithm.PS256} = Algorithm.lookup(:PS256)
    end

    test "returns :unsupported_alg for an unknown atom" do
      assert {:error, :unsupported_alg} = Algorithm.lookup(:HS256)
    end

    test "honors the runtime :algorithms registry override" do
      # Register a stub adapter for an unused alg.
      Application.put_env(:pkcs11ex, :algorithms, %{Custom: __MODULE__.Stub})

      try do
        assert {:ok, __MODULE__.Stub} = Algorithm.lookup(:Custom)
      after
        Application.delete_env(:pkcs11ex, :algorithms)
      end
    end
  end

  defmodule Stub do
    @moduledoc false
    @behaviour Pkcs11ex.Algorithm

    @impl true
    def alg, do: :Custom
    @impl true
    def compatible_key_types, do: [:rsa]
    @impl true
    def hash, do: :sha256
    @impl true
    def signing_mechanism, do: :ck_sha256_rsa_pkcs_pss
    @impl true
    def verifying_mechanism, do: :ck_sha256_rsa_pkcs_pss
    @impl true
    def encode_signature(sig, _), do: {:ok, sig}
    @impl true
    def decode_signature(sig, _), do: {:ok, sig}
  end
end
