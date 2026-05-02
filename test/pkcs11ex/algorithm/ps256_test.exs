defmodule Pkcs11ex.Algorithm.PS256Test do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Algorithm.PS256

  describe "behaviour contract" do
    test "alg/0 returns :PS256" do
      assert PS256.alg() == :PS256
    end

    test "compatible_key_types/0 is RSA only" do
      assert PS256.compatible_key_types() == [:rsa]
    end

    test "hash/0 is SHA-256" do
      assert PS256.hash() == :sha256
    end

    test "signing and verifying mechanism are CKM_SHA256_RSA_PKCS_PSS" do
      assert PS256.signing_mechanism() == :ck_sha256_rsa_pkcs_pss
      assert PS256.verifying_mechanism() == :ck_sha256_rsa_pkcs_pss
    end
  end

  describe "signature encoding" do
    test "encode_signature/2 is identity in :jose context" do
      sig = :crypto.strong_rand_bytes(256)
      assert {:ok, ^sig} = PS256.encode_signature(sig, :jose)
    end

    test "encode_signature/2 is identity in :der context" do
      sig = :crypto.strong_rand_bytes(256)
      assert {:ok, ^sig} = PS256.encode_signature(sig, :der)
    end

    test "decode_signature/2 is identity in both contexts" do
      sig = :crypto.strong_rand_bytes(256)
      assert {:ok, ^sig} = PS256.decode_signature(sig, :jose)
      assert {:ok, ^sig} = PS256.decode_signature(sig, :der)
    end
  end
end
