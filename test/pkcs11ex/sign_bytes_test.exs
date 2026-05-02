defmodule Pkcs11ex.SignBytesTest do
  use ExUnit.Case, async: false

  # ---------- Allowlist gate (no NIF needed) ----------

  describe "sign_bytes/2 — allowlist gate" do
    setup do
      original = Application.get_env(:pkcs11ex, :allowed_algs)
      on_exit(fn -> Application.put_env(:pkcs11ex, :allowed_algs, original) end)
      :ok
    end

    test "rejects :alg :none unconditionally" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:none])

      assert {:error, :disallowed_alg} =
               Pkcs11ex.sign_bytes("data",
                 alg: :none,
                 module: :unused,
                 slot_id: 0,
                 key_label: "x"
               )
    end

    test "rejects alg outside the configured allowlist" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

      assert {:error, :disallowed_alg} =
               Pkcs11ex.sign_bytes("data",
                 alg: :ES256,
                 module: :unused,
                 slot_id: 0,
                 key_label: "x"
               )
    end

    test "rejects missing :alg" do
      assert {:error, :missing_alg} =
               Pkcs11ex.sign_bytes("data",
                 module: :unused,
                 slot_id: 0,
                 key_label: "x"
               )
    end

    test "rejects unsupported alg even if allowlisted" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:HS256])

      assert {:error, :unsupported_alg} =
               Pkcs11ex.sign_bytes("data",
                 alg: :HS256,
                 module: :unused,
                 slot_id: 0,
                 key_label: "x"
               )
    end
  end

  describe "verify_bytes/3 — allowlist gate" do
    setup do
      original = Application.get_env(:pkcs11ex, :allowed_algs)
      on_exit(fn -> Application.put_env(:pkcs11ex, :allowed_algs, original) end)
      :ok
    end

    test "rejects disallowed alg before any NIF call" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

      assert {:error, :disallowed_alg} =
               Pkcs11ex.verify_bytes("data", <<0::256>>,
                 alg: :ES256,
                 module: :unused,
                 slot_id: 0,
                 key_label: "x"
               )
    end
  end
end
