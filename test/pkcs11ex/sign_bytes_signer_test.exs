defmodule Pkcs11ex.SignBytesSignerTest do
  @moduledoc """
  `Pkcs11ex.sign_bytes/2` signer-ref path:

      Pkcs11ex.sign_bytes(payload,
        signer: {:my_slot, :signing},
        alg: :PS256
      )

  Routes through `Pkcs11ex.Slot.Server` for the configured slot, which holds
  the persistent session. Layer-2 callers no longer need to pass module /
  slot_id / key_label / pin themselves.

  Also exercises `Pkcs11ex.JWS.sign/2` with `:signer` to confirm Layer 3
  format adapters get the new ergonomics for free.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server

  setup_all do
    driver = Pkcs11ex.Test.SoftHSM.driver_path()
    softhsm2_util = System.find_executable("softhsm2-util")

    cond do
      is_nil(driver) -> {:skip, "SoftHSM2 driver not installed"}
      is_nil(softhsm2_util) -> {:skip, "softhsm2-util CLI not on PATH"}
      true -> {:ok, driver: driver, softhsm2_util: softhsm2_util}
    end
  end

  setup %{driver: driver, softhsm2_util: softhsm2_util} do
    suffix = System.unique_integer([:positive])
    token_label = "pkcs11ex-signer-#{suffix}"
    key_label = "pkcs11ex-signer-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)

    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("signer_test_#{suffix}")

    slot_config = [
      type: :token,
      driver: driver,
      slot_match: {:token_label, token_label},
      pin_callback: nil,
      keys: [signing: [label: key_label]],
      lazy: true,
      reauthentication: :prompt
    ]

    {:ok, _} =
      start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

    {:ok,
     slot_ref: slot_ref,
     slot_id: slot_id,
     pkcs11_module: module,
     pin: user_pin,
     key_label: key_label,
     token_label: token_label}
  end

  # ---------- Pkcs11ex.sign_bytes(:signer) ----------

  describe "Pkcs11ex.sign_bytes/2 — :signer path" do
    test "signs through the slot's persistent session", ctx do
      assert {:ok, sig} =
               Pkcs11ex.sign_bytes("hello signer",
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 pin: ctx.pin
               )

      assert is_binary(sig)
      assert byte_size(sig) == 256
      assert :logged_in = Server.status(ctx.slot_ref)
    end

    test "subsequent signs reuse the logged-in session — no PIN needed", ctx do
      {:ok, _} =
        Pkcs11ex.sign_bytes("first",
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          pin: ctx.pin
        )

      assert {:ok, _sig} =
               Pkcs11ex.sign_bytes("second",
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256
               )
    end

    test "unknown slot_ref → :slot_not_found", ctx do
      assert {:error, :slot_not_found} =
               Pkcs11ex.sign_bytes("x",
                 signer: {:no_such_slot, :signing},
                 alg: :PS256,
                 pin: ctx.pin
               )
    end

    test "unknown key_ref → :key_not_found", ctx do
      assert {:error, {:key_not_found, :nope}} =
               Pkcs11ex.sign_bytes("x",
                 signer: {ctx.slot_ref, :nope},
                 alg: :PS256,
                 pin: ctx.pin
               )
    end

    test "disallowed alg is rejected before signer resolution", ctx do
      assert {:error, :disallowed_alg} =
               Pkcs11ex.sign_bytes("x",
                 signer: {ctx.slot_ref, :signing},
                 alg: :ES256,
                 pin: ctx.pin
               )
    end

    test "no :signer and no :module → :no_signer_specified" do
      assert {:error, :no_signer_specified} = Pkcs11ex.sign_bytes("x", alg: :PS256)
    end
  end

  # ---------- JWS via :signer ----------

  describe "Pkcs11ex.JWS.sign/2 — :signer path" do
    test "produces a verifiable JWS via the signer-ref ergonomics", ctx do
      # Build a wrapper cert containing the SoftHSM public key so the
      # software-side verify in JWS.verify can check the signature.
      {:ok, {modulus_list, exponent_list}} =
        normalize_pair(Native.export_rsa_public_key(ctx.pkcs11_module, slot_id_for(ctx), ctx.key_label))

      modulus_bin = IO.iodata_to_binary(modulus_list)
      exponent_bin = IO.iodata_to_binary(exponent_list)

      pubkey =
        {:RSAPublicKey, :binary.decode_unsigned(modulus_bin, :big), :binary.decode_unsigned(exponent_bin, :big)}

      issuer_key = X509.PrivateKey.new_rsa(2048)
      issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=signer-test-issuer")
      leaf_cert = X509.Certificate.new(pubkey, "/CN=signer-test-leaf", issuer_cert, issuer_key)
      leaf_der = X509.Certificate.to_der(leaf_cert)

      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      payload = "jws via signer-ref"

      assert {:ok, jws} =
               Pkcs11ex.JWS.sign(payload,
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 pin: ctx.pin,
                 x5c: leaf_der
               )

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end
  end

  defp normalize_pair({:ok, pair}), do: {:ok, pair}
  defp normalize_pair({m, e}), do: {:ok, {m, e}}

  defp slot_id_for(ctx) do
    # The slot_id was captured at init time and stored in ctx; we no longer
    # need to enumerate slots here.
    ctx.slot_id
  end
end
