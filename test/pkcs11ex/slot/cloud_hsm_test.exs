defmodule Pkcs11ex.Slot.CloudHSMTest do
  @moduledoc """
  `:cloud_hsm` slot type — login is skipped entirely; the open session is the
  authenticated context (cloud HSMs authenticate via cloud credentials, not
  PKCS#11 user PIN).

  Uses SoftHSM as a stand-in to exercise the no-login control flow. SoftHSM
  itself requires login for sign-with-private-key, so the actual sign call
  surfaces a `CKR_USER_NOT_LOGGED_IN` from cryptoki — which is *exactly* what
  this test wants to assert: the failure came from the HSM, not from our
  login machinery (the login machinery was bypassed). On a real cloud HSM
  (libkmsp11), the sign succeeds because cloud auth is already in place.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server

  @user_pin "1234"
  @so_pin "1234"

  setup_all do
    driver = Pkcs11ex.Test.SoftHSM.driver_path()
    softhsm2_util = System.find_executable("softhsm2-util")

    cond do
      is_nil(driver) ->
        {:skip, "SoftHSM2 driver not installed"}

      is_nil(softhsm2_util) ->
        {:skip, "softhsm2-util CLI not on PATH"}

      true ->
        suffix = System.unique_integer([:positive])
        token_label = "pkcs11ex-cloudhsm-#{suffix}"
        key_label = "pkcs11ex-cloudhsm-key-#{suffix}"

        slot_id =
          Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, @user_pin, @so_pin)

        module = Pkcs11ex.Test.SoftHSM.module()
        on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

        # Generate a keypair while we're still allowed to log in (we use the
        # token PIN here just to provision; afterwards the slot is run as
        # :cloud_hsm where login is bypassed).
        {:ok, true} = Native.generate_rsa_keypair(module, slot_id, @user_pin, key_label, 2048)

        slot_ref = String.to_atom("cloudhsm_test_#{suffix}")

        slot_config = [
          type: :cloud_hsm,
          driver: driver,
          slot_match: {:slot_id, slot_id},
          # pin_callback intentionally omitted — :cloud_hsm forbids it
          # (Pkcs11ex.Config rule 5 catches it at boot for production paths).
          keys: [signing: [label: key_label]],
          lazy: false,
          reauthentication: :prompt
        ]

        {:ok, _} =
          start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

        {:ok, slot_ref: slot_ref, key_label: key_label}
    end
  end

  describe ":cloud_hsm slot — login bypass" do
    test "Slot.login/2 returns :no_pin_required", %{slot_ref: slot_ref} do
      assert {:error, :no_pin_required} = Server.login(slot_ref, "1234")
    end

    test "Slot.logout/1 is a no-op", %{slot_ref: slot_ref} do
      assert :ok = Server.logout(slot_ref)
    end

    test "sign without :pin and without pin_callback never returns :pin_required", %{
      slot_ref: slot_ref,
      key_label: key_label
    } do
      # If login were being attempted, we'd see :pin_required (no PIN supplied
      # and no callback configured). The :cloud_hsm bypass means we go
      # straight to the C_Sign call, which on SoftHSM fails with
      # CKR_USER_NOT_LOGGED_IN. On a real cloud HSM (libkmsp11), this
      # would succeed. The point of this assertion is the *kind* of error.
      result = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "data")

      # The login machinery wasn't engaged — the only failure mode that
      # could surface :pin_required would have come from there.
      refute match?({:error, :pin_required}, result)
      refute match?({:error, {:pin_callback_raised, _}}, result)
    end

    test "status stays :open after sign attempt (never :logged_in)", %{
      slot_ref: slot_ref,
      key_label: key_label
    } do
      _ = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "data")
      # :cloud_hsm slots never go to :logged_in — login was bypassed.
      refute Server.status(slot_ref) == :logged_in
    end
  end
end
