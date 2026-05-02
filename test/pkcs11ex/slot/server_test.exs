defmodule Pkcs11ex.Slot.ServerTest do
  @moduledoc """
  End-to-end tests for `Pkcs11ex.Slot.Server` against SoftHSM2.

  Each test starts its own `Pkcs11ex.Slot.Server` directly (not under the
  application supervisor) so we can drive each test's slot config without
  touching the runtime config — this keeps SoftHSM mutation isolated to the
  test scope.

  Provisioning mirrors the Phase 1 SoftHSM tests: unique-labeled token via
  `softhsm2-util`, RSA-2048 keypair via `Pkcs11ex.Native.generate_rsa_keypair/5`.
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
    token_label = "pkcs11ex-slotsrv-#{suffix}"
    key_label = "pkcs11ex-slotsrv-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)
    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    # The same shared `module` resource is handed to the Slot.Server under test
    # — PKCS#11 only allows one `C_Initialize` per process per `.so`. We use
    # the slot id reported by softhsm2-util directly rather than relying on
    # `list_slots/1`: SoftHSM caches the slot list at C_Initialize time, so
    # tokens created later don't appear in subsequent enumerations.
    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("test_slot_#{suffix}")

    slot_config = [
      type: :token,
      driver: driver,
      slot_match: {:token_label, token_label},
      pin_callback: nil,
      keys: [signing: [label: key_label]],
      lazy: true,
      reauthentication: :prompt
    ]

    {:ok,
     slot_ref: slot_ref,
     slot_config: slot_config,
     pin: user_pin,
     key_label: key_label,
     token_label: token_label,
     pkcs11_module: module}
  end

  describe "lifecycle" do
    test "lazy slot starts in :uninitialized and opens on first sign", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _pid} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      assert :uninitialized = Server.status(slot_ref)

      assert {:ok, sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "hello", pin: pin)
      assert byte_size(sig) == 256

      assert :logged_in = Server.status(slot_ref)
    end

    test "subsequent signs reuse the logged-in session (no PIN needed after first)", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      {:ok, _sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first", pin: pin)
      # No :pin opt on second call — session is already logged in.
      {:ok, _sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "second", [])

      assert :logged_in = Server.status(slot_ref)
    end

    test "logout drops to :open and the next sign needs the PIN again", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      {:ok, _sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "x", pin: pin)
      :ok = Server.logout(slot_ref)
      assert :open = Server.status(slot_ref)

      assert {:error, :pin_required} =
               Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "y", [])

      assert {:ok, _sig} =
               Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "y", pin: pin)
    end
  end

  describe "sign + verify round trip" do
    test "sign followed by verify on the same slot succeeds", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      payload = "round trip via slot server"

      {:ok, sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, payload, pin: pin)
      assert :ok = Server.verify(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, payload, sig)
    end

    test "tampered payload returns :signature_invalid", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      payload = "round trip via slot server"
      {:ok, sig} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, payload, pin: pin)

      assert {:error, :signature_invalid} =
               Server.verify(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "tampered " <> payload, sig)
    end
  end

  describe "concurrency: serial access to a token slot" do
    test "concurrent sign requests serialize through the GenServer", %{
      slot_ref: slot_ref,
      slot_config: slot_config,
      pin: pin,
      key_label: key_label,
      pkcs11_module: pkcs11_module
    } do
      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: pkcs11_module})

      # Warm up — log in once so subsequent calls don't all try to login.
      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "warmup", pin: pin)

      results =
        1..16
        |> Task.async_stream(
          fn i ->
            Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "p#{i}", [])
          end,
          max_concurrency: 8,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, r} -> r end)

      Enum.each(results, fn r ->
        assert {:ok, sig} = r
        assert byte_size(sig) == 256
      end)
    end
  end
end
