defmodule Pkcs11ex.Slot.PinCallbackTest do
  @moduledoc """
  Tests for the `:pin_callback` config flow and `Pkcs11ex.PIN.with_pin/3`.

  Uses an Agent as a controllable PIN source so tests can verify exactly when
  and how often the callback was invoked (the key property: invoked on first
  login only, not on every sign).
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server

  defmodule PinAgent do
    @moduledoc false
    use Agent

    def start_link(opts) do
      Agent.start_link(
        fn -> %{pin: opts[:pin] || "1234", calls: 0, response: opts[:response] || :ok} end,
        name: __MODULE__
      )
    end

    def fetch do
      Agent.get_and_update(__MODULE__, fn s ->
        {build_response(s), %{s | calls: s.calls + 1}}
      end)
    end

    def calls, do: Agent.get(__MODULE__, & &1.calls)

    defp build_response(%{response: :ok, pin: pin}), do: {:ok, pin}
    defp build_response(%{response: response}), do: response
  end

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
    token_label = "pkcs11ex-pincb-#{suffix}"
    key_label = "pkcs11ex-pincb-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)

    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("pin_test_#{suffix}")

    {:ok,
     slot_ref: slot_ref,
     driver: driver,
     token_label: token_label,
     key_label: key_label,
     pin: user_pin,
     pkcs11_module: module}
  end

  defp slot_config(driver, token_label, key_label, pin_callback) do
    [
      type: :token,
      driver: driver,
      slot_match: {:token_label, token_label},
      pin_callback: pin_callback,
      keys: [signing: [label: key_label]],
      lazy: true,
      reauthentication: :prompt
    ]
  end

  # ---------- pin_callback config flow ----------

  describe ":pin_callback config" do
    test "invokes callback on first sign, not subsequent ones", ctx do
      start_supervised!({PinAgent, pin: ctx.pin})

      slot_config =
        slot_config(ctx.driver, ctx.token_label, ctx.key_label, {PinAgent, :fetch, []})

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      assert PinAgent.calls() == 0

      assert {:ok, _sig} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "first")

      assert PinAgent.calls() == 1

      # Second sign reuses the logged-in session — callback NOT re-invoked.
      assert {:ok, _sig} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "second")

      assert PinAgent.calls() == 1
    end

    test "callback returning {:error, _} surfaces as :pin_required", ctx do
      start_supervised!({PinAgent, pin: ctx.pin, response: {:error, :prompt_cancelled}})

      slot_config =
        slot_config(ctx.driver, ctx.token_label, ctx.key_label, {PinAgent, :fetch, []})

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      assert {:error, :prompt_cancelled} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "x")

      # Callback was attempted (and failed), state stays :open (session opened
      # but no successful login).
      assert PinAgent.calls() == 1
    end

    test "callback raising surfaces wrapped in :pin_callback_raised", ctx do
      defmodule RaisingPinCallback do
        def fetch, do: raise("vault unreachable")
      end

      slot_config =
        slot_config(ctx.driver, ctx.token_label, ctx.key_label, {RaisingPinCallback, :fetch, []})

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      assert {:error, {:pin_callback_raised, _msg}} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "x")
    end

    test "no pin_callback and no opts[:pin] returns :pin_required", ctx do
      slot_config = slot_config(ctx.driver, ctx.token_label, ctx.key_label, nil)

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      assert {:error, :pin_required} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "x")
    end

    test "opts[:pin] takes priority over a configured callback", ctx do
      start_supervised!({PinAgent, pin: "wrong-pin"})

      slot_config =
        slot_config(ctx.driver, ctx.token_label, ctx.key_label, {PinAgent, :fetch, []})

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      # Explicit PIN wins; callback never invoked.
      assert {:ok, _sig} =
               Server.sign(
                 ctx.slot_ref,
                 ctx.key_label,
                 :ck_sha256_rsa_pkcs_pss,
                 "x",
                 pin: ctx.pin
               )

      assert PinAgent.calls() == 0
    end
  end

  # ---------- Pkcs11ex.PIN.with_pin/3 ----------

  describe "Pkcs11ex.PIN.with_pin/3" do
    test "logs in for the closure and logs out afterwards", ctx do
      slot_config = slot_config(ctx.driver, ctx.token_label, ctx.key_label, nil)

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      result =
        Pkcs11ex.PIN.with_pin(ctx.slot_ref, ctx.pin, fn ->
          Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "scoped")
        end)

      assert {:ok, sig} = result
      assert byte_size(sig) == 256

      # After with_pin returns, the slot is logged out — next sign without
      # pin or callback fails.
      assert :open = Server.status(ctx.slot_ref)

      assert {:error, :pin_required} =
               Server.sign(ctx.slot_ref, ctx.key_label, :ck_sha256_rsa_pkcs_pss, "after")
    end

    test "logs out even when the closure raises", ctx do
      slot_config = slot_config(ctx.driver, ctx.token_label, ctx.key_label, nil)

      {:ok, _} =
        start_supervised({Server, slot_ref: ctx.slot_ref, slot_config: slot_config, module: ctx.pkcs11_module})

      assert_raise RuntimeError, "kaboom", fn ->
        Pkcs11ex.PIN.with_pin(ctx.slot_ref, ctx.pin, fn -> raise "kaboom" end)
      end

      assert :open = Server.status(ctx.slot_ref)
    end
  end
end
