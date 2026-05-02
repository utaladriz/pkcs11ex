defmodule Pkcs11ex.Slot.TimeoutTest do
  @moduledoc """
  Inactivity timeout + `:reauthentication` policy.

  Uses a tiny `:session_timeout` (50 ms) and `Process.sleep/1` to advance
  past it. The Slot.Server reads the global timeout lazily on each sign so
  test mutation via `Application.put_env/3` takes effect immediately.

  Per `api.md` §1.3 + §4.2:
    * `:reauthentication: :prompt` — auto re-runs the PIN priority chain
      (opts[:pin] → pin_callback) on the next sign after expiry.
    * `:reauthentication: :fail`   — returns `:reauthentication_required`;
      caller must call `Pkcs11ex.Slot.login/2` explicitly.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server

  @short_timeout_ms 50
  @sleep_past_timeout 80

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
    token_label = "pkcs11ex-tmout-#{suffix}"
    key_label = "pkcs11ex-tmout-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)

    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("timeout_test_#{suffix}")

    original_timeout = Application.get_env(:pkcs11ex, :session_timeout)
    Application.put_env(:pkcs11ex, :session_timeout, @short_timeout_ms)
    on_exit(fn -> Application.put_env(:pkcs11ex, :session_timeout, original_timeout) end)

    {:ok, slot_ref: slot_ref, pkcs11_module: module, pin: user_pin, key_label: key_label, token_label: token_label}
  end

  defp slot_config(driver, token_label, key_label, opts) do
    [
      type: :token,
      driver: driver,
      slot_match: {:token_label, token_label},
      pin_callback: opts[:pin_callback],
      keys: [signing: [label: key_label]],
      lazy: true,
      reauthentication: opts[:reauthentication] || :prompt
    ]
  end

  describe ":prompt mode" do
    test "next sign after timeout re-uses opts[:pin]",
         %{
           slot_ref: slot_ref,
           pkcs11_module: module,
           pin: pin,
           key_label: key_label
         } = ctx do
      slot_config =
        slot_config(driver(), ctx.token_label, key_label, reauthentication: :prompt)

      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first", pin: pin)
      assert :logged_in = Server.status(slot_ref)

      Process.sleep(@sleep_past_timeout)

      assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "second", pin: pin)
      assert :logged_in = Server.status(slot_ref)
    end

    test "next sign after timeout re-invokes the configured pin_callback",
         %{
           slot_ref: slot_ref,
           pkcs11_module: module,
           pin: pin,
           key_label: key_label
         } = ctx do
      {:ok, _} = start_supervised({CallbackPinAgent, pin})

      slot_config =
        slot_config(driver(), ctx.token_label, key_label,
          pin_callback: {CallbackPinAgent, :fetch, []},
          reauthentication: :prompt
        )

      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first")
      assert CallbackPinAgent.calls() == 1

      Process.sleep(@sleep_past_timeout)

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "second")
      assert CallbackPinAgent.calls() == 2
    end

    test "callback failure during reauth surfaces and leaves slot in :open",
         %{
           slot_ref: slot_ref,
           pkcs11_module: module,
           pin: pin,
           key_label: key_label
         } = ctx do
      {:ok, _} = start_supervised({CallbackPinAgent, pin})

      slot_config =
        slot_config(driver(), ctx.token_label, key_label,
          pin_callback: {CallbackPinAgent, :fetch, []},
          reauthentication: :prompt
        )

      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first")
      Process.sleep(@sleep_past_timeout)

      # Flip the callback to error mode before the next sign.
      :ok = CallbackPinAgent.set_response({:error, :prompt_cancelled})

      assert {:error, :prompt_cancelled} =
               Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "after-expiry")

      assert :open = Server.status(slot_ref)
    end
  end

  describe ":fail mode" do
    test "next sign after timeout returns :reauthentication_required, drops to :open",
         %{
           slot_ref: slot_ref,
           pkcs11_module: module,
           pin: pin,
           key_label: key_label
         } = ctx do
      slot_config = slot_config(driver(), ctx.token_label, key_label, reauthentication: :fail)

      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first", pin: pin)
      assert :logged_in = Server.status(slot_ref)

      Process.sleep(@sleep_past_timeout)

      assert {:error, :reauthentication_required} =
               Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "after-expiry", pin: pin)

      assert :open = Server.status(slot_ref)
    end

    test "explicit Slot.login/2 restores :logged_in after :reauthentication_required",
         %{
           slot_ref: slot_ref,
           pkcs11_module: module,
           pin: pin,
           key_label: key_label
         } = ctx do
      slot_config = slot_config(driver(), ctx.token_label, key_label, reauthentication: :fail)

      {:ok, _} =
        start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

      {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "first", pin: pin)
      Process.sleep(@sleep_past_timeout)

      assert {:error, :reauthentication_required} =
               Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "x")

      :ok = Server.login(slot_ref, pin)
      assert :logged_in = Server.status(slot_ref)

      assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "after-relogin")
    end
  end

  defp driver, do: Pkcs11ex.Test.SoftHSM.driver_path()
end

defmodule CallbackPinAgent do
  @moduledoc false
  use Agent

  def start_link(pin) do
    Agent.start_link(fn -> %{pin: pin, response: :ok, calls: 0} end, name: __MODULE__)
  end

  def fetch do
    Agent.get_and_update(__MODULE__, fn s ->
      response =
        case s.response do
          :ok -> {:ok, s.pin}
          other -> other
        end

      {response, %{s | calls: s.calls + 1}}
    end)
  end

  def calls, do: Agent.get(__MODULE__, & &1.calls)
  def set_response(r), do: Agent.update(__MODULE__, &%{&1 | response: r})
end
