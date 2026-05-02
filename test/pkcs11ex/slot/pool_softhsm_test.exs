defmodule Pkcs11ex.Slot.PoolSoftHSMTest do
  @moduledoc """
  Integration test for the multi-worker pool against a real SoftHSM2 slot.

  Starts two `Slot.Server` workers under the same `slot_ref`, registers
  the pool size with `Pkcs11ex.Slot.Pool`, then signs N times and asserts
  via telemetry that signs were distributed round-robin across workers.

  Doesn't go through `Pkcs11ex.SlotSupervisor` — that wiring is small
  enough to verify by reading the supervisor; here we test the runtime
  dispatch + worker-side independent session lifecycles.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.{Pool, Server}

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
    token_label = "pkcs11ex-pool-#{suffix}"
    key_label = "pkcs11ex-pool-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)
    on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

    module = Pkcs11ex.Test.SoftHSM.module()
    {:ok, true} = Native.generate_rsa_keypair(module, slot_id, user_pin, key_label, 2048)

    slot_ref = String.to_atom("pool_test_slot_#{suffix}")

    # Soft HSM slots can pool — login state is shared at the token level
    # in SoftHSM (login on one session implicitly logs in others), so all
    # workers see logged-in state after worker 1 logs in OR each
    # independently logs in via opts[:pin].
    slot_config = [
      type: :soft_hsm,
      driver: driver,
      slot_match: {:token_label, token_label},
      pin_callback: nil,
      keys: [signing: [label: key_label]],
      lazy: true,
      session_pool_size: 2,
      reauthentication: :prompt
    ]

    {:ok,
     slot_ref: slot_ref,
     slot_config: slot_config,
     pin: user_pin,
     key_label: key_label,
     pkcs11_module: module}
  end

  test "two workers handle signs round-robin and telemetry reflects it", %{
    slot_ref: slot_ref,
    slot_config: slot_config,
    pin: pin,
    key_label: key_label,
    pkcs11_module: module
  } do
    # Two independent workers, each with its own session against the same
    # SoftHSM slot.
    {:ok, _pid1} =
      start_supervised(
        {Server,
         slot_ref: slot_ref,
         worker_index: 1,
         slot_config: slot_config,
         module: module},
        id: {Server, slot_ref, 1}
      )

    {:ok, _pid2} =
      start_supervised(
        {Server,
         slot_ref: slot_ref,
         worker_index: 2,
         slot_config: slot_config,
         module: module},
        id: {Server, slot_ref, 2}
      )

    Pool.register(slot_ref, 2)
    on_exit(fn -> Pool.register(slot_ref, 1) end)

    parent = self()
    handler_id = "pool-test-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler_id,
      [:pkcs11ex, :slot, :sign],
      fn _event, _measurements, metadata, _ ->
        send(parent, {:sign_observed, metadata.slot_ref, metadata.worker_index})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    # Four signs — round-robin across two workers should land 2 on each.
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "msg-1", pin: pin)
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "msg-2", pin: pin)
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "msg-3", pin: pin)
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "msg-4", pin: pin)

    indices = collect_observations(slot_ref, 4, [])
    assert length(indices) == 4

    counts = Enum.frequencies(indices)
    assert counts == %{1 => 2, 2 => 2}, "expected even distribution, got #{inspect(counts)}"
  end

  test "each worker maintains its own login state independently", %{
    slot_ref: slot_ref,
    slot_config: slot_config,
    pin: pin,
    key_label: key_label,
    pkcs11_module: module
  } do
    # Provision two workers; verify both reach :logged_in independently
    # after their respective first sign call.
    {:ok, _} =
      start_supervised(
        {Server,
         slot_ref: slot_ref, worker_index: 1, slot_config: slot_config, module: module},
        id: {Server, slot_ref, 1}
      )

    {:ok, _} =
      start_supervised(
        {Server,
         slot_ref: slot_ref, worker_index: 2, slot_config: slot_config, module: module},
        id: {Server, slot_ref, 2}
      )

    Pool.register(slot_ref, 2)
    on_exit(fn -> Pool.register(slot_ref, 1) end)

    # Two signs — round-robin lands one on each. Both workers must
    # independently login (via opts[:pin]) and reach :logged_in.
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "x", pin: pin)
    assert {:ok, _} = Server.sign(slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "y", pin: pin)

    pid1 = GenServer.whereis(Server.via({slot_ref, 1}))
    pid2 = GenServer.whereis(Server.via({slot_ref, 2}))

    assert is_pid(pid1) and is_pid(pid2) and pid1 != pid2

    s1 = :sys.get_state(pid1)
    s2 = :sys.get_state(pid2)

    assert s1.state == :logged_in
    assert s2.state == :logged_in
    assert s1.session != s2.session
  end

  defp collect_observations(_slot_ref, 0, acc), do: Enum.reverse(acc)

  defp collect_observations(slot_ref, n, acc) do
    receive do
      {:sign_observed, ^slot_ref, idx} -> collect_observations(slot_ref, n - 1, [idx | acc])
    after
      2_000 -> Enum.reverse(acc)
    end
  end
end
