defmodule Pkcs11ex.SafeNet.ProbeTest do
  @moduledoc """
  Read-only smoke tests against a real SafeNet eToken.

  All assertions here are **PIN-free** — they only call public
  PKCS#11 operations (`C_GetSlotList`, `C_GetSlotInfo`,
  `C_GetTokenInfo`-equivalents) that don't decrement the token's
  PIN-attempt counter. Safe to run any time the token is plugged in.

  Opt in:

      mix test --include safenet test/pkcs11ex/safenet/

  Or by file:

      mix test --include safenet test/pkcs11ex/safenet/probe_test.exs

  Requires:

    * SafeNet eToken Authentication Client driver at
      `/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib`
      (or `PKCS11EX_SAFENET_LIB`).
    * The eToken physically plugged in.
  """

  use ExUnit.Case, async: false

  @moduletag :safenet

  alias Pkcs11ex.Native
  alias Pkcs11ex.Test.SafeNet

  setup_all do
    cond do
      not SafeNet.driver_present?() ->
        {:skip, "SafeNet driver not at #{SafeNet.driver_path()}"}

      true ->
        case SafeNet.load_module() do
          {:ok, mod} ->
            # ExUnit's context already has a `:module` key (the test
            # module name), so we use `:p11_module` to avoid clobbering.
            {:ok, p11_module: mod}

          {:error, reason} ->
            {:skip, "Driver load failed: #{inspect(reason)}"}
        end
    end
  end

  test "driver load returned a usable handle", %{p11_module: mod} do
    # The NIF returns an opaque resource (Erlang reference) that the
    # subsequent NIF calls accept.
    assert is_reference(mod)
  end

  test "list_slots/1 reports at least one slot with a token present", %{p11_module: mod} do
    {:ok, slots} = Native.list_slots(mod)
    present = Enum.filter(slots, & &1.token_present)

    assert present != [],
           "no SafeNet slot reports token_present=true. Is the eToken plugged in? " <>
             "Total slots: #{length(slots)}"

    # eToken's PKCS#11 module always reports SafeNet, Inc. as
    # manufacturer. If this drifts, the driver moved.
    Enum.each(present, fn slot ->
      assert slot.manufacturer =~ ~r/SafeNet/,
             "Unexpected manufacturer #{inspect(slot.manufacturer)} — wrong driver?"
    end)
  end

  test "auto-discovered slot has a non-empty token_label", %{p11_module: _mod} do
    {:ok, slot} = SafeNet.detect_slot()
    assert slot.token_present
    # Empty label is technically legal but suggests an uninitialised
    # token, which we'd want to know about up front.
    assert slot.token_label != "",
           "Token label is empty — token may not be initialised"
  end

  test "PKCS11EX_SAFENET_SLOT override is honoured" do
    System.put_env("PKCS11EX_SAFENET_SLOT", "42")
    on_exit(fn -> System.delete_env("PKCS11EX_SAFENET_SLOT") end)

    assert {:ok, %{slot_id: 42}} = SafeNet.detect_slot()
  end
end
