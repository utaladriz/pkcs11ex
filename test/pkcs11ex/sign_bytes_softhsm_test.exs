defmodule Pkcs11ex.SignBytesSofthsmTest do
  @moduledoc """
  End-to-end PS256 sign + verify against SoftHSM2.

  Provisions a fresh token + RSA-2048 keypair using `softhsm2-util` (token init)
  and the test-only `Native.generate_rsa_keypair/5` NIF (key gen). Uses a unique
  per-run label so re-runs don't collide; deletes the token in `on_exit/1`.

  This test mutates the user's default SoftHSM2 token store
  (`SOFTHSM2_CONF` if set, or the package default). On macOS in particular,
  setting `SOFTHSM2_CONF` from inside Elixir does not reach `dlopen`'d
  libraries due to a long-standing libc env-table behavior, so we deliberately
  inherit whatever the shell launched the BEAM with.

  The `:softhsm` tag is excluded automatically by `test_helper.exs` when the
  driver isn't found.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native

  setup_all do
    driver = Pkcs11ex.Test.SoftHSM.driver_path()
    softhsm2_util = System.find_executable("softhsm2-util")

    cond do
      is_nil(driver) ->
        {:skip, "SoftHSM2 driver not installed"}

      is_nil(softhsm2_util) ->
        {:skip, "softhsm2-util CLI not on PATH"}

      true ->
        {:ok, ctx} = bootstrap(driver, softhsm2_util)
        Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
        {:ok, ctx}
    end
  end

  defp bootstrap(driver, softhsm2_util) do
    suffix = System.unique_integer([:positive])
    token_label = "pkcs11ex-test-#{suffix}"
    key_label = "pkcs11ex-test-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    {init_output, 0} =
      System.cmd(
        softhsm2_util,
        [
          "--init-token",
          "--free",
          "--label",
          token_label,
          "--pin",
          user_pin,
          "--so-pin",
          so_pin
        ],
        stderr_to_stdout: true
      )

    on_exit(fn ->
      _ =
        System.cmd(
          softhsm2_util,
          ["--delete-token", "--token", token_label],
          stderr_to_stdout: true
        )
    end)

    {:ok, pkcs11_module} = Native.module_load(driver)
    {:ok, slots} = Native.list_slots(pkcs11_module)

    slot_id =
      case Enum.find(slots, &(&1.token_label == token_label)) do
        %{slot_id: id} ->
          id

        nil ->
          raise """
          Token #{inspect(token_label)} not found by NIF after init.
          softhsm2-util output: #{init_output}
          slots seen by NIF: #{inspect(slots)}
          (See SOFTHSM2_CONF in your shell — the BEAM-side process env may not reach `dlopen`'d libs.)
          """
      end

    {:ok, true} = Native.generate_rsa_keypair(pkcs11_module, slot_id, user_pin, key_label, 2048)

    {:ok, pkcs11_module: pkcs11_module, slot_id: slot_id, pin: user_pin, key_label: key_label, token_label: token_label}
  end

  test "signs and verifies a payload with PS256", %{
    pkcs11_module: pkcs11_module,
    slot_id: slot_id,
    pin: pin,
    key_label: key_label
  } do
    payload = "hello pkcs11ex"

    assert {:ok, signature} =
             Pkcs11ex.sign_bytes(payload,
               module: pkcs11_module,
               slot_id: slot_id,
               pin: pin,
               key_label: key_label,
               alg: :PS256
             )

    # RSA-2048 PSS signature is 256 bytes.
    assert byte_size(signature) == 256

    assert :ok =
             Pkcs11ex.verify_bytes(payload, signature,
               module: pkcs11_module,
               slot_id: slot_id,
               key_label: key_label,
               alg: :PS256
             )
  end

  test "tampered payload fails verification with :signature_invalid", %{
    pkcs11_module: pkcs11_module,
    slot_id: slot_id,
    pin: pin,
    key_label: key_label
  } do
    payload = "hello pkcs11ex"

    {:ok, signature} =
      Pkcs11ex.sign_bytes(payload,
        module: pkcs11_module,
        slot_id: slot_id,
        pin: pin,
        key_label: key_label,
        alg: :PS256
      )

    assert {:error, :signature_invalid} =
             Pkcs11ex.verify_bytes("tampered " <> payload, signature,
               module: pkcs11_module,
               slot_id: slot_id,
               key_label: key_label,
               alg: :PS256
             )
  end

  test "missing key surfaces :key_not_found", %{
    pkcs11_module: pkcs11_module,
    slot_id: slot_id,
    pin: pin
  } do
    assert {:error, {:key_not_found, "no-such-key"}} =
             Pkcs11ex.sign_bytes("data",
               module: pkcs11_module,
               slot_id: slot_id,
               pin: pin,
               key_label: "no-such-key",
               alg: :PS256
             )
  end
end
