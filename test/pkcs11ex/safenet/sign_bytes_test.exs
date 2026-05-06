defmodule Pkcs11ex.SafeNet.SignBytesTest do
  @moduledoc """
  Layer-2 (`Pkcs11ex.sign_bytes/2`) coverage against a real SafeNet
  eToken — the next layer up from the raw NIF tests in
  `Pkcs11ex.SafeNet.SignTest`.

  Proves the production sign path works on real hardware:

      Pkcs11ex.sign_bytes(data, signer: {slot_ref, key_ref}, alg: :PS256)

  Routes through the slot supervisor + persistent session pool +
  Layer-2 algorithm adapter (PS256). The signature comes back
  binary-normalised (Layer 2 handles the Rustler `Vec<u8>` -> list
  conversion that bites direct NIF callers).

  Same env-var gating + load-time skip as `SignTest`. Run with:

      PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \\
        mix test --include safenet test/pkcs11ex/safenet/sign_bytes_test.exs
  """

  use ExUnit.Case, async: false

  @moduletag :safenet

  alias Pkcs11ex.Slot.Server
  alias Pkcs11ex.Test.SafeNet

  @pin System.get_env("PKCS11EX_SAFENET_PIN")
  @key_label System.get_env("PKCS11EX_SAFENET_KEY_LABEL")

  if @pin && @key_label do
    setup_all do
      cond do
        not SafeNet.driver_present?() ->
          {:skip, "SafeNet driver not at #{SafeNet.driver_path()}"}

        true ->
          with {:ok, mod} <- SafeNet.load_module(),
               {:ok, slot} <- SafeNet.detect_slot() do
            slot_ref = String.to_atom("safenet_test_#{System.unique_integer([:positive])}")

            slot_config = [
              type: :token,
              driver: SafeNet.driver_path(),
              slot_match: {:slot_id, slot.slot_id},
              pin_callback: nil,
              keys: [signing: [label: @key_label]],
              lazy: true,
              reauthentication: :prompt
            ]

            {:ok, _server} =
              start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: mod})

            Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

            {:ok, slot_ref: slot_ref, p11_module: mod, slot_id: slot.slot_id}
          else
            {:error, reason} ->
              {:skip, "SafeNet bootstrap failed: #{inspect(reason)}"}
          end
      end
    end

    test "sign_bytes/2 round-trips through Layer 2 + Slot.Server", ctx do
      payload = "pkcs11ex layer-2 safenet test #{System.unique_integer([:positive])}"

      assert {:ok, signature} =
               Pkcs11ex.sign_bytes(payload,
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 pin: @pin
               )

      # Layer 2 normalises the NIF's Vec<u8> return into a binary —
      # this is what production callers see.
      assert is_binary(signature)
      assert byte_size(signature) in [256, 384, 512]
    end

    # Note: there's no test here for the explicit-module form
    # `Pkcs11ex.sign_bytes(data, module: ..., slot_id: ..., pin: ...)`.
    # On real hardware, mixing the slot-ref form (which keeps a
    # persistent session via `Slot.Server`) with the explicit form
    # (which opens its own session per call) triggers
    # `CKR_USER_ALREADY_LOGGED_IN` from the token. The explicit
    # form is exercised in `sign_test.exs` against the raw NIF.

    test "verify_bytes/4 round-trips against the same token", ctx do
      payload = "pkcs11ex verify_bytes safenet test #{System.unique_integer([:positive])}"

      {:ok, signature} =
        Pkcs11ex.sign_bytes(payload,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          pin: @pin
        )

      # verify_bytes goes through Layer 2 -> NIF::verify with the
      # token's public key (no PIN required for verify).
      assert :ok =
               Pkcs11ex.verify_bytes(payload, signature,
                 module: ctx.p11_module,
                 slot_id: ctx.slot_id,
                 key_label: @key_label,
                 alg: :PS256
               )
    end

    test "tampered payload fails verify_bytes/4", ctx do
      payload = "pkcs11ex tamper layer-2 safenet test #{System.unique_integer([:positive])}"

      {:ok, signature} =
        Pkcs11ex.sign_bytes(payload,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          pin: @pin
        )

      result =
        Pkcs11ex.verify_bytes("tampered " <> payload, signature,
          module: ctx.p11_module,
          slot_id: ctx.slot_id,
          key_label: @key_label,
          alg: :PS256
        )

      # Verify rejects via either {:error, _} or {:ok, false}-mapped
      # error class depending on the cryptoki driver's behaviour on
      # signature mismatch.
      refute result == :ok,
             "Tampered payload incorrectly accepted by verify_bytes/4 — driver bug or test bug"
    end
  else
    test "skipped — supply PKCS11EX_SAFENET_PIN and PKCS11EX_SAFENET_KEY_LABEL to run" do
      IO.puts(
        "[skip] Pkcs11ex.SafeNet.SignBytesTest — env vars required " <>
          "(see test/pkcs11ex/safenet/sign_test.exs for setup)."
      )
    end
  end
end
