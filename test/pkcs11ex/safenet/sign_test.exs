defmodule Pkcs11ex.SafeNet.SignTest do
  @moduledoc """
  PIN-gated sign tests against a real SafeNet eToken.

  Skipped unless **all** of these env vars are set at test load
  time:

    * `PKCS11EX_SAFENET_PIN` — user PIN. Stored in env only,
      not logged. Wrong PINs decrement SafeNet's attempt counter
      (default lock-out at 5 wrong tries) so be careful.
    * `PKCS11EX_SAFENET_KEY_LABEL` — `CKA_LABEL` of the signing
      key on the token. Look it up via the SafeNet Authentication
      Client GUI or `pkcs11-tool --module <driver> --list-objects
      --type pubkey` (OpenSC).

  Optional:

    * `PKCS11EX_SAFENET_MECHANISM` — atom name of the PKCS#11
      mechanism. Defaults to `ck_sha256_rsa_pkcs_pss` (PS256).
      Set to `ck_sha256_rsa_pkcs` for keys that only support
      PKCS#1 v1.5 (e.g., older Chilean SII keys, most government-
      issued tokens).

  Opt in:

      PKCS11EX_SAFENET_PIN=1234 \\
      PKCS11EX_SAFENET_KEY_LABEL=my-key-label \\
        mix test --include safenet test/pkcs11ex/safenet/sign_test.exs

  ## What this test asserts

    * The driver + slot + PIN combination authenticates
      successfully.
    * Signing produces a 256-byte raw signature for an RSA-2048
      key (the eToken's standard key size).
    * The signature mathematically verifies via the
      `Pkcs11ex.Native.verify/6` round-trip — proves the same
      public key is reachable for both sign and verify ops.
    * A tampered payload is rejected (math fails).
  """

  use ExUnit.Case, async: false

  @moduletag :safenet

  alias Pkcs11ex.Native
  alias Pkcs11ex.Test.SafeNet

  # Env-var detection at module load time. Both vars must be present
  # for the real tests to compile in. Missing vars produce a single
  # placeholder test that prints a setup hint — same pattern the
  # conformance suite uses for missing tool binaries, and avoids the
  # `setup_all` `{:skip, _}` ExUnit limitation.
  @pin System.get_env("PKCS11EX_SAFENET_PIN")
  @key_label System.get_env("PKCS11EX_SAFENET_KEY_LABEL")
  # `Pkcs11ex.Native.sign/6` expects the mechanism as a string (not
  # atom) — it's converted via `Atom.to_string/1` inside Layer 2.
  @mechanism System.get_env("PKCS11EX_SAFENET_MECHANISM") || "ck_sha256_rsa_pkcs_pss"

  if @pin && @key_label do
    setup_all do
      cond do
        not SafeNet.driver_present?() ->
          {:skip, "SafeNet driver not at #{SafeNet.driver_path()}"}

        true ->
          with {:ok, mod} <- SafeNet.load_module(),
               {:ok, slot} <- SafeNet.detect_slot() do
            {:ok, p11_module: mod, slot_id: slot.slot_id, token_label: slot.token_label}
          else
            {:error, reason} ->
              {:skip, "SafeNet bootstrap failed: #{inspect(reason)}"}
          end
      end
    end

    test "sign + verify round trip on a token-resident key", ctx do
      payload = "pkcs11ex safenet smoke test #{System.unique_integer([:positive])}"

      case Native.sign(
             ctx.p11_module,
             ctx.slot_id,
             @pin,
             @mechanism,
             @key_label,
             payload
           ) do
        {:ok, raw} ->
          # Rustler 0.37 encodes `Vec<u8>` returns as Erlang lists.
          # Layer 2 (`Pkcs11ex.sign_bytes`) normalises this; calling
          # the NIF directly we have to do it ourselves.
          signature = IO.iodata_to_binary(raw)

          assert byte_size(signature) in [256, 384, 512],
                 "Unexpected sig size #{byte_size(signature)} — typical RSA-2048 produces 256 bytes"

          assert {:ok, true} =
                   Native.verify(
                     ctx.p11_module,
                     ctx.slot_id,
                     @mechanism,
                     @key_label,
                     payload,
                     signature
                   )

        {:error, {:CKR_MECHANISM_INVALID, _}} ->
          flunk(
            "Token rejected mechanism #{inspect(@mechanism)}. Try " <>
              "PKCS11EX_SAFENET_MECHANISM=ck_sha256_rsa_pkcs (PKCS#1 v1.5) " <>
              "for keys that don't support RSASSA-PSS — common on older " <>
              "SII / government-issued eTokens."
          )

        {:error, {:CKR_PIN_INCORRECT, _}} ->
          flunk(
            "PIN rejected by token. Counter decremented by 1 — " <>
              "DO NOT retry with another wrong PIN; SafeNet locks at 5 wrong tries."
          )

        {:error, {:CKR_KEY_HANDLE_INVALID, _}} ->
          flunk(
            "Key not found by label #{inspect(@key_label)}. " <>
              "Check the label via SafeNet Authentication Client Tools or `pkcs11-tool --list-objects`."
          )

        {:error, reason} ->
          flunk("SafeNet sign failed: #{inspect(reason)}")
      end
    end

    test "tampered payload is rejected by the verify pipeline", ctx do
      payload = "pkcs11ex safenet tamper test #{System.unique_integer([:positive])}"

      case Native.sign(
             ctx.p11_module,
             ctx.slot_id,
             @pin,
             @mechanism,
             @key_label,
             payload
           ) do
        {:ok, raw} ->
          signature = IO.iodata_to_binary(raw)

          result =
            Native.verify(
              ctx.p11_module,
              ctx.slot_id,
              @mechanism,
              @key_label,
              "tampered " <> payload,
              signature
            )

          case result do
            {:ok, false} -> :ok
            {:error, _} -> :ok
            {:ok, true} -> flunk("Tampered payload incorrectly verified — driver bug or test bug")
          end

        {:error, reason} ->
          flunk("SafeNet sign failed before tamper assertion: #{inspect(reason)}")
      end
    end
  else
    test "skipped — supply PKCS11EX_SAFENET_PIN and PKCS11EX_SAFENET_KEY_LABEL to run" do
      IO.puts(
        "[skip] Pkcs11ex.SafeNet.SignTest — PIN and key label env vars required.\n" <>
          "Find the key label via SafeNet Authentication Client Tools or:\n" <>
          "  pkcs11-tool --module <driver> --list-objects --type pubkey\n" <>
          "Then run:\n" <>
          "  PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \\\n" <>
          "    mix test --include safenet test/pkcs11ex/safenet/sign_test.exs"
      )
    end
  end
end
