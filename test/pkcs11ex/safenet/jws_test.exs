defmodule Pkcs11ex.SafeNet.JWSTest do
  @moduledoc """
  Layer-3 JWS round-trip against the eToken — the full
  `Pkcs11ex.JWS.sign/2` -> NIF -> hardware -> `Pkcs11ex.JWS.verify/3`
  pipeline on real hardware.

  We don't (yet) read the cert that's actually on the token (that's
  a `find_objects`-class NIF op we haven't exposed). Instead we
  follow the same pattern as the SoftHSM JWS test: export the
  token's public key via the existing
  `Pkcs11ex.Native.export_rsa_public_key/3` NIF, wrap it in a
  software-signed cert with whatever issuer + subject we want, and
  use that as `x5c`. The signature math depends only on the SPKI
  being the eToken's actual public key — which it is. The Allow
  policy bypasses chain trust, so `:public_key.verify/4`
  successfully validates against the wrapper cert's SPKI.

  Same env-var gating as the other safenet tests; opt in:

      PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \\
        mix test --include safenet test/pkcs11ex/safenet/jws_test.exs
  """

  use ExUnit.Case, async: false

  @moduletag :safenet

  alias Pkcs11ex.Native
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
               {:ok, slot} <- SafeNet.detect_slot(),
               {:ok, leaf_der} <- build_wrapper_cert(mod, slot.slot_id) do
            slot_ref =
              String.to_atom("safenet_jws_#{System.unique_integer([:positive])}")

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
            Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.Allow)

            {:ok, slot_ref: slot_ref, leaf_der: leaf_der}
          else
            {:error, reason} ->
              {:skip, "SafeNet bootstrap failed: #{inspect(reason)}"}
          end
      end
    end

    test "JWS sign + verify round trip", ctx do
      payload = "pkcs11ex JWS smoke #{System.unique_integer([:positive])}"

      assert {:ok, jws} =
               Pkcs11ex.JWS.sign(payload,
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 x5c: ctx.leaf_der,
                 pin: @pin
               )

      assert is_binary(jws)

      # RFC 7797 detached form: <header>..<sig>
      assert [_header_b64, "", _sig_b64] = String.split(jws, ".", parts: 3)

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "tampered payload is rejected by JWS.verify/3", ctx do
      payload = "pkcs11ex JWS tamper #{System.unique_integer([:positive])}"

      {:ok, jws} =
        Pkcs11ex.JWS.sign(payload,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          x5c: ctx.leaf_der,
          pin: @pin
        )

      assert {:error, :signature_invalid} =
               Pkcs11ex.JWS.verify(jws, "tampered " <> payload)
    end

    test "JWS header carries x5c as base64-DER + RFC 7797 detached markers", ctx do
      payload = "pkcs11ex JWS shape #{System.unique_integer([:positive])}"

      {:ok, jws} =
        Pkcs11ex.JWS.sign(payload,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          x5c: ctx.leaf_der,
          pin: @pin
        )

      [header_b64, "", _sig] = String.split(jws, ".", parts: 3)
      header = header_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()

      assert header["alg"] == "PS256"
      assert header["b64"] == false
      assert header["crit"] == ["b64"]
      assert is_list(header["x5c"]) and header["x5c"] != []
      assert hd(header["x5c"]) == Base.encode64(ctx.leaf_der)
    end
  else
    test "skipped — supply PKCS11EX_SAFENET_PIN and PKCS11EX_SAFENET_KEY_LABEL to run" do
      IO.puts(
        "[skip] Pkcs11ex.SafeNet.JWSTest — env vars required " <>
          "(see test/pkcs11ex/safenet/sign_test.exs for setup)."
      )
    end
  end

  # ---------- helpers ----------

  defp build_wrapper_cert(mod, slot_id) do
    case Native.export_rsa_public_key(mod, slot_id, @key_label) do
      {:ok, {modulus_list, exp_list}} ->
        do_wrap(modulus_list, exp_list)

      {modulus_list, exp_list} when is_list(modulus_list) ->
        # Legacy 2-tuple shape some NIF builds return
        do_wrap(modulus_list, exp_list)

      err ->
        {:error, {:export_failed, err}}
    end
  end

  defp do_wrap(modulus_list, exp_list) do
    modulus = modulus_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
    exp = exp_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
    rsa_pubkey = {:RSAPublicKey, modulus, exp}

    issuer_key = X509.PrivateKey.new_rsa(2048)
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-safenet-issuer")

    leaf_cert =
      X509.Certificate.new(rsa_pubkey, "/CN=pkcs11ex-safenet-jws-leaf", issuer_cert, issuer_key)

    {:ok, X509.Certificate.to_der(leaf_cert)}
  end
end
