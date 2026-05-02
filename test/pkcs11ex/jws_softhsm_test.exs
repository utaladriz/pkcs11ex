defmodule Pkcs11ex.JWSSofthsmTest do
  @moduledoc """
  End-to-end JWS sign + verify against SoftHSM2.

  Sign goes through SoftHSM (via `Pkcs11ex.JWS.sign/2` → Layer 2 → NIF →
  cryptoki → SoftHSM2). Verify is software-side via OTP `:public_key` against
  the cert in `x5c`.

  To make this work we need a cert whose `subjectPublicKeyInfo` matches the
  SoftHSM-resident public key. We get there by:

    1. Exporting the SoftHSM RSA public key (modulus + public exponent) via
       `Pkcs11ex.Native.export_rsa_public_key/3`.
    2. Building a self-signed cert that wraps that public key, using a fresh
       *software* RSA key as the cert's nominal issuer (we don't validate the
       cert's signature in the Allow policy — only that the embedded SPKI is
       what we expect).

  The bootstrap mirrors the Layer 2 SoftHSM test: unique-labeled token via
  `softhsm2-util`, RSA-2048 keypair via the `generate_rsa_keypair` NIF.
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
        Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.Allow)
        {:ok, ctx}
    end
  end

  defp bootstrap(driver, softhsm2_util) do
    suffix = System.unique_integer([:positive])
    token_label = "pkcs11ex-jws-test-#{suffix}"
    key_label = "pkcs11ex-jws-key-#{suffix}"
    user_pin = "1234"
    so_pin = "1234"

    {_out, 0} =
      System.cmd(
        softhsm2_util,
        ["--init-token", "--free", "--label", token_label, "--pin", user_pin, "--so-pin", so_pin],
        stderr_to_stdout: true
      )

    on_exit(fn ->
      _ =
        System.cmd(softhsm2_util, ["--delete-token", "--token", token_label], stderr_to_stdout: true)
    end)

    {:ok, pkcs11_module} = Native.module_load(driver)
    {:ok, slots} = Native.list_slots(pkcs11_module)

    %{slot_id: slot_id} = Enum.find(slots, &(&1.token_label == token_label))

    {:ok, true} = Native.generate_rsa_keypair(pkcs11_module, slot_id, user_pin, key_label, 2048)

    # Export the public key components and build a wrapper cert for x5c.
    {:ok, {modulus_list, exponent_list}} =
      case Native.export_rsa_public_key(pkcs11_module, slot_id, key_label) do
        {:ok, pair} -> {:ok, pair}
        {modulus, exponent} -> {:ok, {modulus, exponent}}
      end

    modulus_bin = IO.iodata_to_binary(modulus_list)
    exponent_bin = IO.iodata_to_binary(exponent_list)

    softhsm_pubkey = build_rsa_public_key(modulus_bin, exponent_bin)
    leaf_der = build_wrapper_cert(softhsm_pubkey)

    {:ok, pkcs11_module: pkcs11_module, slot_id: slot_id, pin: user_pin, key_label: key_label, leaf_der: leaf_der}
  end

  test "JWS round trip: SoftHSM signs, software verifies", ctx do
    payload = "hello jws over pkcs11"

    assert {:ok, jws} =
             Pkcs11ex.JWS.sign(payload,
               module: ctx.pkcs11_module,
               slot_id: ctx.slot_id,
               pin: ctx.pin,
               key_label: ctx.key_label,
               alg: :PS256,
               x5c: ctx.leaf_der
             )

    assert is_binary(jws)
    assert [_header, "", _sig] = String.split(jws, ".", parts: 3)

    assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
  end

  test "tampered payload is rejected", ctx do
    payload = "hello jws over pkcs11"

    {:ok, jws} =
      Pkcs11ex.JWS.sign(payload,
        module: ctx.pkcs11_module,
        slot_id: ctx.slot_id,
        pin: ctx.pin,
        key_label: ctx.key_label,
        alg: :PS256,
        x5c: ctx.leaf_der
      )

    assert {:error, :signature_invalid} = Pkcs11ex.JWS.verify(jws, "tampered " <> payload)
  end

  test "header has the required RFC 7797 shape", ctx do
    {:ok, jws} =
      Pkcs11ex.JWS.sign("payload",
        module: ctx.pkcs11_module,
        slot_id: ctx.slot_id,
        pin: ctx.pin,
        key_label: ctx.key_label,
        alg: :PS256,
        x5c: ctx.leaf_der,
        extra_headers: %{"kid" => "softhsm-fixture"}
      )

    [header_b64, "", _sig_b64] = String.split(jws, ".", parts: 3)
    {:ok, header_json} = Base.url_decode64(header_b64, padding: false)
    {:ok, header} = Jason.decode(header_json)

    assert header["alg"] == "PS256"
    assert header["b64"] == false
    assert header["crit"] == ["b64"]
    assert is_list(header["x5c"]) and length(header["x5c"]) >= 1
    assert header["kid"] == "softhsm-fixture"
  end

  # ---------- Cert fixture helpers ----------

  defp build_rsa_public_key(modulus_bin, exponent_bin) do
    modulus = :binary.decode_unsigned(modulus_bin, :big)
    exponent = :binary.decode_unsigned(exponent_bin, :big)
    {:RSAPublicKey, modulus, exponent}
  end

  defp build_wrapper_cert(rsa_pubkey) do
    # We can't sign a cert with the SoftHSM private key from the software side,
    # so we build a cert *containing* the SoftHSM public key, signed by a fresh
    # software RSA "issuer". The Allow policy doesn't validate the cert's
    # signature — it only decodes the leaf and extracts the SPKI. Verify then
    # uses that SPKI to mathematically check the SoftHSM-produced signature on
    # the JWS, which is the actual property we care about.
    issuer_key = X509.PrivateKey.new_rsa(2048)
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-test-issuer")

    leaf_cert =
      X509.Certificate.new(
        rsa_pubkey,
        "/CN=pkcs11ex-test-leaf",
        issuer_cert,
        issuer_key
      )

    X509.Certificate.to_der(leaf_cert)
  end
end
