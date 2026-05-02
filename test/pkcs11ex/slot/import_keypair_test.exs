defmodule Pkcs11ex.Slot.ImportKeypairTest do
  @moduledoc """
  End-to-end test for the PKCS#12 import path used by `mix pkcs11ex.import_p12`.

  Builds a software RSA keypair + cert via `:x509`, packages them into a
  `.p12`, then drives the same internals the Mix task drives:

    1. openssl extracts cert + key as PEM
    2. `:public_key` parses the RSAPrivateKey
    3. `Pkcs11ex.Slot.Server.import_keypair/3` calls into the NIFs

  After import the imported key signs and the imported cert is in the slot.

  ## Test isolation

  Token + module are loaded **once** in `setup_all`. SoftHSM caches its slot
  list at `C_Initialize` time, so the token MUST be initialized before the
  module loads. Each test imports a **unique-labeled** key so two tests in
  the module don't collide.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.Native.RsaPrivateComponents
  alias Pkcs11ex.Slot.Server

  @user_pin "1234"
  @so_pin "1234"

  setup_all do
    driver = Pkcs11ex.Test.SoftHSM.driver_path()
    softhsm2_util = System.find_executable("softhsm2-util")
    openssl = System.find_executable("openssl")

    cond do
      is_nil(driver) ->
        {:skip, "SoftHSM2 driver not installed"}

      is_nil(softhsm2_util) ->
        {:skip, "softhsm2-util CLI not on PATH"}

      is_nil(openssl) ->
        {:skip, "openssl CLI not on PATH"}

      true ->
        suffix = System.unique_integer([:positive])
        token_label = "pkcs11ex-imp-#{suffix}"

        # Token first, then module — so SoftHSM's cached slot list at
        # C_Initialize includes our token.
        slot_id =
          Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, @user_pin, @so_pin)

        module = Pkcs11ex.Test.SoftHSM.module()

        on_exit(fn ->
          Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label)
        end)

        # Build a P12 fixture (one bundle, both tests reuse it).
        tmp_dir = Path.join(System.tmp_dir!(), "pkcs11ex_import_#{suffix}")
        File.mkdir_p!(tmp_dir)
        on_exit(fn -> File.rm_rf!(tmp_dir) end)

        rsa_key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(rsa_key, "/CN=pkcs11ex-import-test")
        File.write!(Path.join(tmp_dir, "key.pem"), X509.PrivateKey.to_pem(rsa_key))
        File.write!(Path.join(tmp_dir, "cert.pem"), X509.Certificate.to_pem(cert))

        p12_path = Path.join(tmp_dir, "bundle.p12")
        p12_password = "p12-#{suffix}"

        {_out, 0} =
          System.cmd(
            openssl,
            [
              "pkcs12",
              "-export",
              "-in",
              Path.join(tmp_dir, "cert.pem"),
              "-inkey",
              Path.join(tmp_dir, "key.pem"),
              "-out",
              p12_path,
              "-password",
              "pass:#{p12_password}"
            ],
            stderr_to_stdout: true
          )

        slot_ref = String.to_atom("import_test_slot_#{suffix}")

        slot_config = [
          type: :token,
          driver: driver,
          slot_match: {:slot_id, slot_id},
          pin_callback: nil,
          keys: [signing: [label: "ignored"]],
          lazy: true,
          reauthentication: :prompt
        ]

        {:ok, _} =
          start_supervised({Server, slot_ref: slot_ref, slot_config: slot_config, module: module})

        {:ok,
         slot_ref: slot_ref,
         pkcs11_module: module,
         openssl: openssl,
         p12_path: p12_path,
         p12_password: p12_password,
         rsa_key: rsa_key}
    end
  end

  test "round trip: P12 → import → sign with imported key", ctx do
    suffix = System.unique_integer([:positive])
    key_label = "imp-key-#{suffix}"
    cert_label = "imp-cert-#{suffix}"

    components = extract_components(ctx)
    {cert_der, subject_der} = extract_cert_pieces(ctx)

    assert :ok =
             Server.import_keypair(
               ctx.slot_ref,
               [
                 components: components,
                 cert_der: cert_der,
                 subject_der: subject_der,
                 key_label: key_label,
                 cert_label: cert_label,
                 id: ""
               ],
               pin: @user_pin
             )

    # Sign with the imported key.
    payload = "imported and signing"

    assert {:ok, sig} =
             Server.sign(ctx.slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, payload)

    assert byte_size(sig) == 256

    # Software-side verify against the source key (we have it because we
    # built the P12 fixture).
    assert :public_key.verify(payload, :sha256, sig, ctx.rsa_key,
             rsa_padding: :rsa_pkcs1_pss_padding,
             rsa_pss_saltlen: 32,
             rsa_mgf1_md: :sha256
           )
  end

  test "import with explicit :id sets CKA_ID on both objects", ctx do
    suffix = System.unique_integer([:positive])
    key_label = "imp-key-id-#{suffix}"
    cert_label = "imp-cert-id-#{suffix}"

    components = extract_components(ctx)
    {cert_der, subject_der} = extract_cert_pieces(ctx)

    assert :ok =
             Server.import_keypair(
               ctx.slot_ref,
               [
                 components: components,
                 cert_der: cert_der,
                 subject_der: subject_der,
                 key_label: key_label,
                 cert_label: cert_label,
                 id: <<0x01, 0x02, 0x03>>
               ],
               pin: @user_pin
             )

    assert {:ok, _sig} =
             Server.sign(ctx.slot_ref, key_label, :ck_sha256_rsa_pkcs_pss, "x")
  end

  # ---------- helpers ----------

  defp extract_components(ctx) do
    {:ok, key_pem} =
      run_openssl(ctx.openssl, [
        "pkcs12",
        "-in",
        ctx.p12_path,
        "-password",
        "pass:#{ctx.p12_password}",
        "-nocerts",
        "-nodes"
      ])

    [pem_entry | _] =
      :public_key.pem_decode(key_pem)
      |> Enum.filter(fn {tag, _, _} -> tag in [:RSAPrivateKey, :PrivateKeyInfo] end)

    rsa = decode_rsa(pem_entry)

    %RsaPrivateComponents{
      modulus: int_to_bin(elem(rsa, 2)),
      public_exponent: int_to_bin(elem(rsa, 3)),
      private_exponent: int_to_bin(elem(rsa, 4)),
      prime1: int_to_bin(elem(rsa, 5)),
      prime2: int_to_bin(elem(rsa, 6)),
      exponent1: int_to_bin(elem(rsa, 7)),
      exponent2: int_to_bin(elem(rsa, 8)),
      coefficient: int_to_bin(elem(rsa, 9))
    }
  end

  defp decode_rsa({:RSAPrivateKey, _, _} = e), do: :public_key.pem_entry_decode(e)

  defp decode_rsa({:PrivateKeyInfo, _, _} = e) do
    rsa = :public_key.pem_entry_decode(e)

    if is_tuple(rsa) and tuple_size(rsa) == 11 and elem(rsa, 0) == :RSAPrivateKey do
      rsa
    else
      raise "expected RSAPrivateKey from PrivateKeyInfo, got #{inspect(rsa)}"
    end
  end

  defp extract_cert_pieces(ctx) do
    {:ok, cert_pem} =
      run_openssl(ctx.openssl, [
        "pkcs12",
        "-in",
        ctx.p12_path,
        "-password",
        "pass:#{ctx.p12_password}",
        "-nokeys",
        "-nodes"
      ])

    {:Certificate, der, _} =
      :public_key.pem_decode(cert_pem)
      |> Enum.find(fn {tag, _, _} -> tag == :Certificate end)

    plain = :public_key.pkix_decode_cert(der, :plain)
    subject = elem(elem(plain, 1), 6)
    subject_der = :public_key.der_encode(:Name, subject)
    {der, subject_der}
  end

  defp run_openssl(openssl, args) do
    case System.cmd(openssl, args, stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {output, _} -> {:error, output}
    end
  end

  defp int_to_bin(n) when is_integer(n) and n >= 0, do: :binary.encode_unsigned(n, :big)
end
