defmodule Mix.Tasks.Pkcs11ex.ImportP12SofthsmTest do
  @moduledoc """
  End-to-end coverage of the `mix pkcs11ex.import_p12` task driving
  the full argv -> openssl -> PEM parse -> Slot.Server.import_keypair
  pipeline.

  Complements `Pkcs11ex.Slot.ImportKeypairTest` which exercises the
  same import path but bypasses the Mix task surface (argv + openssl
  invocation + PEM parsing). This test is the one that catches a
  regression in the parts of the task users actually touch.

  Tagged `:softhsm` — opt in by installing SoftHSM2 + openssl +
  softhsm2-util.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

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
        token_label = "pkcs11ex-mix-imp-#{suffix}"

        slot_id =
          Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, @user_pin, @so_pin)

        module = Pkcs11ex.Test.SoftHSM.module()
        on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

        tmp_dir = Path.join(System.tmp_dir!(), "pkcs11ex_mix_import_#{suffix}")
        File.mkdir_p!(tmp_dir)
        on_exit(fn -> File.rm_rf!(tmp_dir) end)

        rsa_key = X509.PrivateKey.new_rsa(2048)
        cert = X509.Certificate.self_signed(rsa_key, "/CN=pkcs11ex-mix-import")
        key_pem_path = Path.join(tmp_dir, "key.pem")
        cert_pem_path = Path.join(tmp_dir, "cert.pem")
        File.write!(key_pem_path, X509.PrivateKey.to_pem(rsa_key))
        File.write!(cert_pem_path, X509.Certificate.to_pem(cert))

        p12_path = Path.join(tmp_dir, "bundle.p12")
        p12_password = "mix-#{suffix}"

        {_out, 0} =
          System.cmd(
            openssl,
            [
              "pkcs12",
              "-export",
              "-in",
              cert_pem_path,
              "-inkey",
              key_pem_path,
              "-out",
              p12_path,
              "-password",
              "pass:#{p12_password}"
            ],
            stderr_to_stdout: true
          )

        slot_ref = String.to_atom("mix_imp_slot_#{suffix}")

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

        {:ok, slot_ref: slot_ref, pkcs11_module: module, p12_path: p12_path, p12_password: p12_password}
    end
  end

  setup do
    # Mix.Shell.Process captures `Mix.shell().info/1` output as messages
    # so we can assert on the success line printed by the task.
    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)
    :ok
  end

  test "Mix task imports a P12 and the imported key signs", ctx do
    key_label = "imp-mix-#{System.unique_integer([:positive])}"
    cert_label = "imp-mix-cert-#{System.unique_integer([:positive])}"

    System.put_env("PKCS11EX_TEST_P12_PWD", ctx.p12_password)
    System.put_env("PKCS11EX_TEST_USER_PIN", @user_pin)

    on_exit(fn ->
      System.delete_env("PKCS11EX_TEST_P12_PWD")
      System.delete_env("PKCS11EX_TEST_USER_PIN")
    end)

    Mix.Tasks.Pkcs11ex.ImportP12.run([
      "--in",
      ctx.p12_path,
      "--slot",
      Atom.to_string(ctx.slot_ref),
      "--label",
      key_label,
      "--cert-label",
      cert_label,
      "--password-from-env",
      "PKCS11EX_TEST_P12_PWD",
      "--pin-from-env",
      "PKCS11EX_TEST_USER_PIN"
    ])

    assert_received {:mix_shell, :info, [msg]}
    assert msg =~ "Imported keypair into slot"
    assert msg =~ key_label

    # Sanity check: the imported key is actually usable for signing.
    assert {:ok, signature} =
             Server.sign(
               ctx.slot_ref,
               key_label,
               :ck_sha256_rsa_pkcs_pss,
               "the imported key works"
             )

    assert is_binary(signature) and byte_size(signature) == 256
  end

  test "Mix task surfaces :slot_not_found when the slot atom isn't running",
       ctx do
    System.put_env("PKCS11EX_TEST_P12_PWD", ctx.p12_password)
    System.put_env("PKCS11EX_TEST_USER_PIN", @user_pin)

    on_exit(fn ->
      System.delete_env("PKCS11EX_TEST_P12_PWD")
      System.delete_env("PKCS11EX_TEST_USER_PIN")
    end)

    assert_raise Mix.Error, ~r/slot :no_such_slot is not running/, fn ->
      Mix.Tasks.Pkcs11ex.ImportP12.run([
        "--in",
        ctx.p12_path,
        "--slot",
        "no_such_slot",
        "--label",
        "k",
        "--password-from-env",
        "PKCS11EX_TEST_P12_PWD",
        "--pin-from-env",
        "PKCS11EX_TEST_USER_PIN"
      ])
    end
  end

  test "wrong P12 password surfaces a friendly error", ctx do
    System.put_env("PKCS11EX_TEST_BAD_PWD", "definitely-wrong")
    System.put_env("PKCS11EX_TEST_USER_PIN", @user_pin)

    on_exit(fn ->
      System.delete_env("PKCS11EX_TEST_BAD_PWD")
      System.delete_env("PKCS11EX_TEST_USER_PIN")
    end)

    assert_raise Mix.Error, ~r/PKCS#12 password incorrect/, fn ->
      Mix.Tasks.Pkcs11ex.ImportP12.run([
        "--in",
        ctx.p12_path,
        "--slot",
        Atom.to_string(ctx.slot_ref),
        "--label",
        "won-t-import",
        "--password-from-env",
        "PKCS11EX_TEST_BAD_PWD",
        "--pin-from-env",
        "PKCS11EX_TEST_USER_PIN"
      ])
    end
  end
end
