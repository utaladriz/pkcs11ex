defmodule Mix.Tasks.Pkcs11ex.ImportP12Test do
  @moduledoc """
  Argument-validation coverage for the `mix pkcs11ex.import_p12`
  task. End-to-end import (real PKCS#12 + real SoftHSM slot) lives
  in `pkcs11ex.import_p12_softhsm_test.exs`.

  Every assertion here is reachable with no openssl invocation and
  no SoftHSM token — they hit the validation path before the task
  shells out.
  """

  use ExUnit.Case, async: false

  describe "run/1 — argument validation" do
    test "rejects an unrecognised switch" do
      assert_raise Mix.Error, ~r/invalid options/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run(["--bogus", "x"])
      end
    end

    test "missing --in surfaces a clear error" do
      assert_raise Mix.Error, ~r/--in is required/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--slot",
          "x",
          "--label",
          "y"
        ])
      end
    end

    test "missing --slot surfaces a clear error" do
      assert_raise Mix.Error, ~r/--slot is required/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          "any.p12",
          "--label",
          "y"
        ])
      end
    end

    test "missing --label surfaces a clear error" do
      assert_raise Mix.Error, ~r/--label is required/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          "any.p12",
          "--slot",
          "x"
        ])
      end
    end

    test "non-existent --in path surfaces 'bundle not found'" do
      missing = Path.join(System.tmp_dir!(), "definitely-missing-#{System.unique_integer([:positive])}.p12")
      refute File.exists?(missing)

      assert_raise Mix.Error, ~r/bundle not found/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          missing,
          "--slot",
          "x",
          "--label",
          "y"
        ])
      end
    end

    test "malformed --id (non-hex) surfaces a clear error" do
      tmp = empty_p12_path()

      assert_raise Mix.Error, ~r/--id must be hex/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          tmp,
          "--slot",
          "x",
          "--label",
          "y",
          "--id",
          "ZZ"
        ])
      end
    end

    test "0x-prefixed --id is accepted (parsing reaches openssl/secret stage)" do
      tmp = empty_p12_path()

      # Past --id parsing it tries to fetch a secret; --password-from-env
      # missing env raises with the env-var-not-set message — proves the
      # 0x... id parsed.
      assert_raise Mix.Error, ~r/env var.*not set/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          tmp,
          "--slot",
          "x",
          "--label",
          "y",
          "--id",
          "0x01",
          "--password-from-env",
          "PKCS11EX_TEST_NEVER_SET",
          "--pin-from-env",
          "PKCS11EX_TEST_NEVER_SET"
        ])
      end
    end

    test "--password-from-env pointing at unset env var raises explicitly" do
      tmp = empty_p12_path()

      assert_raise Mix.Error, ~r/env var PKCS11EX_TEST_NEVER_SET not set/, fn ->
        Mix.Tasks.Pkcs11ex.ImportP12.run([
          "--in",
          tmp,
          "--slot",
          "x",
          "--label",
          "y",
          "--password-from-env",
          "PKCS11EX_TEST_NEVER_SET",
          "--pin-from-env",
          "PKCS11EX_TEST_NEVER_SET"
        ])
      end
    end
  end

  defp empty_p12_path do
    path = Path.join(System.tmp_dir!(), "import-p12-test-#{System.unique_integer([:positive])}.p12")
    File.write!(path, <<>>)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
