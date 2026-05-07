defmodule Pkcs11ex.PKCS12Test do
  use ExUnit.Case, async: false

  alias Pkcs11ex.PKCS12
  alias Pkcs11ex.PKCS12.Bundle

  @password "1234"
  @wrong_password "wrong"

  setup_all do
    if System.find_executable("openssl") == nil do
      {:skip, "openssl CLI not on PATH"}
    else
      tmp = Path.join(System.tmp_dir!(), "pkcs11ex_p12_test_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp)
      on_exit(fn -> File.rm_rf!(tmp) end)

      {:ok, build_fixtures(tmp)}
    end
  end

  defp build_fixtures(tmp) do
    # Software RSA keypair + self-signed cert.
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=pkcs11ex-pkcs12-test")

    key_pem_path = Path.join(tmp, "key.pem")
    cert_pem_path = Path.join(tmp, "cert.pem")
    File.write!(key_pem_path, X509.PrivateKey.to_pem(key))
    File.write!(cert_pem_path, X509.Certificate.to_pem(cert))

    with_key_path = Path.join(tmp, "with_key.p12")

    {_out, 0} =
      System.cmd(
        "openssl",
        [
          "pkcs12",
          "-export",
          "-in",
          cert_pem_path,
          "-inkey",
          key_pem_path,
          "-name",
          "pkcs11ex-test",
          "-out",
          with_key_path,
          "-password",
          "pass:#{@password}"
        ],
        stderr_to_stdout: true
      )

    %{
      tmp: tmp,
      with_key_path: with_key_path,
      with_key_bytes: File.read!(with_key_path),
      key: key,
      cert_der: X509.Certificate.to_der(cert)
    }
  end

  # ---------- Happy path ----------

  describe "load/2 — bundle with cert + key" do
    test "loads from a file path", ctx do
      assert {:ok, %Bundle{} = bundle} =
               PKCS12.load(ctx.with_key_path, password: @password)

      assert bundle.has_private_key == true
      assert %SignCore.X509{} = bundle.leaf
      assert bundle.leaf.der == ctx.cert_der
      assert bundle.chain == []
      assert is_nil(bundle.friendly_name)
    end

    test "loads from raw bytes", ctx do
      assert {:ok, %Bundle{} = bundle} =
               PKCS12.load(ctx.with_key_bytes, password: @password)

      assert bundle.has_private_key == true
      assert bundle.leaf.der == ctx.cert_der
    end

    test "the loaded leaf has a usable public key", ctx do
      {:ok, %Bundle{leaf: leaf}} = PKCS12.load(ctx.with_key_path, password: @password)
      assert {:RSAPublicKey, _modulus, _exponent} = leaf.public_key
    end

    test "spki_sha256 of the leaf matches the original cert", ctx do
      {:ok, %Bundle{leaf: leaf}} = PKCS12.load(ctx.with_key_path, password: @password)

      {:ok, original} = SignCore.X509.from_der(ctx.cert_der)
      assert SignCore.X509.spki_sha256(leaf) == SignCore.X509.spki_sha256(original)
    end
  end

  # ---------- Failure modes ----------

  describe "load/2 — failure paths" do
    test "wrong password → :p12_password_incorrect", ctx do
      assert {:error, :p12_password_incorrect} =
               PKCS12.load(ctx.with_key_path, password: @wrong_password)
    end

    test "garbage bytes → :p12_invalid" do
      assert {:error, :p12_invalid} =
               PKCS12.load(:crypto.strong_rand_bytes(512), password: @password)
    end

    test "empty bytes → :p12_invalid" do
      assert {:error, :p12_invalid} = PKCS12.load(<<>>, password: @password)
    end
  end

  # ---------- Configuration ----------

  describe "load/2 — :max_chain" do
    test "default cap is 8 (well above a 1-cert bundle)", ctx do
      assert {:ok, _bundle} = PKCS12.load(ctx.with_key_path, password: @password)
    end

    test ":max_chain: 0 rejects any bundle with a cert", ctx do
      assert {:error, :p12_chain_too_long} =
               PKCS12.load(ctx.with_key_path, password: @password, max_chain: 0)
    end
  end

  # ---------- Anti-pattern: loader is read-only ----------

  describe "API surface" do
    test "Bundle has no field exposing the private key", _ctx do
      fields = Bundle.__struct__() |> Map.from_struct() |> Map.keys()
      refute :private_key in fields
      refute :key in fields
      assert :has_private_key in fields
    end
  end
end
