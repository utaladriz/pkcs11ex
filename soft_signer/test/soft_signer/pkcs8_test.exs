defmodule SoftSigner.PKCS8Test do
  @moduledoc """
  Round-trip + edge-case tests for the PKCS#8 PEM software signer.

  Builds keypairs + certs via `:x509` (no openssl needed for the
  unencrypted case), shells out to `openssl` only for the
  encrypted-PEM test. Covers:

    * Unencrypted key + single cert PEM round-trip
    * Cert chain (leaf + intermediate) round-trip
    * Encrypted PKCS#8 with correct password
    * Encrypted PKCS#8 with wrong password
    * Encrypted key without supplying a password
    * Missing-key / missing-cert / file-not-found error paths
    * `key_pem`/`cert_pem` string-input form
    * PDF.sign + PDF.verify round-trip via the loaded key
  """

  use ExUnit.Case, async: false

  setup_all do
    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
    Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

    suffix = System.unique_integer([:positive])
    tmp = Path.join(System.tmp_dir!(), "soft_signer_p8_#{suffix}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    rsa_key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(rsa_key, "/CN=pkcs8-test")

    key_pem_path = Path.join(tmp, "key.pem")
    cert_pem_path = Path.join(tmp, "cert.pem")
    File.write!(key_pem_path, X509.PrivateKey.to_pem(rsa_key))
    File.write!(cert_pem_path, X509.Certificate.to_pem(cert))

    {:ok,
     tmp: tmp,
     key_pem_path: key_pem_path,
     cert_pem_path: cert_pem_path,
     rsa_key: rsa_key,
     cert: cert}
  end

  describe "load/1 — unencrypted key" do
    test "from file paths", ctx do
      assert {:ok, %SoftSigner.PKCS8{} = signer} =
               SoftSigner.PKCS8.load(
                 key_path: ctx.key_pem_path,
                 cert_path: ctx.cert_pem_path
               )

      assert is_tuple(signer.rsa_key)
      assert elem(signer.rsa_key, 0) == :RSAPrivateKey
      assert is_binary(signer.leaf_der)
      assert signer.chain_ders == []
    end

    test "from in-memory PEM strings", ctx do
      key_pem = File.read!(ctx.key_pem_path)
      cert_pem = File.read!(ctx.cert_pem_path)

      assert {:ok, %SoftSigner.PKCS8{}} =
               SoftSigner.PKCS8.load(key_pem: key_pem, cert_pem: cert_pem)
    end

    test "cert PEM with leaf + intermediate", ctx do
      issuer_key = X509.PrivateKey.new_rsa(2048)
      issuer = X509.Certificate.self_signed(issuer_key, "/CN=intermediate")
      leaf_pubkey = X509.PublicKey.derive(ctx.rsa_key)
      leaf = X509.Certificate.new(leaf_pubkey, "/CN=leaf-via-intermediate", issuer, issuer_key)

      chained_cert_pem = X509.Certificate.to_pem(leaf) <> X509.Certificate.to_pem(issuer)
      chained_path = Path.join(ctx.tmp, "chained.pem")
      File.write!(chained_path, chained_cert_pem)

      {:ok, signer} =
        SoftSigner.PKCS8.load(key_path: ctx.key_pem_path, cert_path: chained_path)

      assert length(SoftSigner.PKCS8.cert_chain(signer)) == 2
      assert hd(signer.chain_ders) == X509.Certificate.to_der(issuer)
    end
  end

  describe "load/1 — encrypted key" do
    setup ctx do
      openssl = System.find_executable("openssl")

      if is_nil(openssl) do
        {:skip, "openssl CLI required for encrypted-PEM tests"}
      else
        encrypted_path = Path.join(ctx.tmp, "key-encrypted.pem")
        password = "p8-#{System.unique_integer([:positive])}"

        # `pkcs8 -topk8 -v2 aes-256-cbc` produces an
        # `ENCRYPTED PRIVATE KEY` PEM.
        {_out, 0} =
          System.cmd(
            openssl,
            [
              "pkcs8",
              "-topk8",
              "-in",
              ctx.key_pem_path,
              "-out",
              encrypted_path,
              "-v2",
              "aes-256-cbc",
              "-passout",
              "pass:#{password}"
            ],
            stderr_to_stdout: true
          )

        {:ok, encrypted_path: encrypted_path, password: password}
      end
    end

    test "correct password unlocks the key", ctx do
      assert {:ok, %SoftSigner.PKCS8{}} =
               SoftSigner.PKCS8.load(
                 key_path: ctx.encrypted_path,
                 cert_path: ctx.cert_pem_path,
                 password: ctx.password
               )
    end

    test "wrong password surfaces :wrong_password", ctx do
      assert {:error, :wrong_password} =
               SoftSigner.PKCS8.load(
                 key_path: ctx.encrypted_path,
                 cert_path: ctx.cert_pem_path,
                 password: "definitely-wrong"
               )
    end

    test "missing password on encrypted key surfaces :password_required", ctx do
      assert {:error, :password_required} =
               SoftSigner.PKCS8.load(
                 key_path: ctx.encrypted_path,
                 cert_path: ctx.cert_pem_path
               )
    end
  end

  describe "load/1 — error paths" do
    test "missing key opt", ctx do
      assert {:error, :missing_key} =
               SoftSigner.PKCS8.load(cert_path: ctx.cert_pem_path)
    end

    test "missing cert opt", ctx do
      assert {:error, :missing_cert} =
               SoftSigner.PKCS8.load(key_path: ctx.key_pem_path)
    end

    test "non-existent key file", ctx do
      missing = "/tmp/never-exists-#{System.unique_integer([:positive])}.pem"

      assert {:error, {:pem_not_found, ^missing}} =
               SoftSigner.PKCS8.load(key_path: missing, cert_path: ctx.cert_pem_path)
    end

    test "garbage PEM surfaces :no_pem_entries", ctx do
      assert {:error, :no_pem_entries} =
               SoftSigner.PKCS8.load(key_pem: "not a pem", cert_path: ctx.cert_pem_path)
    end

    test "cert PEM with no Certificate entry surfaces :no_cert_entries", ctx do
      bad_cert_path = Path.join(ctx.tmp, "bad-cert.pem")

      File.write!(
        bad_cert_path,
        "-----BEGIN CERTIFICATE REQUEST-----\nNULL\n-----END CERTIFICATE REQUEST-----\n"
      )

      assert {:error, :no_cert_entries} =
               SoftSigner.PKCS8.load(key_path: ctx.key_pem_path, cert_path: bad_cert_path)
    end
  end

  describe "PDF round-trip via PKCS#8 signer" do
    test "sign + verify works end-to-end", ctx do
      {:ok, signer} =
        SoftSigner.PKCS8.load(
          key_path: ctx.key_pem_path,
          cert_path: ctx.cert_pem_path
        )

      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        SignCore.PDF.sign(base_pdf,
          signer: signer,
          alg: :PS256,
          x5c: SoftSigner.PKCS8.cert_chain(signer),
          placeholder_size: 4096
        )

      assert {:ok, :anyone} = SignCore.PDF.verify(signed_pdf)
    end
  end

  defp build_minimal_pdf do
    objects = [
      {1, "<< /Type /Catalog /Pages 2 0 R >>"},
      {2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"},
      {3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}
    ]

    header = "%PDF-1.7\n"

    {body, offsets} =
      Enum.reduce(objects, {header, %{}}, fn {num, content}, {acc, offs} ->
        offset = byte_size(acc)
        obj_bytes = "#{num} 0 obj\n#{content}\nendobj\n"
        {acc <> obj_bytes, Map.put(offs, num, offset)}
      end)

    startxref_offset = byte_size(body)
    size = Enum.max(Map.keys(offsets)) + 1

    entries =
      Enum.map_join(0..(size - 1), "", fn n ->
        case Map.get(offsets, n) do
          nil ->
            if n == 0, do: "0000000000 65535 f \n", else: "0000000000 00000 f \n"

          offset ->
            offset_str = String.pad_leading(Integer.to_string(offset), 10, "0")
            "#{offset_str} 00000 n \n"
        end
      end)

    body <>
      "xref\n0 #{size}\n" <>
      entries <>
      "trailer\n<< /Size #{size} /Root 1 0 R >>\n" <>
      "startxref\n#{startxref_offset}\n%%EOF\n"
  end
end
