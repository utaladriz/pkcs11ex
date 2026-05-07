defmodule SoftSigner.PKCS12Test do
  @moduledoc """
  Round-trip test for the PKCS#12 software signer.

  Builds a fresh keypair via `:x509`, packages it as a P12 via
  `openssl pkcs12 -export`, loads it through `SoftSigner.PKCS12.load/2`,
  and routes a signature through `SignCore.PDF.sign/2`. Verifies the
  resulting PDF round-trips through `SignCore.PDF.verify/2`.

  Skips when openssl isn't on PATH (the bundle export step depends
  on it).
  """

  use ExUnit.Case, async: false

  setup_all do
    unless System.find_executable("openssl") do
      raise "openssl CLI not on PATH — required for SoftSigner.PKCS12 tests"
    end

    suffix = System.unique_integer([:positive])
    tmp = Path.join(System.tmp_dir!(), "soft_signer_test_#{suffix}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    rsa_key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(rsa_key, "/CN=soft-signer-test")

    key_pem_path = Path.join(tmp, "key.pem")
    cert_pem_path = Path.join(tmp, "cert.pem")
    File.write!(key_pem_path, X509.PrivateKey.to_pem(rsa_key))
    File.write!(cert_pem_path, X509.Certificate.to_pem(cert))

    p12_path = Path.join(tmp, "bundle.p12")
    password = "soft-#{suffix}"

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
          "-out",
          p12_path,
          "-password",
          "pass:#{password}"
        ],
        stderr_to_stdout: true
      )

    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
    Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

    {:ok, p12_path: p12_path, password: password, leaf_der: X509.Certificate.to_der(cert)}
  end

  test "load/2 happy path", ctx do
    assert {:ok, %SoftSigner.PKCS12{} = signer} =
             SoftSigner.PKCS12.load(ctx.p12_path, password: ctx.password)

    assert is_tuple(signer.rsa_key)
    assert elem(signer.rsa_key, 0) == :RSAPrivateKey
    assert is_binary(signer.leaf_der)
    assert SoftSigner.PKCS12.cert_chain(signer) == [signer.leaf_der | signer.chain_ders]
  end

  test "wrong password surfaces a friendly error", ctx do
    assert {:error, {:openssl, msg}} =
             SoftSigner.PKCS12.load(ctx.p12_path, password: "definitely-wrong")

    assert msg =~ "password incorrect"
  end

  test "missing bundle path surfaces :bundle_not_found" do
    missing = "/tmp/never-exists-#{System.unique_integer([:positive])}.p12"

    assert {:error, {:bundle_not_found, ^missing}} =
             SoftSigner.PKCS12.load(missing, password: "irrelevant")
  end

  test "PDF.sign + PDF.verify round trip via SoftSigner.PKCS12", ctx do
    {:ok, signer} = SoftSigner.PKCS12.load(ctx.p12_path, password: ctx.password)

    base_pdf = build_minimal_pdf()

    {:ok, signed_pdf} =
      SignCore.PDF.sign(base_pdf,
        signer: signer,
        alg: :PS256,
        x5c: SoftSigner.PKCS12.cert_chain(signer),
        placeholder_size: 4096
      )

    assert is_binary(signed_pdf)
    assert byte_size(signed_pdf) > byte_size(base_pdf)

    assert {:ok, :anyone} = SignCore.PDF.verify(signed_pdf)
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
