defmodule Pkcs11ex.Conformance.XMLXmlsec1Test do
  @moduledoc """
  Standards-conformance check for `SignCore.XML.sign/2` against the
  `xmlsec1` CLI (libxmlsec1) — the canonical third-party XML-DSig /
  XAdES verifier shipped on every major Linux distro and Homebrew.

  Excluded by default; opt in via `mix test --include conformance`.

  Requires:

    * SoftHSM2 (the existing :softhsm fixture).
    * `xmlsec1` from libxmlsec1 — `brew install libxmlsec1` on macOS,
      `apt-get install xmlsec1` on Debian.

  This is the test that decides whether the
  `SignCore.XML.Canonicalizer.canonicalize_subtree/2` workaround for
  the vendored xmerl_c14n's exc-c14n bug actually produces the same
  bytes a standards-compliant exc-c14n implementation produces. If
  it doesn't, this test fails — and Phase 4b.2 (NIF-wrap
  `bergshamra`) gets its trigger.
  """

  use ExUnit.Case, async: false

  @moduletag :conformance
  @moduletag :softhsm

  if xmlsec1 = System.find_executable("xmlsec1") do
    @xmlsec1 xmlsec1

    alias Pkcs11ex.Native
    alias Pkcs11ex.XML

    setup_all do
      softhsm2_util = System.find_executable("softhsm2-util")
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)
      {:ok, bootstrap(softhsm2_util)}
    end

    test "XML.sign/2 (B-B) output verifies under xmlsec1 --verify", ctx do
      base_xml = sii_dte_fixture()

      {:ok, signed_xml} =
        XML.sign(base_xml,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der
        )

      xml_path = write_temp(signed_xml, "conformance-bb", "xml")
      cert_path = write_temp(ctx.leaf_pem, "conformance-bb-cert", "pem")

      {output, status} =
        System.cmd(
          @xmlsec1,
          [
            "--verify",
            "--insecure",
            "--pubkey-cert-pem",
            cert_path,
            "--id-attr:Id",
            "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
            xml_path
          ],
          stderr_to_stdout: true
        )

      assert status == 0,
             """
             xmlsec1 rejected the signed XML.
             Exit: #{status}
             Output:
             #{output}
             """

      assert output =~ "OK",
             "xmlsec1 reported success exit code but no 'OK' in output:\n#{output}"
    end

    @tag :tsa
    test "XML.sign/2 (B-T) output still verifies under xmlsec1 --verify", ctx do
      tsa_url = System.get_env("PKCS11EX_TSA_URL") || "http://timestamp.digicert.com"
      base_xml = sii_dte_fixture()

      {:ok, signed_xml} =
        XML.sign(base_xml,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          tsa_url: tsa_url,
          tsa_timeout: 15_000
        )

      xml_path = write_temp(signed_xml, "conformance-bt", "xml")
      cert_path = write_temp(ctx.leaf_pem, "conformance-bt-cert", "pem")

      {output, status} =
        System.cmd(
          @xmlsec1,
          [
            "--verify",
            "--insecure",
            "--pubkey-cert-pem",
            cert_path,
            "--id-attr:Id",
            "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
            xml_path
          ],
          stderr_to_stdout: true
        )

      assert status == 0,
             "xmlsec1 rejected B-T XML.\nExit: #{status}\nOutput:\n#{output}"
    end

    # ---------- helpers ----------

    defp write_temp(bytes, prefix, ext) do
      path =
        Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}.#{ext}")

      File.write!(path, bytes)
      on_exit(fn -> File.rm(path) end)
      path
    end

    defp bootstrap(softhsm2_util) do
      suffix = System.unique_integer([:positive])
      token_label = "pkcs11ex-conf-xml-#{suffix}"
      key_label = "pkcs11ex-conf-xml-key-#{suffix}"
      user_pin = "1234"
      so_pin = "1234"

      slot_id = Pkcs11ex.Test.SoftHSM.init_token!(softhsm2_util, token_label, user_pin, so_pin)
      on_exit(fn -> Pkcs11ex.Test.SoftHSM.delete_token(softhsm2_util, token_label) end)

      pkcs11_module = Pkcs11ex.Test.SoftHSM.module()
      {:ok, true} = Native.generate_rsa_keypair(pkcs11_module, slot_id, user_pin, key_label, 2048)

      {:ok, {modulus_list, exponent_list}} =
        case Native.export_rsa_public_key(pkcs11_module, slot_id, key_label) do
          {:ok, pair} -> {:ok, pair}
          {modulus, exponent} -> {:ok, {modulus, exponent}}
        end

      modulus_bin = IO.iodata_to_binary(modulus_list)
      exponent_bin = IO.iodata_to_binary(exponent_list)
      softhsm_pubkey = build_rsa_public_key(modulus_bin, exponent_bin)
      {leaf_der, leaf_pem} = build_wrapper_cert(softhsm_pubkey)

      %{
        pkcs11_module: pkcs11_module,
        slot_id: slot_id,
        pin: user_pin,
        key_label: key_label,
        leaf_der: leaf_der,
        leaf_pem: leaf_pem
      }
    end

    defp build_rsa_public_key(modulus_bin, exponent_bin) do
      modulus = :binary.decode_unsigned(modulus_bin, :big)
      exponent = :binary.decode_unsigned(exponent_bin, :big)
      {:RSAPublicKey, modulus, exponent}
    end

    defp build_wrapper_cert(rsa_pubkey) do
      issuer_key = X509.PrivateKey.new_rsa(2048)
      issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-conformance-issuer")

      leaf_cert =
        X509.Certificate.new(
          rsa_pubkey,
          "/CN=pkcs11ex-conformance-leaf",
          issuer_cert,
          issuer_key
        )

      der = X509.Certificate.to_der(leaf_cert)
      pem = X509.Certificate.to_pem(leaf_cert)
      {der, pem}
    end

    defp sii_dte_fixture do
      """
      <?xml version="1.0" encoding="ISO-8859-1"?><DTE version="1.0" xmlns="http://www.sii.cl/SiiDte"><Documento ID="F1234T33"><Encabezado><IdDoc><TipoDTE>33</TipoDTE><Folio>1234</Folio><FchEmis>2026-05-06</FchEmis></IdDoc><Emisor><RUTEmisor>76123456-7</RUTEmisor><RznSoc>Test Provider Spa</RznSoc></Emisor><Receptor><RUTRecep>11111111-1</RUTRecep><RznSocRecep>Test Buyer SA</RznSocRecep></Receptor><Totales><MntNeto>1000</MntNeto><IVA>190</IVA><MntTotal>1190</MntTotal></Totales></Encabezado><Detalle><NroLinDet>1</NroLinDet><NmbItem>Test item</NmbItem><QtyItem>1</QtyItem><PrcItem>1000</PrcItem><MontoItem>1000</MontoItem></Detalle></Documento></DTE>
      """
      |> String.trim()
    end
  else
    test "skipped — xmlsec1 not on PATH (install: brew install libxmlsec1)" do
      IO.puts(
        "[skip] Pkcs11ex.Conformance.XMLXmlsec1Test — xmlsec1 not on PATH. " <>
          "Install with `brew install libxmlsec1` (macOS) or " <>
          "`apt-get install xmlsec1` (Debian)."
      )
    end
  end
end
