defmodule Pkcs11ex.SafeNet.ConformanceTest do
  @moduledoc """
  External-verifier conformance against eToken-signed outputs —
  the strongest end-to-end proof point in the test suite.

  Runs `pdfsig` (Poppler) over a PAdES B-B PDF signed with the
  eToken's actual hardware-resident key, and `xmlsec1` (libxmlsec1)
  over a XAdES B-B XML same. Asserts the third-party verifiers
  accept the math.

  Three tags must all be active:

    * `:conformance` — opt-in
    * `:safenet` — opt-in (eToken plugged in, env vars set)
    * compile-time: pdfsig / xmlsec1 binaries on PATH

  Run with:

      PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \\
        mix test --include conformance --include safenet \\
                 test/pkcs11ex/safenet/conformance_test.exs

  This is what closes the loop on the Phase 4b.2 question for
  hardware: not only do `Pkcs11ex.PDF.verify/2` and
  `Pkcs11ex.XML.verify/2` accept their own output, but standards-
  compliant external implementations accept it too.
  """

  use ExUnit.Case, async: false

  @moduletag :conformance
  @moduletag :safenet

  alias Pkcs11ex.{Native, PDF, XML}
  alias Pkcs11ex.Slot.Server
  alias Pkcs11ex.Test.SafeNet

  @pin System.get_env("PKCS11EX_SAFENET_PIN")
  @key_label System.get_env("PKCS11EX_SAFENET_KEY_LABEL")
  @pdfsig System.find_executable("pdfsig")
  @xmlsec1 System.find_executable("xmlsec1")

  if @pin && @key_label && @pdfsig && @xmlsec1 do
    setup_all do
      cond do
        not SafeNet.driver_present?() ->
          {:skip, "SafeNet driver not at #{SafeNet.driver_path()}"}

        true ->
          with {:ok, mod} <- SafeNet.load_module(),
               {:ok, slot} <- SafeNet.detect_slot(),
               {:ok, leaf_der, leaf_pem} <- build_wrapper_cert(mod, slot.slot_id) do
            slot_ref = String.to_atom("safenet_conf_#{System.unique_integer([:positive])}")

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

            {:ok, slot_ref: slot_ref, leaf_der: leaf_der, leaf_pem: leaf_pem}
          else
            {:error, reason} -> {:skip, "SafeNet bootstrap failed: #{inspect(reason)}"}
          end
      end
    end

    test "eToken-signed PAdES B-B PDF passes pdfsig", ctx do
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          x5c: ctx.leaf_der,
          pin: @pin,
          placeholder_size: 4096
        )

      pdf_path = write_temp(signed_pdf, "safenet-conformance", "pdf")
      {output, status} = System.cmd(@pdfsig, [pdf_path], stderr_to_stdout: true)

      assert pdfsig_signature_valid?(output),
             "pdfsig REJECTED a real-hardware-signed PDF.\nExit: #{status}\nOutput:\n#{output}"
    end

    test "eToken-signed XAdES B-B XML passes xmlsec1 --verify", ctx do
      base_xml = sii_dte_fixture()

      {:ok, signed_xml} =
        XML.sign(base_xml,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          x5c: ctx.leaf_der,
          pin: @pin
        )

      xml_path = write_temp(signed_xml, "safenet-conformance", "xml")
      cert_path = write_temp(ctx.leaf_pem, "safenet-conformance-cert", "pem")

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
             "xmlsec1 REJECTED a real-hardware-signed XML.\nExit: #{status}\nOutput:\n#{output}"

      assert output =~ "OK"
    end
  else
    test "skipped — needs :safenet env vars + pdfsig + xmlsec1" do
      missing =
        [
          {is_nil(@pin) || is_nil(@key_label), "PKCS11EX_SAFENET_PIN/KEY_LABEL"},
          {is_nil(@pdfsig), "pdfsig"},
          {is_nil(@xmlsec1), "xmlsec1"}
        ]
        |> Enum.filter(&elem(&1, 0))
        |> Enum.map(&elem(&1, 1))
        |> Enum.join(", ")

      IO.puts("[skip] Pkcs11ex.SafeNet.ConformanceTest — missing: #{missing}")
    end
  end

  # ---------- helpers ----------

  defp pdfsig_signature_valid?(output) do
    output =~ "Signature Validation: Signature is Valid." or
      output =~ "Signature is valid" or
      output =~ "Signature Validity: Signature is Valid"
  end

  defp write_temp(bytes, prefix, ext) do
    path =
      Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}.#{ext}")

    File.write!(path, bytes)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_wrapper_cert(mod, slot_id) do
    case Native.export_rsa_public_key(mod, slot_id, @key_label) do
      {:ok, {modulus_list, exp_list}} -> do_wrap(modulus_list, exp_list)
      {modulus_list, exp_list} when is_list(modulus_list) -> do_wrap(modulus_list, exp_list)
      err -> {:error, {:export_failed, err}}
    end
  end

  defp do_wrap(modulus_list, exp_list) do
    modulus = modulus_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
    exp = exp_list |> IO.iodata_to_binary() |> :binary.decode_unsigned(:big)
    rsa_pubkey = {:RSAPublicKey, modulus, exp}

    issuer_key = X509.PrivateKey.new_rsa(2048)
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-safenet-conf-issuer")

    leaf_cert =
      X509.Certificate.new(rsa_pubkey, "/CN=pkcs11ex-safenet-conf-leaf", issuer_cert, issuer_key)

    der = X509.Certificate.to_der(leaf_cert)
    pem = X509.Certificate.to_pem(leaf_cert)
    {:ok, der, pem}
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

  defp sii_dte_fixture do
    """
    <?xml version="1.0" encoding="ISO-8859-1"?><DTE version="1.0" xmlns="http://www.sii.cl/SiiDte"><Documento ID="F1234T33"><Encabezado><IdDoc><TipoDTE>33</TipoDTE><Folio>1234</Folio><FchEmis>2026-05-06</FchEmis></IdDoc><Emisor><RUTEmisor>76123456-7</RUTEmisor><RznSoc>Test Provider Spa</RznSoc></Emisor><Receptor><RUTRecep>11111111-1</RUTRecep><RznSocRecep>Test Buyer SA</RznSocRecep></Receptor><Totales><MntNeto>1000</MntNeto><IVA>190</IVA><MntTotal>1190</MntTotal></Totales></Encabezado><Detalle><NroLinDet>1</NroLinDet><NmbItem>Test item</NmbItem><QtyItem>1</QtyItem><PrcItem>1000</PrcItem><MontoItem>1000</MontoItem></Detalle></Documento></DTE>
    """
    |> String.trim()
  end
end
