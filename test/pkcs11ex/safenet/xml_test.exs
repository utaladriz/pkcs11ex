defmodule Pkcs11ex.SafeNet.XMLTest do
  @moduledoc """
  XAdES B-B round-trip against the eToken — the full
  `SignCore.XML.sign/2` -> Layer 2 -> NIF -> hardware ->
  `SignCore.XML.verify/2` pipeline on real hardware.

  Same wrapper-cert scheme as the JWS / PDF safenet tests; the
  signature math runs against the eToken's actual private key.

  Opt in:

      PKCS11EX_SAFENET_PIN=<pin> PKCS11EX_SAFENET_KEY_LABEL=<label> \\
        mix test --include safenet test/pkcs11ex/safenet/xml_test.exs
  """

  use ExUnit.Case, async: false

  @moduletag :safenet

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot.Server
  alias Pkcs11ex.Test.SafeNet
  alias Pkcs11ex.XML
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
              String.to_atom("safenet_xml_#{System.unique_integer([:positive])}")

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
            Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

            {:ok, slot_ref: slot_ref, leaf_der: leaf_der}
          else
            {:error, reason} ->
              {:skip, "SafeNet bootstrap failed: #{inspect(reason)}"}
          end
      end
    end

    test "XML.sign/2 + XML.verify/2 round trip on the eToken", ctx do
      base_xml = sii_dte_fixture()

      assert {:ok, signed_xml} =
               XML.sign(base_xml,
                 signer: {ctx.slot_ref, :signing},
                 alg: :PS256,
                 x5c: ctx.leaf_der,
                 pin: @pin
               )

      assert {:ok, :anyone} = XML.verify(signed_xml)

      # Output carries the canonical XAdES B-B markers.
      assert signed_xml =~ "<ds:Signature "
      assert signed_xml =~ "<xades:QualifyingProperties "
      assert signed_xml =~ "<xades:SigningCertificateV2>"
    end

    test "tampered XML data is rejected", ctx do
      base_xml = sii_dte_fixture()

      {:ok, signed_xml} =
        XML.sign(base_xml,
          signer: {ctx.slot_ref, :signing},
          alg: :PS256,
          x5c: ctx.leaf_der,
          pin: @pin
        )

      tampered = String.replace(signed_xml, "<MntTotal>1190</MntTotal>", "<MntTotal>9999</MntTotal>")
      assert {:error, :digest_mismatch} = XML.verify(tampered)
    end
  else
    test "skipped — supply PKCS11EX_SAFENET_PIN and PKCS11EX_SAFENET_KEY_LABEL to run" do
      IO.puts("[skip] Pkcs11ex.SafeNet.XMLTest — env vars required.")
    end
  end

  # ---------- helpers ----------

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
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-safenet-issuer")

    leaf_cert =
      X509.Certificate.new(rsa_pubkey, "/CN=pkcs11ex-safenet-xml-leaf", issuer_cert, issuer_key)

    {:ok, X509.Certificate.to_der(leaf_cert)}
  end

  defp sii_dte_fixture do
    """
    <?xml version="1.0" encoding="ISO-8859-1"?><DTE version="1.0" xmlns="http://www.sii.cl/SiiDte"><Documento ID="F1234T33"><Encabezado><IdDoc><TipoDTE>33</TipoDTE><Folio>1234</Folio><FchEmis>2026-05-06</FchEmis></IdDoc><Emisor><RUTEmisor>76123456-7</RUTEmisor><RznSoc>Test Provider Spa</RznSoc></Emisor><Receptor><RUTRecep>11111111-1</RUTRecep><RznSocRecep>Test Buyer SA</RznSocRecep></Receptor><Totales><MntNeto>1000</MntNeto><IVA>190</IVA><MntTotal>1190</MntTotal></Totales></Encabezado><Detalle><NroLinDet>1</NroLinDet><NmbItem>Test item</NmbItem><QtyItem>1</QtyItem><PrcItem>1000</PrcItem><MontoItem>1000</MontoItem></Detalle></Documento></DTE>
    """
    |> String.trim()
  end
end
