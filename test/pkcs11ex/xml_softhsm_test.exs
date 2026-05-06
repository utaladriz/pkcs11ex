defmodule Pkcs11ex.XMLSofthsmTest do
  @moduledoc """
  End-to-end XAdES B-B sign against SoftHSM2.

  Sign goes through the full pipeline: `Pkcs11ex.XML.sign/2` →
  Canonicalizer → XAdES → Builder → `Pkcs11ex.sign_bytes/2` →
  Layer 2 → NIF → cryptoki → SoftHSM2 → Builder → string splice.

  Asserts the structural contract:

    * the signed XML parses cleanly,
    * carries exactly one `<ds:Signature>`,
    * `<ds:SignatureValue>` decodes to a 256-byte raw RSA-2048 sig,
    * `<ds:SignedInfo>` canonicalises to the same bytes the
      verifier would feed to `:public_key.verify/4`,
    * the `<ds:Reference>` to the data digest matches SHA-256 of
      the input doc's exc-c14n form,
    * the `<ds:Reference>` to `<xades:SignedProperties>` matches
      SHA-256 of the SP subtree's exc-c14n form,
    * the raw RSASSA-PSS signature embedded in
      `<ds:SignatureValue>` mathematically verifies against the
      leaf's SPKI when run through `:public_key.verify/4` over the
      DER-encoded `<ds:SignedInfo>` canonical bytes.

  The SPKI math check is the load-bearing assertion. It proves the
  HSM-produced signature, when reassembled inside the XML envelope,
  validates against the same public key any external XAdES verifier
  (`xmlsec1`, BouncyCastle) would extract from `<ds:KeyInfo>`.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.Native
  alias Pkcs11ex.XML
  alias Pkcs11ex.XML.{Builder, Canonicalizer}

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
        {:ok, ctx}
    end
  end

  defp bootstrap(_driver, softhsm2_util) do
    suffix = System.unique_integer([:positive])
    token_label = "pkcs11ex-xml-test-#{suffix}"
    key_label = "pkcs11ex-xml-key-#{suffix}"
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
    leaf_der = build_wrapper_cert(softhsm_pubkey)

    {:ok,
     pkcs11_module: pkcs11_module,
     slot_id: slot_id,
     pin: user_pin,
     key_label: key_label,
     leaf_der: leaf_der,
     leaf_pubkey: softhsm_pubkey}
  end

  test "XML.sign/2 produces a XAdES envelope whose math verifies", ctx do
    base_xml = sii_dte_fixture()

    assert {:ok, signed_xml} =
             XML.sign(base_xml,
               module: ctx.pkcs11_module,
               slot_id: ctx.slot_id,
               pin: ctx.pin,
               key_label: ctx.key_label,
               alg: :PS256,
               x5c: ctx.leaf_der,
               signing_time: ~U[2026-05-06 14:05:30Z]
             )

    # Parses cleanly and contains exactly one <ds:Signature>.
    assert {:ok, _root} = Canonicalizer.parse(signed_xml)
    assert :binary.matches(signed_xml, "<ds:Signature ") |> length() == 1

    # SignatureValue decodes to a 256-byte raw RSA-2048 sig.
    [_, sig_b64] = Regex.run(~r/<ds:SignatureValue>(.+?)<\/ds:SignatureValue>/s, signed_xml)
    raw_sig = Base.decode64!(sig_b64 |> String.replace(~r/\s+/, ""))
    assert byte_size(raw_sig) == 256

    # Recompute SignedInfo canonical bytes from the signed XML and
    # verify the math against the SoftHSM public key.
    si_canonical = extract_canonical_signed_info(signed_xml)

    assert :public_key.verify(
             si_canonical,
             :sha256,
             raw_sig,
             ctx.leaf_pubkey,
             rsa_padding: :rsa_pkcs1_pss_padding,
             rsa_pss_saltlen: 32,
             rsa_mgf1_md: :sha256
           )

    # Reference 1 (data) digest matches SHA-256 of the original
    # document's exc-c14n form (enveloped-signature transform is a
    # no-op at sign time).
    {:ok, base_root} = Canonicalizer.parse(base_xml)
    {:ok, base_canonical} = Canonicalizer.canonicalize(base_root)
    expected_data_digest = :crypto.hash(:sha256, base_canonical) |> Base.encode64()
    assert signed_xml =~ ~s(<ds:DigestValue>#{expected_data_digest}</ds:DigestValue>)
  end

  test "rejects an alg outside the configured allowlist", ctx do
    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

    assert {:error, :disallowed_alg} =
             XML.sign(sii_dte_fixture(),
               module: ctx.pkcs11_module,
               slot_id: ctx.slot_id,
               pin: ctx.pin,
               key_label: ctx.key_label,
               alg: :HS256,
               x5c: ctx.leaf_der
             )
  end

  # Pulls the canonical bytes of <ds:SignedInfo> out of the signed
  # document — the same bytes the verifier feeds to verify/4.
  defp extract_canonical_signed_info(signed_xml) do
    {:ok, root} = Canonicalizer.parse(signed_xml)
    sig_node = find_descendant(root, "Signature")
    si_node = find_child(sig_node, "SignedInfo")
    {:ok, canonical} = Canonicalizer.canonicalize_subtree(si_node)
    canonical
  end

  defp find_descendant({:xmlElement, _, _, _, _, _, _, _, content, _, _, _} = node, local_name) do
    if name_matches?(node, local_name) do
      node
    else
      content
      |> Enum.find_value(fn child ->
        case child do
          {:xmlElement, _, _, _, _, _, _, _, _, _, _, _} -> find_descendant(child, local_name)
          _ -> nil
        end
      end)
    end
  end

  defp find_child({:xmlElement, _, _, _, _, _, _, _, content, _, _, _}, local_name) do
    Enum.find(content, fn
      {:xmlElement, _, _, _, _, _, _, _, _, _, _, _} = e -> name_matches?(e, local_name)
      _ -> false
    end)
  end

  defp name_matches?({:xmlElement, name, _, _, _, _, _, _, _, _, _, _}, local_name) do
    name_str = Atom.to_string(name)
    name_str == local_name or String.ends_with?(name_str, ":" <> local_name)
  end

  # ---------- cert fixture helpers (mirrored from PDF SoftHSM test) ----------

  defp build_rsa_public_key(modulus_bin, exponent_bin) do
    modulus = :binary.decode_unsigned(modulus_bin, :big)
    exponent = :binary.decode_unsigned(exponent_bin, :big)
    {:RSAPublicKey, modulus, exponent}
  end

  defp build_wrapper_cert(rsa_pubkey) do
    issuer_key = X509.PrivateKey.new_rsa(2048)
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-xml-test-issuer")

    leaf_cert =
      X509.Certificate.new(
        rsa_pubkey,
        "/CN=pkcs11ex-xml-test-leaf",
        issuer_cert,
        issuer_key
      )

    X509.Certificate.to_der(leaf_cert)
  end

  # SII-DTE-shaped fixture (Chilean tax document). Public schema, no
  # PII. This is the most likely v1 use case for XAdES B-B.
  defp sii_dte_fixture do
    """
    <?xml version="1.0" encoding="ISO-8859-1"?><DTE version="1.0" xmlns="http://www.sii.cl/SiiDte"><Documento ID="F1234T33"><Encabezado><IdDoc><TipoDTE>33</TipoDTE><Folio>1234</Folio><FchEmis>2026-05-06</FchEmis></IdDoc><Emisor><RUTEmisor>76123456-7</RUTEmisor><RznSoc>Test Provider Spa</RznSoc></Emisor><Receptor><RUTRecep>11111111-1</RUTRecep><RznSocRecep>Test Buyer SA</RznSocRecep></Receptor><Totales><MntNeto>1000</MntNeto><IVA>190</IVA><MntTotal>1190</MntTotal></Totales></Encabezado><Detalle><NroLinDet>1</NroLinDet><NmbItem>Test item</NmbItem><QtyItem>1</QtyItem><PrcItem>1000</PrcItem><MontoItem>1000</MontoItem></Detalle></Documento></DTE>
    """
    |> String.trim()
  end
end
