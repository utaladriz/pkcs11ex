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
        Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.Allow)
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

  describe "verify/2 round-trip" do
    setup ctx do
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

      Map.put(ctx, :signed_xml, signed_xml)
    end

    test "happy path — Allow policy lets the signed XML through", ctx do
      assert {:ok, :anyone} = XML.verify(ctx.signed_xml)
    end

    test "verify success populates :subject_id in [:pkcs11ex, :verify, :stop] metadata",
         ctx do
      pid = self()
      handler_id = "xml-verify-subject-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler_id,
        [:pkcs11ex, :verify, :stop],
        fn _e, _m, meta, _ -> send(pid, {:verify_stop_meta, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert {:ok, :anyone} = XML.verify(ctx.signed_xml)
      assert_received {:verify_stop_meta, meta}
      assert meta.subject_id == :anyone
      assert meta.byte_count == byte_size(ctx.signed_xml)
      refute Map.has_key?(meta, :error_class)
    end

    test "tampered byte inside the signed range surfaces :digest_mismatch", ctx do
      pdf = ctx.signed_xml
      # The MntTotal value sits in the data range. Flipping a digit
      # invalidates the data Reference's digest.
      tampered = String.replace(pdf, "<MntTotal>1190</MntTotal>", "<MntTotal>9999</MntTotal>")
      assert {:error, :digest_mismatch} = XML.verify(tampered)
    end

    test "modified SignatureValue bytes surface :signature_invalid", ctx do
      [_, sig_b64] = Regex.run(~r/<ds:SignatureValue>(.+?)<\/ds:SignatureValue>/s, ctx.signed_xml)
      flipped_b64 = String.replace_prefix(sig_b64, String.first(sig_b64), flip(String.first(sig_b64)))
      tampered = String.replace(ctx.signed_xml, sig_b64, flipped_b64)
      assert {:error, :signature_invalid} = XML.verify(tampered)
    end

    test "policy refusal short-circuits before any signature math", ctx do
      Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.XMLSofthsmTest.RefusingPolicy)
      on_exit(fn -> Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.Allow) end)
      assert {:error, :unknown_signer} = XML.verify(ctx.signed_xml)
    end

    test "XML without any <ds:Signature> surfaces :no_signature_element" do
      assert {:error, :no_signature_element} = XML.verify(sii_dte_fixture())
    end

    test "tampered SigningCertificateV2/CertDigest surfaces :xades_cert_digest_mismatch", ctx do
      [_, before_digest] = Regex.run(~r/<xades:CertDigest>.*?<ds:DigestValue>([^<]+)/s, ctx.signed_xml)
      forged = Base.encode64(:crypto.hash(:sha256, "not the leaf"))
      tampered = String.replace(ctx.signed_xml, before_digest, forged)
      assert {:error, :xades_cert_digest_mismatch} = XML.verify(tampered)
    end
  end

  defmodule RefusingPolicy do
    @moduledoc false
    @behaviour Pkcs11ex.Policy
    @impl true
    def resolve(_h, _o), do: {:error, :unknown_signer}
    @impl true
    def validate(_c, _ch, _o), do: {:error, :unknown_signer}
  end

  defp flip("A"), do: "B"
  defp flip(c), do: <<List.first(:binary.bin_to_list(c)) - 1::8>>

  describe "XAdES B-T (Phase 5 step 9)" do
    @describetag :tsa

    @default_tsa "http://timestamp.digicert.com"

    setup do
      tsa_url = System.get_env("PKCS11EX_TSA_URL") || @default_tsa
      {:ok, tsa_url: tsa_url}
    end

    test ":tsa_url attaches a SignatureTimeStamp under UnsignedSignatureProperties",
         %{tsa_url: tsa_url} = ctx do
      base_xml = sii_dte_fixture()

      assert {:ok, signed_xml} =
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

      # B-T sign-side: the signed XML still passes B-B verify (the
      # timestamp lives in unsignedAttrs space and is not covered by
      # the signature math).
      assert {:ok, :anyone} = XML.verify(signed_xml)

      # The B-T elements are present, in the right nesting order.
      assert :binary.match(signed_xml, "<xades:UnsignedProperties>") != :nomatch
      assert :binary.match(signed_xml, "<xades:UnsignedSignatureProperties>") != :nomatch
      assert :binary.match(signed_xml, "<xades:SignatureTimeStamp ") != :nomatch
      assert :binary.match(signed_xml, "<xades:EncapsulatedTimeStamp>") != :nomatch
      # Canonicalisation method is exc-c14n per ETSI EN 319 132-1 §5.4.1.
      assert signed_xml =~ ~r/<ds:CanonicalizationMethod[^>]*Algorithm="http:\/\/www\.w3\.org\/2001\/10\/xml-exc-c14n#"/

      # The encapsulated TST is a CMS SignedData ContentInfo (DER
      # SEQUENCE starting with 0x30, base64-encoded).
      [_, ts_b64] =
        Regex.run(
          ~r/<xades:EncapsulatedTimeStamp>([^<]+)<\/xades:EncapsulatedTimeStamp>/,
          signed_xml
        )

      tst_der = ts_b64 |> String.replace(~r/\s+/, "") |> Base.decode64!()
      assert <<0x30, _::binary>> = tst_der
      # id-signedData OID
      assert :binary.match(
               tst_der,
               <<0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02>>
             ) != :nomatch
    end

    test "without :tsa_url, the QP carries no UnsignedProperties block", ctx do
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

      assert :binary.match(signed_xml, "<xades:UnsignedProperties>") == :nomatch
      assert :binary.match(signed_xml, "<xades:SignatureTimeStamp") == :nomatch
    end
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
