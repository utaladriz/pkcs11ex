defmodule Pkcs11ex.PDFSofthsmTest do
  @moduledoc """
  End-to-end PAdES B-B sign against SoftHSM2.

  Sign goes through the full pipeline:
  `Pkcs11ex.PDF.sign/2` → `Pkcs11ex.PDF.Writer.prepare/2` → CMS
  attribute build → `Pkcs11ex.sign_bytes/2` → Layer 2 → NIF → cryptoki
  → SoftHSM2 → `Pkcs11ex.CMS.SignedData.build/3` →
  `Pkcs11ex.PDF.Writer.inject_signature/2`.

  Verification is split between this test and step 9. Here we assert
  the structural contract:

    * the signed PDF parses as two revisions (original + signature),
    * `/Contents` decodes back to a valid `id-signedData` ContentInfo,
    * the embedded `messageDigest` PKCS#9 attribute matches
      `SHA-256(signed_input)`,
    * the SignerInfo's `issuerAndSerialNumber` resolves to the leaf
      we passed in `:x5c`,
    * the raw RSASSA-PSS signature embedded in the SignerInfo
      mathematically verifies against the leaf's SPKI when run
      through `:public_key.verify/4` over the DER-encoded
      `signedAttrs`.

  The SPKI math check is the load-bearing assertion. It proves the
  HSM-produced signature, when reassembled inside the CMS, will
  validate against the same public key any external PAdES verifier
  would extract from the embedded `x5c` chain.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias Pkcs11ex.{CMS, PDF}
  alias Pkcs11ex.Native
  alias Pkcs11ex.PDF.Reader

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
    token_label = "pkcs11ex-pdf-test-#{suffix}"
    key_label = "pkcs11ex-pdf-key-#{suffix}"
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

  test "PDF.sign/2 produces a signed PDF whose CMS round-trips and verifies", ctx do
    base_pdf = build_minimal_pdf()
    signing_time = ~U[2026-05-06 14:05:30Z]

    {:ok, signed_pdf} =
      PDF.sign(base_pdf,
        module: ctx.pkcs11_module,
        slot_id: ctx.slot_id,
        pin: ctx.pin,
        key_label: ctx.key_label,
        alg: :PS256,
        x5c: ctx.leaf_der,
        signing_time: signing_time,
        reason: "Round-trip test",
        placeholder_size: 4096
      )

    # Two revisions (original + signature), reachable via /Prev.
    assert {:ok, [head, original]} = Reader.revisions(signed_pdf)
    assert original.size == 4
    assert head.size == 6
    assert head.prev != nil

    # /Contents extracted from the signed file decodes as id-signedData.
    {byte_range, contents_hex} = extract_signature_artifacts(signed_pdf)
    [_a, b, c, d] = byte_range
    assert c == b + byte_size(contents_hex)
    assert b + byte_size(contents_hex) + d == byte_size(signed_pdf)

    cms_padded = decode_hex_strict_upper(contents_hex)
    cms_der = strip_trailing_zero_padding(cms_padded)

    {:ok, parsed} = CMS.SignedData.parse(cms_der)

    # Recompute SHA-256 over the actual signed bytes from the file
    signed_input = binary_part(signed_pdf, 0, b) <> binary_part(signed_pdf, c, d)
    expected_digest = :crypto.hash(:sha256, signed_input)
    assert parsed.message_digest == expected_digest

    # Signing time round-trips through UTCTime to within seconds.
    assert DateTime.diff(parsed.signing_time, signing_time, :second) == 0

    # The SignerInfo resolved the leaf we passed in.
    assert parsed.leaf.der == ctx.leaf_der

    # And — the load-bearing math: the raw RSASSA-PSS signature embedded
    # in the SignerInfo verifies against the leaf's SPKI for the
    # DER-encoded signedAttrs.
    assert :public_key.verify(
             parsed.to_be_signed,
             :sha256,
             parsed.signature,
             ctx.leaf_pubkey,
             rsa_padding: :rsa_pkcs1_pss_padding,
             rsa_pss_saltlen: 32,
             rsa_mgf1_md: :sha256
           )
  end

  test "rejects an alg outside the configured allowlist", ctx do
    base_pdf = build_minimal_pdf()

    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

    assert {:error, :disallowed_alg} =
             PDF.sign(base_pdf,
               module: ctx.pkcs11_module,
               slot_id: ctx.slot_id,
               pin: ctx.pin,
               key_label: ctx.key_label,
               alg: :RS256,
               x5c: ctx.leaf_der
             )
  end

  test "errors when /Sig DER would overflow the placeholder", ctx do
    base_pdf = build_minimal_pdf()

    assert {:error, {:writer, :cms_der_too_large}} =
             PDF.sign(base_pdf,
               module: ctx.pkcs11_module,
               slot_id: ctx.slot_id,
               pin: ctx.pin,
               key_label: ctx.key_label,
               alg: :PS256,
               x5c: ctx.leaf_der,
               # 256 bytes is below the CMS DER for an RSA-2048 PS256 sig
               # plus the embedded x5c — sizing too tight surfaces here.
               placeholder_size: 256
             )
  end

  # ---------- helpers ----------

  defp extract_signature_artifacts(pdf) do
    [_, a, b, c, d] = Regex.run(~r/\/ByteRange \[(\d+) (\d+) (\d+) (\d+)\]/, pdf, capture: :all)
    byte_range = [a, b, c, d] |> Enum.map(&String.to_integer/1)

    [_, hex] = Regex.run(~r/\/Contents <([0-9A-Fa-f]+)>/, pdf, capture: :all)
    {byte_range, hex}
  end

  defp decode_hex_strict_upper(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> bin
      :error -> raise "/Contents was not valid hex"
    end
  end

  # The CMS DER is left-aligned in the placeholder; remaining bytes are
  # `0x00` filler. The DER's length prefix tells us where it actually
  # ends — strip everything past that.
  defp strip_trailing_zero_padding(<<0x30, rest::binary>> = full) do
    {len, _len_octets} = der_length(rest)
    expected_total = byte_size(full) - byte_size(rest) + length_octets_size(rest) + len
    binary_part(full, 0, expected_total)
  end

  defp der_length(<<0::1, len::7, _rest::binary>>), do: {len, 1}

  defp der_length(<<1::1, n::7, rest::binary>>) when n > 0 do
    <<len::size(n)-unit(8), _::binary>> = rest
    {len, 1 + n}
  end

  defp length_octets_size(<<0::1, _len::7, _rest::binary>>), do: 1
  defp length_octets_size(<<1::1, n::7, _rest::binary>>), do: 1 + n

  defp build_rsa_public_key(modulus_bin, exponent_bin) do
    modulus = :binary.decode_unsigned(modulus_bin, :big)
    exponent = :binary.decode_unsigned(exponent_bin, :big)
    {:RSAPublicKey, modulus, exponent}
  end

  defp build_wrapper_cert(rsa_pubkey) do
    issuer_key = X509.PrivateKey.new_rsa(2048)
    issuer_cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-pdf-test-issuer")

    leaf_cert =
      X509.Certificate.new(
        rsa_pubkey,
        "/CN=pkcs11ex-pdf-test-leaf",
        issuer_cert,
        issuer_key
      )

    X509.Certificate.to_der(leaf_cert)
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
