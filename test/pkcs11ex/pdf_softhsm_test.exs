defmodule Pkcs11ex.PDFSofthsmTest do
  @moduledoc """
  End-to-end PAdES B-B sign against SoftHSM2.

  Sign goes through the full pipeline:
  `SignCore.PDF.sign/2` → `SignCore.PDF.Writer.prepare/2` → CMS
  attribute build → `Pkcs11ex.sign_bytes/2` → Layer 2 → NIF → cryptoki
  → SoftHSM2 → `SignCore.CMS.SignedData.build/3` →
  `SignCore.PDF.Writer.inject_signature/2`.

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

  alias SignCore.CMS
  alias Pkcs11ex.PDF
  alias Pkcs11ex.Native
  alias SignCore.PDF.Reader

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
        Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)
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

  describe "verify/2 round-trip" do
    setup ctx do
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          placeholder_size: 4096
        )

      Map.put(ctx, :signed_pdf, signed_pdf)
    end

    test "happy path — Allow policy lets the signed PDF through", ctx do
      assert {:ok, :anyone} = PDF.verify(ctx.signed_pdf)
    end

    test "verify success populates :subject_id in [:pkcs11ex, :verify, :stop] metadata",
         ctx do
      pid = self()
      handler_id = "pdf-verify-subject-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler_id,
        [:pkcs11ex, :verify, :stop],
        fn _evt, _msr, meta, _ -> send(pid, {:verify_stop_meta, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert {:ok, :anyone} = PDF.verify(ctx.signed_pdf)
      assert_received {:verify_stop_meta, meta}
      assert meta.subject_id == :anyone
      assert meta.byte_count == byte_size(ctx.signed_pdf)
      refute Map.has_key?(meta, :error_class)
    end

    test "tampered byte inside the signed range surfaces :message_digest_mismatch", ctx do
      # Catalog object body sits well before the /Sig dict, inside the
      # signed range. Flipping a single byte there must invalidate the
      # CMS messageDigest before any signature math runs.
      pdf = ctx.signed_pdf
      [pos, _len] = Tuple.to_list(:binary.match(pdf, "%PDF-1.7"))
      tampered = replace_byte(pdf, pos, ?X)

      assert {:error, :message_digest_mismatch} = PDF.verify(tampered)
    end

    test "tampered byte inside the hex placeholder is rejected", ctx do
      # Flip a byte inside the /Contents hex region. /ByteRange excludes
      # this region so messageDigest still matches, but the CMS bytes
      # change. Three possible failure modes — all of them are "we
      # caught the tamper":
      #   - :malformed_signature_contents — the new strict DER-length
      #     check rejects CMS that no longer starts with 0x30 (SEQUENCE)
      #   - :signature_invalid             — CMS parses but signature math fails
      #   - {:cms_codec, _, _}             — CMS structure no longer decodable
      pdf = ctx.signed_pdf
      contents_pos = pdf |> :binary.match("/Contents <") |> elem(0) |> Kernel.+(byte_size("/Contents <"))
      tampered = replace_byte(pdf, contents_pos, ?F)

      result = PDF.verify(tampered)

      assert match?({:error, :malformed_signature_contents}, result) or
               match?({:error, :signature_invalid}, result) or
               match?({:error, {:cms_codec, _, _}}, result)
    end

    test "PDF without any /Sig dict surfaces :no_signature" do
      base_pdf = build_minimal_pdf()
      assert {:error, :no_signature} = PDF.verify(base_pdf)
    end

    test "free-text mentioning /ByteRange appended after signature is detected as append-attack", ctx do
      # Pre-fix this returned :multiple_signatures_unsupported_in_v1
      # because the regex-based parser counted the appended `/ByteRange`
      # text as a second signature. With proper xref-based parsing the
      # appended free text is correctly ignored as not-a-Sig-object,
      # and the broader append-attack guard catches the trailing bytes
      # — which is the more accurate response. The dedicated multi-sig
      # rejection test lives in `verify_failure_paths_test.exs` with a
      # correctly-constructed two-Sig fixture.
      forged = ctx.signed_pdf <> "\n%fake-sig\n/ByteRange [0 1 2 3]\n/Contents <00>\n"
      assert {:error, :incremental_update_after_signature} = PDF.verify(forged)
    end

    test "policy refusal short-circuits before any signature math", ctx do
      # Swap the Allow policy for one that refuses everything; verify
      # must return :unknown_signer without crunching the signature.
      Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.PDFSofthsmTest.RefusingPolicy)
      on_exit(fn -> Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow) end)

      assert {:error, :unknown_signer} = PDF.verify(ctx.signed_pdf)
    end

    test "any byte appended after the signed revision is detected", ctx do
      # The canonical "append-attack": take a validly signed PDF and
      # tack additional bytes on the end. /ByteRange's signed length
      # is frozen at sign time, so c+d < byte_size after any append.
      tampered = ctx.signed_pdf <> "X"
      assert {:error, :incremental_update_after_signature} = PDF.verify(tampered)
    end

    test "even a single trailing null byte is detected", ctx do
      tampered = ctx.signed_pdf <> <<0x00>>
      assert {:error, :incremental_update_after_signature} = PDF.verify(tampered)
    end

    test "a forged incremental update appended after the signature is detected", ctx do
      forged_update = "\n4 0 obj\n<< /Forged true >>\nendobj\n"
      tampered = ctx.signed_pdf <> forged_update
      assert {:error, :incremental_update_after_signature} = PDF.verify(tampered)
    end

    test "append-attack is detected before the policy gate runs (fail-fast)", ctx do
      # The check_no_unsigned_trailing_bytes step runs before the
      # policy gate, so even an appended PDF whose chain would fail
      # the policy gets flagged with the more specific
      # :incremental_update_after_signature error.
      Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.PDFSofthsmTest.RefusingPolicy)
      on_exit(fn -> Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow) end)

      tampered = ctx.signed_pdf <> "X"
      assert {:error, :incremental_update_after_signature} = PDF.verify(tampered)
    end
  end

  describe "PAdES B-T (Phase 5 step 8)" do
    @describetag :tsa

    @default_tsa "http://timestamp.digicert.com"
    @signed_data_oid_bytes <<0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02>>
    # id-aa-signatureTimeStampToken: 1.2.840.113549.1.9.16.2.14
    @id_aa_sig_ts_oid_bytes <<0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E>>

    setup do
      tsa_url = System.get_env("PKCS11EX_TSA_URL") || @default_tsa
      {:ok, tsa_url: tsa_url}
    end

    test ":tsa_url attaches a real TimeStampToken as id-aa-signatureTimeStampToken",
         %{
           tsa_url: tsa_url
         } = ctx do
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          tsa_url: tsa_url,
          tsa_timeout: 15_000,
          # 4 KiB B-B fits; B-T adds a TST (~5–7 KiB on DigiCert) so we
          # need a fatter placeholder.
          placeholder_size: 16_384
        )

      # B-T sign-side: the signed PDF still passes B-B verify (the
      # timestamp lives in unsignedAttrs and is not covered by the
      # signature math).
      assert {:ok, :anyone} = PDF.verify(signed_pdf)

      # The CMS embedded in /Contents now carries the signature TST.
      {byte_range, contents_hex} = extract_signature_artifacts(signed_pdf)
      cms_padded = decode_hex_strict_upper(contents_hex)
      cms_der = strip_trailing_zero_padding(cms_padded)

      assert :binary.match(cms_der, @id_aa_sig_ts_oid_bytes) != :nomatch,
             "CMS lacks id-aa-signatureTimeStampToken — B-T attribute missing"

      # The TST itself is a CMS SignedData; its OID must appear inside
      # the encoded unsigned-attribute value.
      sigts_pos = :binary.match(cms_der, @id_aa_sig_ts_oid_bytes) |> elem(0)
      tail = binary_part(cms_der, sigts_pos, byte_size(cms_der) - sigts_pos)

      assert :binary.match(tail, @signed_data_oid_bytes) != :nomatch,
             "TST not embedded as a SignedData ContentInfo"

      [_a, b, c, d] = byte_range
      _ = b
      _ = c
      _ = d
    end

    test "without :tsa_url, the CMS does not carry id-aa-signatureTimeStampToken", ctx do
      base_pdf = build_minimal_pdf()

      {:ok, signed_pdf} =
        PDF.sign(base_pdf,
          module: ctx.pkcs11_module,
          slot_id: ctx.slot_id,
          pin: ctx.pin,
          key_label: ctx.key_label,
          alg: :PS256,
          x5c: ctx.leaf_der,
          placeholder_size: 4_096
        )

      {_, contents_hex} = extract_signature_artifacts(signed_pdf)
      cms_padded = decode_hex_strict_upper(contents_hex)
      cms_der = strip_trailing_zero_padding(cms_padded)

      assert :binary.match(cms_der, @id_aa_sig_ts_oid_bytes) == :nomatch,
             "B-B PDF unexpectedly carries the B-T timestamp attribute"
    end
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

  defmodule RefusingPolicy do
    @moduledoc false
    @behaviour SignCore.Policy
    @impl true
    def resolve(_header, _opts), do: {:error, :unknown_signer}
    @impl true
    def validate(_cert, _chain, _opts), do: {:error, :unknown_signer}
  end

  defp replace_byte(bin, pos, byte) do
    <<prefix::binary-size(pos), _::binary-size(1), rest::binary>> = bin
    <<prefix::binary, byte, rest::binary>>
  end

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
