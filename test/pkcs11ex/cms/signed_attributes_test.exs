defmodule SignCore.CMS.SignedAttributesTest do
  @moduledoc """
  Phase 4a steps 1+2 — `build/1` builds the three RFC 5652 §11
  required attributes; `to_be_signed/1` re-emits them as the universal
  `SET OF Attribute` form for the signature digest.

  Cross-check against `openssl asn1parse` is gated on openssl being
  installed; structural assertions cover the codec wiring without it.
  """

  use ExUnit.Case, async: true

  alias SignCore.CMS.{Codec, OIDs, SignedAttributes}

  @digest_sha256 :crypto.hash(:sha256, "phase 4a smoke payload")
  @id_aa_signing_certificate_v2 {1, 2, 840, 113_549, 1, 9, 16, 2, 47}

  describe "build/1" do
    test "rejects missing digest" do
      assert {:error, :missing_digest} = SignedAttributes.build([])
    end

    test "rejects non-binary digest" do
      assert {:error, :invalid_digest} = SignedAttributes.build(digest: nil)
      assert {:error, :invalid_digest} = SignedAttributes.build(digest: ~c"charlist")
    end

    test "rejects empty digest" do
      assert {:error, :invalid_digest} = SignedAttributes.build(digest: <<>>)
    end

    test "produces three attributes with the correct OIDs by default" do
      assert {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256)
      assert length(attrs) == 3

      types = Enum.map(attrs, fn {:Attribute, oid, _values} -> oid end)
      assert OIDs.id_content_type() in types
      assert OIDs.id_message_digest() in types
      assert OIDs.id_signing_time() in types
    end

    test "messageDigest carries the supplied digest bytes verbatim" do
      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256)
      {:Attribute, _, [digest]} = Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113_549, 1, 9, 4}, _}, &1))
      assert digest == @digest_sha256
    end

    test "contentType defaults to id-data; can be overridden" do
      {:ok, default_attrs} = SignedAttributes.build(digest: @digest_sha256)

      {:Attribute, _, [content_oid]} =
        Enum.find(default_attrs, &match?({:Attribute, {1, 2, 840, 113_549, 1, 9, 3}, _}, &1))

      assert content_oid == OIDs.id_data()

      override = {1, 2, 840, 113_549, 1, 7, 2}

      {:ok, override_attrs} =
        SignedAttributes.build(digest: @digest_sha256, content_oid: override)

      {:Attribute, _, [content_oid_override]} =
        Enum.find(override_attrs, &match?({:Attribute, {1, 2, 840, 113_549, 1, 9, 3}, _}, &1))

      assert content_oid_override == override
    end

    test "signingTime defaults to current UTC; can be overridden; UTCTime in 1950..2049" do
      fixed_dt = ~U[2026-05-04 12:34:56Z]
      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256, signing_time: fixed_dt)

      {:Attribute, _, [time_choice]} =
        Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113_549, 1, 9, 5}, _}, &1))

      assert {:utcTime, ~c"260504123456Z"} = time_choice
    end

    test "signingTime uses GeneralizedTime outside 1950..2049" do
      future = DateTime.from_naive!(~N[2099-01-02 03:04:05], "Etc/UTC")

      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256, signing_time: future)

      {:Attribute, _, [time_choice]} =
        Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113_549, 1, 9, 5}, _}, &1))

      assert {:generalTime, ~c"20990102030405Z"} = time_choice
    end

    test "omits signing-certificate-v2 when :leaf_cert_der is not supplied" do
      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256)

      refute Enum.any?(attrs, &match?({:Attribute, @id_aa_signing_certificate_v2, _}, &1))
    end

    test "appends signing-certificate-v2 when :leaf_cert_der is supplied" do
      leaf_der = "not a real cert but build/1 only hashes it"
      expected_hash = :crypto.hash(:sha256, leaf_der)

      {:ok, attrs} =
        SignedAttributes.build(digest: @digest_sha256, leaf_cert_der: leaf_der)

      assert {:Attribute, @id_aa_signing_certificate_v2, [{:asn1_OPENTYPE, der}]} =
               Enum.find(attrs, &match?({:Attribute, @id_aa_signing_certificate_v2, _}, &1))

      # Minimal SigningCertificateV2 shape, RFC 5035 §3:
      #   SEQUENCE { SEQUENCE OF { SEQUENCE { OCTET STRING certHash } } }
      # With SHA-256, all length fields fit in one byte.
      assert <<0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20, cert_hash::binary-size(32)>> =
               der

      assert cert_hash == expected_hash,
             "certHash must be SHA-256(leaf_cert_der) per RFC 5035 §3"
    end

    test ":signing_certificate=false opts out even when :leaf_cert_der is supplied" do
      {:ok, attrs} =
        SignedAttributes.build(
          digest: @digest_sha256,
          leaf_cert_der: "anything",
          signing_certificate: false
        )

      refute Enum.any?(attrs, &match?({:Attribute, @id_aa_signing_certificate_v2, _}, &1))
    end

    test "signing-certificate-v2 survives the DER round-trip through to_be_signed/decode" do
      leaf_der = "round-trip leaf"
      expected_hash = :crypto.hash(:sha256, leaf_der)

      {:ok, attrs} =
        SignedAttributes.build(digest: @digest_sha256, leaf_cert_der: leaf_der)

      assert {:ok, tbs} = SignedAttributes.to_be_signed(attrs)
      assert {:ok, decoded} = Codec.decode(:SignedAttributes, tbs)

      {:Attribute, @id_aa_signing_certificate_v2, [opaque]} =
        Enum.find(decoded, &match?({:Attribute, @id_aa_signing_certificate_v2, _}, &1))

      # OTP doesn't ship a typed entry for this OID, so the values come
      # back wrapped as raw DER (either as `{:asn1_OPENTYPE, der}` or as
      # the bare binary, depending on OTP version). Accept both.
      der =
        case opaque do
          {:asn1_OPENTYPE, bytes} -> bytes
          bytes when is_binary(bytes) -> bytes
        end

      assert <<0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20, cert_hash::binary-size(32)>> =
               der

      assert cert_hash == expected_hash
    end
  end

  describe "to_be_signed/1" do
    test "produces a DER SET (universal tag 0x31), not [0] IMPLICIT (0xA0)" do
      {:ok, attrs} =
        SignedAttributes.build(digest: @digest_sha256, signing_time: ~U[2026-05-04 12:34:56Z])

      assert {:ok, der} = SignedAttributes.to_be_signed(attrs)
      assert <<0x31, _rest::binary>> = der

      # And not the [0] IMPLICIT form — that's reserved for embedding
      # inside SignerInfo, which the OTP codec emits automatically.
      refute <<0xA0>> == binary_part(der, 0, 1)
    end

    test "decode of to-be-signed bytes round-trips back to the input attributes" do
      {:ok, attrs} =
        SignedAttributes.build(digest: @digest_sha256, signing_time: ~U[2026-05-04 12:34:56Z])

      {:ok, der} = SignedAttributes.to_be_signed(attrs)
      {:ok, decoded} = Codec.decode(:SignedAttributes, der)

      assert is_list(decoded) and length(decoded) == 3

      decoded_oids = Enum.map(decoded, fn {:Attribute, oid, _} -> oid end)
      assert OIDs.id_content_type() in decoded_oids
      assert OIDs.id_message_digest() in decoded_oids
      assert OIDs.id_signing_time() in decoded_oids
    end

    test "to-be-signed bytes are byte-stable across encode/decode cycles" do
      {:ok, attrs} =
        SignedAttributes.build(digest: @digest_sha256, signing_time: ~U[2026-05-04 12:34:56Z])

      {:ok, der1} = SignedAttributes.to_be_signed(attrs)
      {:ok, decoded} = Codec.decode(:SignedAttributes, der1)
      {:ok, der2} = Codec.encode(:SignedAttributes, decoded)

      assert der1 == der2,
             "to-be-signed bytes must be canonical DER — round-trip is a no-op"
    end
  end

  describe "openssl cross-check" do
    @describetag :openssl

    test "to-be-signed bytes parse cleanly via `openssl asn1parse`" do
      if openssl = System.find_executable("openssl") do
        {:ok, attrs} =
          SignedAttributes.build(
            digest: @digest_sha256,
            signing_time: ~U[2026-05-04 12:34:56Z]
          )

        {:ok, der} = SignedAttributes.to_be_signed(attrs)

        path = Path.join(System.tmp_dir!(), "sa_#{System.unique_integer([:positive])}.der")
        File.write!(path, der)
        on_exit(fn -> File.rm(path) end)

        {out, 0} = System.cmd(openssl, ["asn1parse", "-inform", "DER", "-in", path])

        # openssl prints friendly attribute names rather than dotted-decimal.
        assert out =~ ":contentType"
        assert out =~ ":signingTime"
        assert out =~ ":messageDigest"
        assert out =~ ":pkcs7-data", "default contentType value should resolve to id-data"
        assert out =~ "UTCTIME", "signingTime in 1950..2049 should encode as UTCTime"
        # 32-byte SHA-256 digest visible as a hex dump.
        assert out =~ "OCTET STRING"
      else
        :ok
      end
    end
  end
end
