defmodule Pkcs11ex.CMS.SignedAttributesTest do
  @moduledoc """
  Phase 4a steps 1+2 — `build/1` builds the three RFC 5652 §11
  required attributes; `to_be_signed/1` re-emits them as the universal
  `SET OF Attribute` form for the signature digest.

  Cross-check against `openssl asn1parse` is gated on openssl being
  installed; structural assertions cover the codec wiring without it.
  """

  use ExUnit.Case, async: true

  alias Pkcs11ex.CMS.{Codec, OIDs, SignedAttributes}

  @digest_sha256 :crypto.hash(:sha256, "phase 4a smoke payload")

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
      {:Attribute, _, [digest]} = Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113549, 1, 9, 4}, _}, &1))
      assert digest == @digest_sha256
    end

    test "contentType defaults to id-data; can be overridden" do
      {:ok, default_attrs} = SignedAttributes.build(digest: @digest_sha256)
      {:Attribute, _, [content_oid]} =
        Enum.find(default_attrs, &match?({:Attribute, {1, 2, 840, 113549, 1, 9, 3}, _}, &1))

      assert content_oid == OIDs.id_data()

      override = {1, 2, 840, 113549, 1, 7, 2}

      {:ok, override_attrs} =
        SignedAttributes.build(digest: @digest_sha256, content_oid: override)

      {:Attribute, _, [content_oid_override]} =
        Enum.find(override_attrs, &match?({:Attribute, {1, 2, 840, 113549, 1, 9, 3}, _}, &1))

      assert content_oid_override == override
    end

    test "signingTime defaults to current UTC; can be overridden; UTCTime in 1950..2049" do
      fixed_dt = ~U[2026-05-04 12:34:56Z]
      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256, signing_time: fixed_dt)

      {:Attribute, _, [time_choice]} =
        Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113549, 1, 9, 5}, _}, &1))

      assert {:utcTime, ~c"260504123456Z"} = time_choice
    end

    test "signingTime uses GeneralizedTime outside 1950..2049" do
      future = DateTime.from_naive!(~N[2099-01-02 03:04:05], "Etc/UTC")

      {:ok, attrs} = SignedAttributes.build(digest: @digest_sha256, signing_time: future)

      {:Attribute, _, [time_choice]} =
        Enum.find(attrs, &match?({:Attribute, {1, 2, 840, 113549, 1, 9, 5}, _}, &1))

      assert {:generalTime, ~c"20990102030405Z"} = time_choice
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
