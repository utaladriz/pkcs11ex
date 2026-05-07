defmodule SignCore.CMS.CodecTest do
  @moduledoc """
  Phase 4a step 0 smoke tests for `SignCore.CMS.Codec`.

  Validates that the OTP `:CryptographicMessageSyntax-2009` codec is
  callable, that our wrapper flattens errors as documented, and that a
  minimal SignedData ContentInfo round-trips byte-stable.

  Substantive encoding (`build_signed_attributes/1`,
  `signed_attrs_to_be_signed/1`, `build_signed_data/3`) lands in
  Phase 4a steps 1-3.
  """

  use ExUnit.Case, async: true

  alias SignCore.CMS.{Codec, OIDs}

  describe "encode/decode round-trip" do
    test "minimal SignedData ContentInfo (empty signerInfos, detached content)" do
      oid_signed_data = OIDs.id_signed_data()
      oid_data = OIDs.id_data()
      oid_sha256 = OIDs.id_sha256()

      inner =
        {:SignedData, 1, [{:DigestAlgorithmIdentifier, oid_sha256, :asn1_NOVALUE}],
         {:EncapsulatedContentInfo, oid_data, :asn1_NOVALUE}, :asn1_NOVALUE, :asn1_NOVALUE, []}

      ci = {:ContentInfo, oid_signed_data, inner}

      assert {:ok, der} = Codec.encode(:ContentInfo, ci)
      assert is_binary(der)
      assert byte_size(der) > 0
      # DER ContentInfo always starts with SEQUENCE (0x30) tag.
      assert <<0x30, _rest::binary>> = der

      assert {:ok, decoded} = Codec.decode(:ContentInfo, der)
      assert {:ContentInfo, ^oid_signed_data, signed_data} = decoded

      # OTP normalises the version INTEGER to atoms (`:v1` etc).
      assert {:SignedData, :v1, [{:DigestAlgorithmIdentifier, ^oid_sha256, :asn1_NOVALUE}],
              {:EncapsulatedContentInfo, ^oid_data, :asn1_NOVALUE}, :asn1_NOVALUE, :asn1_NOVALUE, []} = signed_data
    end

    test "decode then re-encode is byte-stable" do
      oid_signed_data = OIDs.id_signed_data()
      oid_data = OIDs.id_data()
      oid_sha256 = OIDs.id_sha256()

      inner =
        {:SignedData, 1, [{:DigestAlgorithmIdentifier, oid_sha256, :asn1_NOVALUE}],
         {:EncapsulatedContentInfo, oid_data, :asn1_NOVALUE}, :asn1_NOVALUE, :asn1_NOVALUE, []}

      {:ok, der1} = Codec.encode(:ContentInfo, {:ContentInfo, oid_signed_data, inner})
      {:ok, decoded} = Codec.decode(:ContentInfo, der1)
      {:ok, der2} = Codec.encode(:ContentInfo, decoded)

      assert der1 == der2,
             "DER must be canonical — a decode/re-encode cycle should be a no-op"
    end
  end

  describe "error flattening" do
    test "encode with a malformed term returns {:error, {:cms_codec, ...}}" do
      bad_term = {:ContentInfo, :not_an_oid, "not a valid content"}
      assert {:error, {:cms_codec, :ContentInfo, _reason}} = Codec.encode(:ContentInfo, bad_term)
    end

    test "decode of garbage bytes returns {:error, {:cms_codec, ...}}" do
      assert {:error, {:cms_codec, :ContentInfo, _reason}} =
               Codec.decode(:ContentInfo, <<0xFF, 0xFF, 0xFF>>)
    end
  end

  describe "SignCore.CMS.OIDs" do
    test "OID accessors return the correct dotted-decimal tuples" do
      assert OIDs.id_data() == {1, 2, 840, 113_549, 1, 7, 1}
      assert OIDs.id_signed_data() == {1, 2, 840, 113_549, 1, 7, 2}
      assert OIDs.id_content_type() == {1, 2, 840, 113_549, 1, 9, 3}
      assert OIDs.id_message_digest() == {1, 2, 840, 113_549, 1, 9, 4}
      assert OIDs.id_signing_time() == {1, 2, 840, 113_549, 1, 9, 5}
      assert OIDs.id_sha256() == {2, 16, 840, 1, 101, 3, 4, 2, 1}
    end
  end
end
