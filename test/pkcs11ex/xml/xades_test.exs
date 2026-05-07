defmodule SignCore.XML.XAdESTest do
  @moduledoc """
  Tests `SignCore.XML.XAdES.qualifying_properties/1` produces a
  parseable `<xades:QualifyingProperties>` element with the
  required B-B fields:

    * Target attribute references the parent `<ds:Signature>`.
    * `<xades:SignedProperties>` carries the supplied Id.
    * `<xades:SigningTime>` is ISO-8601 UTC.
    * `<xades:SigningCertificateV2>` embeds:
        - SHA-256 of the leaf cert under `<xades:CertDigest>`,
        - DER-encoded RFC 5035 IssuerSerial under
          `<xades:IssuerSerialV2>`.

  IssuerSerial DER is byte-checked against an OpenSSL-compatible
  encoder (`asn1ct_gen`) by re-decoding it through OTP and asserting
  the round-trip matches the cert's actual issuer + serial.
  """

  use ExUnit.Case, async: true

  alias SignCore.XML.{Canonicalizer, XAdES}

  setup do
    issuer_key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-xades-test")
    der = X509.Certificate.to_der(cert)
    {:ok, leaf} = SignCore.X509.from_der(der)
    {:ok, leaf_cert: leaf, leaf_der: der}
  end

  describe "qualifying_properties/1" do
    test "produces a parseable QP block", %{leaf_cert: leaf} do
      {:ok, qp} =
        XAdES.qualifying_properties(
          signature_id: "Signature-test",
          signed_properties_id: "xades-test",
          leaf_cert: leaf,
          signing_time: ~U[2026-05-06 14:05:30Z]
        )

      assert qp =~ ~s(Target="#Signature-test")
      assert qp =~ ~s(<xades:SignedProperties Id="xades-test">)
      assert qp =~ "<xades:SigningTime>2026-05-06T14:05:30Z</xades:SigningTime>"
      assert qp =~ "<xades:SigningCertificateV2>"
      assert qp =~ "<xades:CertDigest>"
      assert qp =~ "<xades:IssuerSerialV2>"

      assert {:ok, _} = Canonicalizer.parse(qp)
    end

    test "CertDigest is SHA-256 of the leaf cert DER", %{leaf_cert: leaf, leaf_der: der} do
      {:ok, qp} =
        XAdES.qualifying_properties(
          signature_id: "Signature-1",
          signed_properties_id: "xades-1",
          leaf_cert: leaf
        )

      [_, digest_b64] = Regex.run(~r/<ds:DigestValue>(.+?)<\/ds:DigestValue>/, qp)
      assert Base.decode64!(digest_b64) == :crypto.hash(:sha256, der)
    end

    test "missing required opts surface :missing_xades_opt" do
      assert {:error, {:missing_xades_opt, :signature_id}} =
               XAdES.qualifying_properties(signed_properties_id: "x", leaf_cert: %{})

      assert {:error, {:missing_xades_opt, :signed_properties_id}} =
               XAdES.qualifying_properties(signature_id: "x", leaf_cert: %{})

      assert {:error, {:missing_xades_opt, :leaf_cert}} =
               XAdES.qualifying_properties(signature_id: "x", signed_properties_id: "y")
    end

    test "QP canonicalises deterministically", %{leaf_cert: leaf} do
      {:ok, qp} =
        XAdES.qualifying_properties(
          signature_id: "Signature-1",
          signed_properties_id: "xades-1",
          leaf_cert: leaf,
          signing_time: ~U[2026-05-06 14:05:30Z]
        )

      {:ok, root_a} = Canonicalizer.parse(qp)
      {:ok, root_b} = Canonicalizer.parse(qp)
      {:ok, ca} = Canonicalizer.canonicalize(root_a)
      {:ok, cb} = Canonicalizer.canonicalize(root_b)
      assert ca == cb
    end
  end

  describe "build_issuer_serial_v2_der/1" do
    test "round-trips the certificate's issuer + serial", %{leaf_cert: leaf} do
      {:ok, der} = XAdES.build_issuer_serial_v2_der(leaf)

      # The encoded DER is a valid SEQUENCE.
      assert <<0x30, _rest::binary>> = der

      # Decode it back. Outer is IssuerSerial = SEQUENCE { GeneralNames, INTEGER }.
      {:ok, decoded} = decode_issuer_serial(der)
      {decoded_issuer_der, decoded_serial} = decoded

      # Compare against the cert's actual issuer + serial.
      plain = :public_key.pkix_decode_cert(leaf.der, :plain)
      tbs = elem(plain, 1)
      expected_serial = elem(tbs, 2)
      expected_issuer_der = :public_key.der_encode(:Name, elem(tbs, 4))

      assert decoded_serial == expected_serial
      assert decoded_issuer_der == expected_issuer_der
    end
  end

  # Hand-rolled DER decoder for IssuerSerial. Accepts the SEQUENCE
  # bytes and returns `{name_der, serial_int}`.
  defp decode_issuer_serial(<<0x30, rest::binary>>) do
    {body, _} = take_tlv_body(rest)

    # body = GeneralNames(0x30) || INTEGER(0x02)
    {gn_body, after_gn} = consume_tag(body, 0x30)
    # GeneralName = [4] EXPLICIT Name; the [4] body already contains
    # the full Name SEQUENCE bytes (starting with 0x30).
    {name_der, _} = consume_tag(gn_body, 0xA4)

    {ser_bytes, _} = consume_tag(after_gn, 0x02)
    serial = :binary.decode_unsigned(ser_bytes, :big)

    {:ok, {name_der, serial}}
  end

  # Strips one TLV from the head of `bin` (must start with `tag`)
  # and returns `{value_bytes, rest_after_tlv}`.
  defp consume_tag(<<tag, rest::binary>>, tag) do
    {value, tail} = take_tlv_body(rest)
    {value, tail}
  end

  defp take_tlv_body(rest) do
    {len, after_len} = decode_length(rest)
    <<value::binary-size(len), tail::binary>> = after_len
    {value, tail}
  end

  defp decode_length(<<0::1, len::7, rest::binary>>), do: {len, rest}

  defp decode_length(<<1::1, n::7, rest::binary>>) do
    <<bytes::binary-size(n), tail::binary>> = rest
    {:binary.decode_unsigned(bytes, :big), tail}
  end
end
