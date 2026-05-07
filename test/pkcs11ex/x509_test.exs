defmodule Pkcs11ex.X509Test do
  @moduledoc """
  Direct unit coverage for `SignCore.X509` — the entry point every
  verify path eventually flows through. Pre-existing tests exercise
  `from_der/1` via the pinned-registry / XAdES flows but never assert
  the malformed-input contract directly.
  """

  use ExUnit.Case, async: true

  alias SignCore.X509, as: PkX509

  setup do
    issuer_key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(issuer_key, "/CN=pkcs11ex-x509-test")
    der = X509.Certificate.to_der(cert)
    {:ok, der: der, cert: cert}
  end

  describe "from_der/1 — happy path" do
    test "decodes a valid X.509 DER", %{der: der} do
      assert {:ok, %PkX509{} = parsed} = PkX509.from_der(der)
      assert parsed.der == der
      assert is_tuple(parsed.otp_cert)
      assert elem(parsed.otp_cert, 0) == :OTPCertificate

      # public_key is whatever subjectPublicKey was — for RSA it's an
      # `:RSAPublicKey` record.
      assert is_tuple(parsed.public_key)
      assert elem(parsed.public_key, 0) == :RSAPublicKey
    end

    test "the DER round-trips byte-identical", %{der: der} do
      {:ok, parsed} = PkX509.from_der(der)
      assert parsed.der == der
    end
  end

  describe "from_der/1 — malformed input" do
    test "empty binary surfaces :invalid_cert" do
      assert {:error, :invalid_cert} = PkX509.from_der(<<>>)
    end

    test "random non-DER garbage surfaces :invalid_cert" do
      assert {:error, :invalid_cert} = PkX509.from_der(<<0xFF, 0xEE, 0xDD>>)
    end

    test "truncated valid DER surfaces :invalid_cert", %{der: der} do
      truncated = binary_part(der, 0, byte_size(der) - 50)
      assert {:error, :invalid_cert} = PkX509.from_der(truncated)
    end

    test "valid DER that isn't an X.509 SEQUENCE surfaces :invalid_cert" do
      # SEQUENCE { OCTET STRING { 'hello' } } — well-formed DER, not a cert.
      not_a_cert = <<0x30, 0x07, 0x04, 0x05, ?h, ?e, ?l, ?l, ?o>>
      assert {:error, :invalid_cert} = PkX509.from_der(not_a_cert)
    end

    test "single-byte input surfaces :invalid_cert" do
      assert {:error, :invalid_cert} = PkX509.from_der(<<0x30>>)
    end

    test "non-binary input fails the guard" do
      assert_raise FunctionClauseError, fn -> PkX509.from_der(:not_a_binary) end
      assert_raise FunctionClauseError, fn -> PkX509.from_der(nil) end
      assert_raise FunctionClauseError, fn -> PkX509.from_der(123) end
    end
  end

  describe "spki_sha256/1" do
    test "returns a 64-char lowercase hex string", %{der: der} do
      {:ok, parsed} = PkX509.from_der(der)
      hash = PkX509.spki_sha256(parsed)

      assert is_binary(hash)
      assert byte_size(hash) == 64
      assert hash =~ ~r/^[0-9a-f]{64}$/
    end

    test "matches a hand-computed SHA-256 of the cert's SubjectPublicKeyInfo DER", %{der: der} do
      {:ok, parsed} = PkX509.from_der(der)

      # Replicate the canonical SPKI extraction independently:
      # plain decode -> tbs.subjectPublicKeyInfo (slot 7) -> der_encode.
      plain_cert = :public_key.pkix_decode_cert(der, :plain)
      plain_tbs = elem(plain_cert, 1)
      plain_spki = elem(plain_tbs, 7)
      spki_der = :public_key.der_encode(:SubjectPublicKeyInfo, plain_spki)
      expected = :crypto.hash(:sha256, spki_der) |> Base.encode16(case: :lower)

      assert PkX509.spki_sha256(parsed) == expected
    end

    test "is stable: same cert always yields the same pin", %{der: der} do
      {:ok, parsed} = PkX509.from_der(der)
      a = PkX509.spki_sha256(parsed)
      b = PkX509.spki_sha256(parsed)
      assert a == b
    end

    test "differs across distinct keypairs (basic collision sanity check)" do
      der_a =
        X509.PrivateKey.new_rsa(2048)
        |> X509.Certificate.self_signed("/CN=a")
        |> X509.Certificate.to_der()

      der_b =
        X509.PrivateKey.new_rsa(2048)
        |> X509.Certificate.self_signed("/CN=b")
        |> X509.Certificate.to_der()

      {:ok, a} = PkX509.from_der(der_a)
      {:ok, b} = PkX509.from_der(der_b)
      refute PkX509.spki_sha256(a) == PkX509.spki_sha256(b)
    end
  end
end
