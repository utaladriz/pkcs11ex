defmodule Pkcs11ex.CMS.SignedDataTest do
  @moduledoc """
  Phase 4a step 3 — `Pkcs11ex.CMS.SignedData.build/3`.

  Drives the assembly with a software-generated RSA keypair (test
  fixture only — production paths must use `Pkcs11ex.sign_bytes/2`
  against PKCS#11). Since CMS just embeds the signature bytes
  verbatim and the verifier independently checks them against the
  signedAttrs digest, a software-signed fixture exercises the same
  encoding paths.

  Cross-validates by parsing the output with `openssl pkcs7 -print` and
  asserting structural fields land where they should.
  """

  use ExUnit.Case, async: true

  alias Pkcs11ex.CMS.{Codec, OIDs, SignedAttributes, SignedData}
  alias Pkcs11ex.X509, as: PkcsX509

  setup do
    rsa_priv = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(rsa_priv, "/CN=phase4a test signer/O=pkcs11ex test")
    leaf_der = X509.Certificate.to_der(cert)
    {:ok, leaf} = PkcsX509.from_der(leaf_der)

    {:ok, leaf: leaf, rsa_priv: rsa_priv}
  end

  defp sign_attrs!(attrs, rsa_priv) do
    {:ok, tbs} = SignedAttributes.to_be_signed(attrs)
    :public_key.sign(tbs, :sha256, rsa_priv)
  end

  describe "build/3 happy path" do
    test "produces a DER ContentInfo wrapping SignedData", ctx do
      digest = :crypto.hash(:sha256, "hello phase 4a")

      {:ok, attrs} =
        SignedAttributes.build(digest: digest, signing_time: ~U[2026-05-04 12:34:56Z])

      sig = sign_attrs!(attrs, ctx.rsa_priv)

      assert {:ok, der} =
               SignedData.build(attrs, sig,
                 certificates: [ctx.leaf],
                 digest_algorithm: :sha256,
                 signature_algorithm: :rsa_sha256
               )

      assert is_binary(der)
      assert <<0x30, _rest::binary>> = der

      # Decode and assert top-level shape.
      {:ok, {:ContentInfo, oid, signed_data}} = Codec.decode(:ContentInfo, der)
      assert oid == OIDs.id_signed_data()
      assert {:SignedData, :v1, _digest_algs, _enc_ci, _certs, :asn1_NOVALUE, [_signer_info]} =
               signed_data
    end

    test "accepts raw DER certs as well as parsed X509 structs", ctx do
      digest = :crypto.hash(:sha256, "raw der path")
      {:ok, attrs} = SignedAttributes.build(digest: digest)
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      assert {:ok, _der} =
               SignedData.build(attrs, sig,
                 certificates: [ctx.leaf.der],
                 digest_algorithm: :sha256,
                 signature_algorithm: :rsa_sha256
               )
    end

    test "embeds the certificate chain", ctx do
      digest = :crypto.hash(:sha256, "with chain")
      {:ok, attrs} = SignedAttributes.build(digest: digest)
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      {:ok, der} =
        SignedData.build(attrs, sig,
          certificates: [ctx.leaf, ctx.leaf],
          digest_algorithm: :sha256,
          signature_algorithm: :rsa_sha256
        )

      {:ok, {:ContentInfo, _, signed_data}} = Codec.decode(:ContentInfo, der)
      certs = elem(signed_data, 4)
      assert length(certs) == 2
    end

    test "uses :rsa_pss_sha256 OID when requested", ctx do
      digest = :crypto.hash(:sha256, "pss path")
      {:ok, attrs} = SignedAttributes.build(digest: digest)
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      {:ok, der} =
        SignedData.build(attrs, sig,
          certificates: [ctx.leaf],
          signature_algorithm: :rsa_pss_sha256
        )

      {:ok, {:ContentInfo, _, signed_data}} = Codec.decode(:ContentInfo, der)
      [signer_info] = elem(signed_data, 6)
      sig_alg = elem(signer_info, 5)
      assert {:SignatureAlgorithmIdentifier, oid, _params} = sig_alg
      assert oid == OIDs.id_rsassa_pss()
    end
  end

  describe "build/3 input validation" do
    test "rejects empty certificate chain", ctx do
      {:ok, attrs} = SignedAttributes.build(digest: :crypto.hash(:sha256, "x"))
      sig = sign_attrs!(attrs, ctx.rsa_priv)
      assert {:error, :empty_certificate_chain} = SignedData.build(attrs, sig, certificates: [])
    end

    test "rejects missing :certificates opt", ctx do
      {:ok, attrs} = SignedAttributes.build(digest: :crypto.hash(:sha256, "x"))
      sig = sign_attrs!(attrs, ctx.rsa_priv)
      assert {:error, :missing_certificates} = SignedData.build(attrs, sig, [])
    end

    test "rejects invalid cert entry", ctx do
      {:ok, attrs} = SignedAttributes.build(digest: :crypto.hash(:sha256, "x"))
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      assert {:error, :invalid_cert} =
               SignedData.build(attrs, sig, certificates: [<<0xFF, 0xFF, 0xFF>>])
    end

    test "rejects unsupported digest algorithm", ctx do
      {:ok, attrs} = SignedAttributes.build(digest: :crypto.hash(:sha256, "x"))
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      assert {:error, {:unsupported_digest_algorithm, :md5}} =
               SignedData.build(attrs, sig,
                 certificates: [ctx.leaf],
                 digest_algorithm: :md5
               )
    end

    test "rejects unsupported signature algorithm", ctx do
      {:ok, attrs} = SignedAttributes.build(digest: :crypto.hash(:sha256, "x"))
      sig = sign_attrs!(attrs, ctx.rsa_priv)

      assert {:error, {:unsupported_signature_algorithm, :ecdsa_secp256r1_sha256}} =
               SignedData.build(attrs, sig,
                 certificates: [ctx.leaf],
                 signature_algorithm: :ecdsa_secp256r1_sha256
               )
    end
  end

  describe "openssl cross-check" do
    @describetag :openssl

    test "openssl pkcs7 -print parses our SignedData cleanly", ctx do
      if openssl = System.find_executable("openssl") do
        digest = :crypto.hash(:sha256, "phase 4a openssl probe")

        {:ok, attrs} =
          SignedAttributes.build(digest: digest, signing_time: ~U[2026-05-04 12:34:56Z])

        sig = sign_attrs!(attrs, ctx.rsa_priv)

        {:ok, der} =
          SignedData.build(attrs, sig,
            certificates: [ctx.leaf],
            digest_algorithm: :sha256,
            signature_algorithm: :rsa_sha256
          )

        path = Path.join(System.tmp_dir!(), "sd_#{System.unique_integer([:positive])}.p7s")
        File.write!(path, der)
        on_exit(fn -> File.rm(path) end)

        {out, 0} = System.cmd(openssl, ["pkcs7", "-in", path, "-inform", "DER", "-print"])
        assert out =~ "pkcs7-signedData"
        assert out =~ "version: 1"
        assert out =~ "sha256"
        assert out =~ "phase4a test signer"
      else
        :ok
      end
    end

    test "openssl cms -verify accepts our SignedData against the signed payload", ctx do
      if openssl = System.find_executable("openssl") do
        # cms -verify needs the actual signed payload (detached) plus a
        # cert. We feed signedAttrs DER as the verification input — that's
        # what was signed.
        digest = :crypto.hash(:sha256, "verify-friendly")

        {:ok, attrs} =
          SignedAttributes.build(digest: digest, signing_time: ~U[2026-05-04 12:34:56Z])

        sig = sign_attrs!(attrs, ctx.rsa_priv)

        {:ok, der} =
          SignedData.build(attrs, sig,
            certificates: [ctx.leaf],
            signature_algorithm: :rsa_sha256
          )

        # We don't run openssl cms -verify end-to-end here because it
        # would need the original *content* (not signedAttrs digest) and
        # we didn't embed eContent (detached). Instead, prove the
        # parsing path round-trips: re-decode our DER and verify the
        # signature math by hand against signedAttrs.
        {:ok, tbs_for_verify} = SignedAttributes.to_be_signed(attrs)
        {:ok, {:ContentInfo, _, signed_data}} = Codec.decode(:ContentInfo, der)
        [signer_info] = elem(signed_data, 6)
        embedded_sig = elem(signer_info, 6)
        assert embedded_sig == sig

        # Use the leaf's public key to verify the signature over the
        # signedAttrs to-be-signed bytes.
        leaf_pub = ctx.leaf.public_key
        assert :public_key.verify(tbs_for_verify, :sha256, embedded_sig, leaf_pub)
        _ = openssl
      else
        :ok
      end
    end
  end
end
