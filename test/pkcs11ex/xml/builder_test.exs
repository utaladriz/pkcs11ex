defmodule SignCore.XML.BuilderTest do
  @moduledoc """
  Unit tests for `SignCore.XML.Builder`. Verify that:

    * Generated `<ds:Reference>`, `<ds:SignedInfo>`, and
      `<ds:Signature>` strings parse cleanly through xmerl.
    * The Builder honours the URI mappings for the JOSE algs we
      support.
    * The output canonicalises deterministically via the Phase
      4b.1.0 `SignCore.XML.Canonicalizer` (the bytes a verifier
      actually digests).
  """

  use ExUnit.Case, async: true

  alias SignCore.XML.{Builder, Canonicalizer}

  describe "URI helpers" do
    test "signature_method_uri/1 maps PS256 and RS256" do
      assert Builder.signature_method_uri(:PS256) =~ "sha256-rsa-MGF1"
      assert Builder.signature_method_uri(:RS256) =~ "rsa-sha256"
    end

    test "alg_from_signature_method_uri/1 round-trips" do
      assert {:ok, :PS256} = Builder.alg_from_signature_method_uri(Builder.signature_method_uri(:PS256))
      assert {:ok, :RS256} = Builder.alg_from_signature_method_uri(Builder.signature_method_uri(:RS256))
    end

    test "alg_from_signature_method_uri/1 rejects unknown URIs" do
      assert {:error, {:unsupported_signature_method, _}} =
               Builder.alg_from_signature_method_uri("http://example.com/unknown")
    end
  end

  describe "reference/4" do
    test "produces a parseable <ds:Reference>" do
      digest = :crypto.hash(:sha256, "x") |> Base.encode64()

      ref =
        Builder.reference(
          "#object-1",
          [Builder.transform_envelope_uri(), Builder.c14n_exclusive_uri()],
          digest
        )

      # Wrap in a host element so xmerl can parse the namespaced child.
      doc = ~s(<ds:Test xmlns:ds="#{Builder.ds_ns()}">#{ref}</ds:Test>)
      assert {:ok, _} = Canonicalizer.parse(doc)
    end

    test "embeds the supplied URI verbatim (escaped)" do
      digest = "AAAA"

      ref =
        Builder.reference("#with-amp&char", [], digest)

      assert ref =~ ~s(URI="#with-amp&amp;char")
    end

    test "Type attribute when supplied appears in the element" do
      digest = "AAAA"

      ref =
        Builder.reference("#xades-1", [Builder.c14n_exclusive_uri()], digest,
          type: Builder.reference_xades_signed_properties_type()
        )

      assert ref =~ ~s(Type="http://uri.etsi.org/01903#SignedProperties")
    end

    test "transforms list is preserved in document order" do
      digest = "AAAA"

      ref =
        Builder.reference(
          "#x",
          [Builder.transform_envelope_uri(), Builder.c14n_exclusive_uri()],
          digest
        )

      env_pos = pos(ref, "enveloped-signature")
      c14n_pos = pos(ref, "exc-c14n")
      assert env_pos < c14n_pos
    end
  end

  describe "signed_info/2" do
    test "produces a parseable <ds:SignedInfo>" do
      ref =
        Builder.reference("", [Builder.transform_envelope_uri()], "AAAA")

      si = Builder.signed_info([ref], :PS256)

      assert si =~ ~s(<ds:SignedInfo xmlns:ds=)
      assert si =~ ~s(<ds:CanonicalizationMethod)
      assert si =~ ~s(<ds:SignatureMethod)
      assert si =~ Builder.signature_method_uri(:PS256)
      assert {:ok, _} = Canonicalizer.parse(si)
    end

    test "canonicalises deterministically" do
      ref = Builder.reference("", [Builder.transform_envelope_uri()], "AAAA")
      si = Builder.signed_info([ref], :RS256)

      {:ok, root_a} = Canonicalizer.parse(si)
      {:ok, root_b} = Canonicalizer.parse(si)
      {:ok, ca} = Canonicalizer.canonicalize(root_a)
      {:ok, cb} = Canonicalizer.canonicalize(root_b)
      assert ca == cb
    end
  end

  describe "signature/5" do
    test "wraps SignedInfo + value + chain + QP into a parseable envelope" do
      ref = Builder.reference("", [Builder.transform_envelope_uri()], "AAAA")
      si = Builder.signed_info([ref], :PS256)

      sig_value = Base.encode64(<<1, 2, 3>>)
      cert_b64 = Base.encode64(<<0xFF, 0xFE>>)

      qp = ~s(<xades:QualifyingProperties xmlns:xades="#{Builder.xades_ns()}"></xades:QualifyingProperties>)

      sig =
        Builder.signature(si, sig_value, [cert_b64], qp, signature_id: "Signature-test")

      assert sig =~ ~s(Id="Signature-test")
      assert sig =~ "<ds:SignatureValue>" <> sig_value <> "</ds:SignatureValue>"
      assert sig =~ "<ds:X509Certificate>" <> cert_b64 <> "</ds:X509Certificate>"
      assert sig =~ "QualifyingProperties"

      assert {:ok, _} = Canonicalizer.parse(sig)
    end

    test "auto-generates an Id when none supplied" do
      ref = Builder.reference("", [Builder.transform_envelope_uri()], "AAAA")
      si = Builder.signed_info([ref], :PS256)

      qp =
        ~s(<xades:QualifyingProperties xmlns:xades="#{Builder.xades_ns()}"></xades:QualifyingProperties>)

      sig = Builder.signature(si, "AAAA", ["BBBB"], qp)
      assert Regex.match?(~r/Id="Signature-[0-9a-f]{16}"/, sig)
    end
  end

  defp pos(haystack, needle) do
    {p, _} = :binary.match(haystack, needle)
    p
  end
end
