# Tiny in-test signer that fulfils the SignCore.Signer protocol with
# a software RSA key. Defined first so the test module below can
# reference `%JWSTestSigner{}` in setup blocks.
defmodule JWSTestSigner do
  defstruct [:rsa_key]

  defimpl SignCore.Signer do
    def sign(%JWSTestSigner{rsa_key: key}, tbs, opts) do
      alg = Keyword.fetch!(opts, :alg)
      encoding_context = Keyword.get(opts, :encoding_context, :der)

      raw =
        case alg do
          :PS256 ->
            :public_key.sign(tbs, :sha256, key,
              rsa_padding: :rsa_pkcs1_pss_padding,
              rsa_pss_saltlen: 32,
              rsa_mgf1_md: :sha256
            )

          :RS256 ->
            :public_key.sign(tbs, :sha256, key)
        end

      with {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
        adapter.encode_signature(raw, encoding_context)
      end
    end
  end
end

defmodule Pkcs11ex.JWSTest do
  use ExUnit.Case, async: false

  setup do
    original = Application.get_env(:pkcs11ex, :allowed_algs)
    on_exit(fn -> Application.put_env(:pkcs11ex, :allowed_algs, original) end)
    Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
    :ok
  end

  # ---------- sign/2 — gate behavior (no NIF reached) ----------

  describe "sign/2 — input validation" do
    test "rejects missing :alg" do
      assert {:error, :missing_alg} =
               Pkcs11ex.JWS.sign("payload", x5c: <<0::256>>, module: :unused, slot_id: 0, key_label: "k")
    end

    test "rejects :alg :none unconditionally" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:none])

      assert {:error, :disallowed_alg} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :none,
                 x5c: <<0::256>>,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k"
               )
    end

    test "rejects alg outside the allowlist" do
      assert {:error, :disallowed_alg} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :ES256,
                 x5c: <<0::256>>,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k"
               )
    end

    test "rejects unsupported alg" do
      Application.put_env(:pkcs11ex, :allowed_algs, [:HS256])

      assert {:error, :unsupported_alg} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :HS256,
                 x5c: <<0::256>>,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k"
               )
    end

    test "rejects missing :x5c" do
      assert {:error, :missing_x5c} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :PS256,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k"
               )
    end

    test "rejects extra_headers that overlap reserved keys" do
      assert {:error, :reserved_header_overlap} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :PS256,
                 x5c: <<0::256>>,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k",
                 extra_headers: %{"alg" => "RS256"}
               )

      assert {:error, :reserved_header_overlap} =
               Pkcs11ex.JWS.sign("payload",
                 alg: :PS256,
                 x5c: <<0::256>>,
                 module: :unused,
                 slot_id: 0,
                 key_label: "k",
                 extra_headers: %{x5c: ["foo"]}
               )
    end
  end

  # ---------- verify/3 — input validation (no NIF reached) ----------

  describe "verify/3 — malformed input" do
    test "rejects a JWS with the wrong number of segments" do
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify("not.a.detached.jws", "payload")
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify("only_two.segments", "payload")
    end

    test "rejects a JWS with non-empty middle segment" do
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify("aaa.bbb.ccc", "payload")
    end

    test "rejects bogus base64url in the header segment" do
      bad = "!!!.." <> Base.url_encode64("xxx", padding: false)
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify(bad, "payload")
    end

    test "rejects header that isn't valid JSON" do
      header = Base.url_encode64("not json", padding: false)
      sig = Base.url_encode64("xxx", padding: false)
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify("#{header}..#{sig}", "payload")
    end

    test "rejects header missing :alg" do
      header_json = Jason.encode!(%{"b64" => false, "crit" => ["b64"], "x5c" => []})
      header_b64 = Base.url_encode64(header_json, padding: false)
      sig = Base.url_encode64("xxx", padding: false)

      assert {:error, :missing_required_header} =
               Pkcs11ex.JWS.verify("#{header_b64}..#{sig}", "payload")
    end

    test "rejects header with b64=true (b64/crit violation)" do
      header_json = Jason.encode!(%{"alg" => "PS256", "b64" => true, "crit" => ["b64"], "x5c" => []})
      header_b64 = Base.url_encode64(header_json, padding: false)
      sig = Base.url_encode64("xxx", padding: false)

      assert {:error, :b64_crit_violation} =
               Pkcs11ex.JWS.verify("#{header_b64}..#{sig}", "payload")
    end

    test "rejects header where crit doesn't include b64" do
      header_json =
        Jason.encode!(%{"alg" => "PS256", "b64" => false, "crit" => ["other"], "x5c" => []})

      header_b64 = Base.url_encode64(header_json, padding: false)
      sig = Base.url_encode64("xxx", padding: false)

      assert {:error, :b64_crit_violation} =
               Pkcs11ex.JWS.verify("#{header_b64}..#{sig}", "payload")
    end

    test "rejects header with disallowed alg" do
      header_json = Jason.encode!(%{"alg" => "ES256", "b64" => false, "crit" => ["b64"], "x5c" => []})
      header_b64 = Base.url_encode64(header_json, padding: false)
      sig = Base.url_encode64("xxx", padding: false)

      assert {:error, :disallowed_alg} =
               Pkcs11ex.JWS.verify("#{header_b64}..#{sig}", "payload")
    end
  end

  # ---------- Software-side round trip with verify/3 ----------
  # Sign with a software RSA key (using OTP :public_key) and verify with
  # Pkcs11ex.JWS.verify/3. Exercises the verify pipeline end-to-end without
  # needing PKCS#11. The Allow policy decodes the leaf from x5c and accepts.

  describe "verify/3 — software-side round trip" do
    setup do
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      pubkey = X509.PublicKey.derive(software_key)
      cert = X509.Certificate.self_signed(software_key, "/CN=pkcs11ex-test", template: :server)
      der = X509.Certificate.to_der(cert)

      {:ok, software_key: software_key, pubkey: pubkey, der: der}
    end

    test "valid signature verifies", %{software_key: key, der: der} do
      payload = "hello pkcs11ex"
      jws = manually_build_jws(payload, key, der)

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "tampered payload is rejected", %{software_key: key, der: der} do
      payload = "hello pkcs11ex"
      jws = manually_build_jws(payload, key, der)

      assert {:error, :signature_invalid} = Pkcs11ex.JWS.verify(jws, "tampered " <> payload)
    end

    test "wrong cert (different key) is rejected", %{software_key: key} do
      payload = "hello pkcs11ex"

      other_key = X509.PrivateKey.new_rsa(2048)
      other_der = X509.Certificate.self_signed(other_key, "/CN=other") |> X509.Certificate.to_der()

      jws = manually_build_jws(payload, key, other_der)

      assert {:error, :signature_invalid} = Pkcs11ex.JWS.verify(jws, payload)
    end
  end

  # ---------- Helper: hand-construct a JWS with a software RSA key ----------

  defp manually_build_jws(payload, software_key, leaf_der) do
    header =
      Jason.encode!(%{
        "alg" => "PS256",
        "b64" => false,
        "crit" => ["b64"],
        "x5c" => [Base.encode64(leaf_der)]
      })

    header_b64 = Base.url_encode64(header, padding: false)
    signing_input = <<header_b64::binary, ?., payload::binary>>

    sig =
      :public_key.sign(signing_input, :sha256, software_key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      )

    sig_b64 = Base.url_encode64(sig, padding: false)
    "#{header_b64}..#{sig_b64}"
  end

  # ---------- Attached JWS (RFC 7515) ----------

  describe "sign/2 — attached form" do
    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-attached-test", template: :server)
      der = X509.Certificate.to_der(cert)
      signer = %JWSTestSigner{rsa_key: software_key}

      {:ok, signer: signer, der: der, software_key: software_key}
    end

    test "produces a 3-segment attached JWS with payload in the middle", ctx do
      payload = "hello attached jws"

      assert {:ok, jws} =
               SignCore.JWS.sign(payload,
                 signer: ctx.signer,
                 alg: :PS256,
                 x5c: ctx.der,
                 attached: true
               )

      assert [header_b64, payload_b64, sig_b64] = String.split(jws, ".", parts: 3)
      assert header_b64 != ""
      assert payload_b64 != ""
      assert sig_b64 != ""

      # Middle segment decodes back to the original payload bytes.
      assert Base.url_decode64!(payload_b64, padding: false) == payload

      # Header doesn't carry b64/crit (those are RFC 7797 detached markers).
      header = header_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()
      refute Map.has_key?(header, "b64")
      refute Map.has_key?(header, "crit")
    end

    test "verify auto-detects attached form (no payload arg needed)", ctx do
      payload = "hello attached jws"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          x5c: ctx.der,
          attached: true
        )

      # Pass nil for payload — the verifier extracts it from the middle segment.
      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, nil)
    end

    test "verify cross-checks supplied payload against the embedded one", ctx do
      payload = "hello attached jws"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          x5c: ctx.der,
          attached: true
        )

      # Supplied payload matches embedded → OK.
      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)

      # Supplied payload differs from embedded → :payload_mismatch.
      assert {:error, :payload_mismatch} =
               Pkcs11ex.JWS.verify(jws, "different payload")
    end

    test "tampered attached payload fails signature verify", ctx do
      payload = "hello attached jws"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          x5c: ctx.der,
          attached: true
        )

      # Replace the middle segment with a different (valid base64url) payload.
      [h, _p, s] = String.split(jws, ".", parts: 3)
      tampered = "#{h}.#{Base.url_encode64("tampered", padding: false)}.#{s}"

      assert {:error, :signature_invalid} = Pkcs11ex.JWS.verify(tampered, nil)
    end

    test "detached default still works after the attached changes", ctx do
      payload = "hello detached jws"

      {:ok, jws} =
        SignCore.JWS.sign(payload, signer: ctx.signer, alg: :PS256, x5c: ctx.der)

      # Empty middle segment — detached marker.
      assert [_h, "", _s] = String.split(jws, ".", parts: 3)

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "detached verify rejects nil payload with :missing_payload", ctx do
      payload = "hello"

      {:ok, jws} =
        SignCore.JWS.sign(payload, signer: ctx.signer, alg: :PS256, x5c: ctx.der)

      assert {:error, :missing_payload} = Pkcs11ex.JWS.verify(jws, nil)
    end
  end

  # ---------- Kid-only JWS (no x5c in header, kid lookup at verify) ----------

  describe "sign/2 — kid-only flow (optional x5c)" do
    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-kid-test", template: :server)
      der = X509.Certificate.to_der(cert)
      signer = %JWSTestSigner{rsa_key: software_key}

      {:ok, signer: signer, der: der}
    end

    test "x5c may be omitted when extra_headers carries a kid", ctx do
      payload = "kid-only jws"
      kid = "acme-2025"

      assert {:ok, jws} =
               SignCore.JWS.sign(payload,
                 signer: ctx.signer,
                 alg: :PS256,
                 extra_headers: %{"kid" => kid}
               )

      header = jws |> String.split(".") |> hd() |> Base.url_decode64!(padding: false) |> Jason.decode!()
      refute Map.has_key?(header, "x5c")
      assert header["kid"] == kid
    end

    test "kid-only JWS verifies via :kid_certs lookup", ctx do
      payload = "kid-only jws"
      kid = "acme-2025"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          extra_headers: %{"kid" => kid}
        )

      assert {:ok, :anyone} =
               Pkcs11ex.JWS.verify(jws, payload, kid_certs: %{kid => ctx.der})
    end

    test "kid-only JWS without :kid_certs falls back to policy.resolve (Allow refuses sans x5c)", ctx do
      payload = "kid-only jws"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          extra_headers: %{"kid" => "acme-2025"}
        )

      # Allow policy looks for x5c in the header — without it, it returns
      # :unknown_signer. Caller has to bring :kid_certs OR a kid-aware policy.
      assert {:error, :unknown_signer} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "missing both x5c and kid still fails fast with :missing_x5c", ctx do
      assert {:error, :missing_x5c} =
               SignCore.JWS.sign("nope",
                 signer: ctx.signer,
                 alg: :PS256
               )
    end

    test "kid + attached works in combination", ctx do
      payload = "kid-only attached"
      kid = "acme-2025"

      {:ok, jws} =
        SignCore.JWS.sign(payload,
          signer: ctx.signer,
          alg: :PS256,
          attached: true,
          extra_headers: %{"kid" => kid}
        )

      assert [_h, p, _s] = String.split(jws, ".", parts: 3)
      assert p != ""

      assert {:ok, :anyone} =
               Pkcs11ex.JWS.verify(jws, nil, kid_certs: %{kid => ctx.der})
    end
  end

  # ---------- Signature timestamp (B-T) — Flattened JSON Serialization ----------

  describe "JWS B-T — verify on hand-built Flattened JSON envelopes" do
    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-bt-test", template: :server)
      der = X509.Certificate.to_der(cert)

      {:ok, software_key: software_key, der: der}
    end

    test "verify accepts JSON-form attached JWS", %{software_key: key, der: der} do
      payload = "hello bt jws"
      tst = <<0xDE, 0xAD, 0xBE, 0xEF>>
      jws = manually_build_json_jws(payload, key, der, attached: true, tst: tst)

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, nil)
    end

    test "verify accepts JSON-form detached JWS with external payload", %{software_key: key, der: der} do
      payload = "hello bt detached"
      jws = manually_build_json_jws(payload, key, der, attached: false, tst: <<1, 2, 3>>)

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "verify on JSON-form detached without payload arg returns :missing_payload",
         %{software_key: key, der: der} do
      jws = manually_build_json_jws("p", key, der, attached: false, tst: <<>>)

      assert {:error, :missing_payload} = Pkcs11ex.JWS.verify(jws, nil)
    end

    test "verify on JSON-form attached cross-checks supplied payload (mismatch rejected)",
         %{software_key: key, der: der} do
      payload = "hello"
      jws = manually_build_json_jws(payload, key, der, attached: true, tst: <<>>)

      assert {:error, :payload_mismatch} = Pkcs11ex.JWS.verify(jws, "tampered")
    end

    test "verify rejects JSON envelope with missing :protected",
         %{software_key: key, der: der} do
      payload = "x"
      good = manually_build_json_jws(payload, key, der, attached: true, tst: <<>>)
      decoded = Jason.decode!(good)
      bad = decoded |> Map.delete("protected") |> Jason.encode!()

      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify(bad, nil)
    end

    test "verify rejects JSON envelope with missing :signature",
         %{software_key: key, der: der} do
      good = manually_build_json_jws("x", key, der, attached: true, tst: <<>>)
      bad = good |> Jason.decode!() |> Map.delete("signature") |> Jason.encode!()

      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify(bad, nil)
    end

    test "verify rejects malformed JSON" do
      assert {:error, :malformed_jws} = Pkcs11ex.JWS.verify("{not json", nil)
    end

    test "tampered payload in JSON form is rejected", %{software_key: key, der: der} do
      payload = "hello"
      good = manually_build_json_jws(payload, key, der, attached: true, tst: <<>>)
      decoded = Jason.decode!(good)

      tampered =
        decoded
        |> Map.put("payload", Base.url_encode64("evil", padding: false))
        |> Jason.encode!()

      assert {:error, :signature_invalid} = Pkcs11ex.JWS.verify(tampered, nil)
    end
  end

  describe "extract_tst/1" do
    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-tst-extract", template: :server)
      der = X509.Certificate.to_der(cert)

      {:ok, software_key: software_key, der: der}
    end

    test "returns the TST bytes from a JSON-form JWS", %{software_key: key, der: der} do
      tst = :crypto.strong_rand_bytes(64)
      jws = manually_build_json_jws("p", key, der, attached: true, tst: tst)

      assert {:ok, ^tst} = Pkcs11ex.JWS.extract_tst(jws)
    end

    test "returns :no_timestamp for compact-form input", %{software_key: key, der: der} do
      jws = manually_build_jws("p", key, der)
      assert {:error, :no_timestamp} = Pkcs11ex.JWS.extract_tst(jws)
    end

    test "returns :no_timestamp for JSON without x-tst", %{software_key: key, der: der} do
      jws = manually_build_json_jws("p", key, der, attached: true, tst: <<>>)
      stripped = jws |> Jason.decode!() |> Map.put("header", %{}) |> Jason.encode!()
      assert {:error, :no_timestamp} = Pkcs11ex.JWS.extract_tst(stripped)
    end
  end

  describe "sign/2 — :tsa_url gate" do
    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-tsa-gate-test", template: :server)
      der = X509.Certificate.to_der(cert)
      signer = %JWSTestSigner{rsa_key: software_key}

      {:ok, signer: signer, der: der}
    end

    test "an unreachable :tsa_url surfaces as {:bt_failed, _}", ctx do
      # Localhost on a port nobody listens on — the RFC3161 client should
      # fail to connect and we should get the timestamp-gate's error wrapper.
      assert {:error, {:bt_failed, _reason}} =
               SignCore.JWS.sign("hello",
                 signer: ctx.signer,
                 alg: :PS256,
                 x5c: ctx.der,
                 tsa_url: "http://127.0.0.1:1/no-tsa-here",
                 tsa_timeout: 500
               )
    end
  end

  # Live RFC 3161 round-trip against the public DigiCert TSA. Tagged
  # `:tsa` so it's opt-in like the other TSA-dependent tests in
  # this repo (PAdES B-T, XAdES B-T).
  describe "sign/2 + verify/3 — live signature timestamp (DigiCert)" do
    @describetag :tsa

    setup do
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])
      Application.put_env(:pkcs11ex, :trust_policy, SignCore.Policy.Allow)

      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-bt-live", template: :server)
      der = X509.Certificate.to_der(cert)
      signer = %JWSTestSigner{rsa_key: software_key}

      {:ok, signer: signer, der: der}
    end

    test "attached JWS round-trips with TST in unprotected header", ctx do
      payload = "hello bt live"

      assert {:ok, jws} =
               SignCore.JWS.sign(payload,
                 signer: ctx.signer,
                 alg: :PS256,
                 x5c: ctx.der,
                 attached: true,
                 tsa_url: "http://timestamp.digicert.com",
                 tsa_timeout: 15_000
               )

      # Output is JSON Flattened Serialization, not compact.
      assert String.starts_with?(jws, "{")
      decoded = Jason.decode!(jws)
      assert is_binary(decoded["protected"])
      assert is_binary(decoded["payload"])
      assert is_binary(decoded["signature"])
      assert is_binary(decoded["header"]["x-tst"])

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, nil)

      # TST is parseable DER (a CMS SignedData wrapper, smoke check on length).
      assert {:ok, tst_der} = Pkcs11ex.JWS.extract_tst(jws)
      assert byte_size(tst_der) > 100
    end

    test "detached JWS round-trips with TST", ctx do
      payload = "hello bt detached live"

      assert {:ok, jws} =
               SignCore.JWS.sign(payload,
                 signer: ctx.signer,
                 alg: :PS256,
                 x5c: ctx.der,
                 tsa_url: "http://timestamp.digicert.com",
                 tsa_timeout: 15_000
               )

      assert String.starts_with?(jws, "{")
      decoded = Jason.decode!(jws)
      # Detached: payload field is omitted from the JSON envelope.
      refute Map.has_key?(decoded, "payload")
      assert is_binary(decoded["header"]["x-tst"])

      assert {:ok, :anyone} = Pkcs11ex.JWS.verify(jws, payload)
    end
  end

  # ---------- Helper: hand-construct a JSON-form JWS with a software RSA key ----------

  defp manually_build_json_jws(payload, software_key, leaf_der, opts) do
    attached = Keyword.fetch!(opts, :attached)
    tst = Keyword.fetch!(opts, :tst)

    base = %{"alg" => "PS256", "x5c" => [Base.encode64(leaf_der)]}

    header_map =
      if attached, do: base, else: Map.merge(base, %{"b64" => false, "crit" => ["b64"]})

    header_b64 = header_map |> Jason.encode!() |> Base.url_encode64(padding: false)

    signing_input =
      if attached do
        payload_b64 = Base.url_encode64(payload, padding: false)
        <<header_b64::binary, ?., payload_b64::binary>>
      else
        <<header_b64::binary, ?., payload::binary>>
      end

    sig =
      :public_key.sign(signing_input, :sha256, software_key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      )

    sig_b64 = Base.url_encode64(sig, padding: false)

    envelope = %{
      "protected" => header_b64,
      "header" => %{"x-tst" => Base.encode64(tst)},
      "signature" => sig_b64
    }

    envelope =
      if attached,
        do: Map.put(envelope, "payload", Base.url_encode64(payload, padding: false)),
        else: envelope

    Jason.encode!(envelope)
  end
end
