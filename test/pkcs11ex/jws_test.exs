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
      Application.put_env(:pkcs11ex, :trust_policy, Pkcs11ex.Policy.Allow)

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
end
