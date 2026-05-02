defmodule Pkcs11ex.Policy.PinnedRegistryTest do
  use ExUnit.Case, async: false

  alias Pkcs11ex.Policy.PinnedRegistry

  setup do
    # Snapshot whatever is in the registry before each test so we don't bleed
    # state across tests. The registry is started by the application; we
    # mutate its table directly.
    snapshot = PinnedRegistry.list()

    on_exit(fn ->
      Enum.each(PinnedRegistry.list(), fn {hex, _} -> PinnedRegistry.delete(hex) end)
      Enum.each(snapshot, fn {hex, sid} -> PinnedRegistry.put(hex, sid) end)
    end)

    :ok
  end

  describe "put/2 + lookup/1 + delete/1" do
    test "round trip" do
      hex = String.duplicate("a", 64)
      assert :ok = PinnedRegistry.put(hex, :acme)
      assert {:ok, :acme} = PinnedRegistry.lookup(hex)
      assert :ok = PinnedRegistry.delete(hex)
      assert :error = PinnedRegistry.lookup(hex)
    end

    test "is case-insensitive on the hex digest" do
      lower = String.duplicate("a", 64)
      upper = String.duplicate("A", 64)

      assert :ok = PinnedRegistry.put(upper, :stored_via_uppercase)
      assert {:ok, :stored_via_uppercase} = PinnedRegistry.lookup(lower)
    end

    test "rejects non-hex / wrong-length inputs" do
      assert {:error, :invalid_spki_hex} = PinnedRegistry.put("not-hex", :x)
      assert {:error, :invalid_spki_hex} = PinnedRegistry.put(String.duplicate("z", 64), :x)
      assert {:error, :invalid_spki_hex} = PinnedRegistry.put(String.duplicate("a", 63), :x)

      assert {:error, :invalid_spki_hex} = PinnedRegistry.delete("nope")
    end

    test "delete is idempotent" do
      assert :ok = PinnedRegistry.delete(String.duplicate("b", 64))
    end

    test "list/0 returns the full set" do
      hex1 = String.duplicate("1", 64)
      hex2 = String.duplicate("2", 64)

      :ok = PinnedRegistry.put(hex1, :a)
      :ok = PinnedRegistry.put(hex2, :b)

      pins = PinnedRegistry.list()
      assert {hex1, :a} in pins
      assert {hex2, :b} in pins
    end
  end

  describe "Pkcs11ex.Policy.resolve/2" do
    setup do
      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=test-pin")
      der = X509.Certificate.to_der(cert)
      x5c_b64 = Base.encode64(der)
      {:ok, pkcs11_cert} = Pkcs11ex.X509.from_der(der)
      spki = Pkcs11ex.X509.spki_sha256(pkcs11_cert)

      {:ok, der: der, x5c_b64: x5c_b64, spki: spki}
    end

    test "matches when SPKI is in the registry", %{x5c_b64: x5c_b64, spki: spki} do
      :ok = PinnedRegistry.put(spki, :acme)

      assert {:ok, %Pkcs11ex.X509{}, []} =
               PinnedRegistry.resolve(%{"x5c" => [x5c_b64]}, [])
    end

    test "returns :unknown_signer when SPKI is not pinned", %{x5c_b64: x5c_b64} do
      assert {:error, :unknown_signer} =
               PinnedRegistry.resolve(%{"x5c" => [x5c_b64]}, [])
    end

    test "returns :unknown_signer for missing or empty x5c" do
      assert {:error, :unknown_signer} = PinnedRegistry.resolve(%{}, [])
      assert {:error, :unknown_signer} = PinnedRegistry.resolve(%{"x5c" => []}, [])
    end

    test "returns :invalid_x5c_b64 for bogus base64" do
      assert {:error, :invalid_x5c_b64} =
               PinnedRegistry.resolve(%{"x5c" => ["!!!not-base64!!!"]}, [])
    end

    test "returns :invalid_cert for valid base64 that isn't a cert" do
      assert {:error, :invalid_cert} =
               PinnedRegistry.resolve(%{"x5c" => [Base.encode64("not a cert")]}, [])
    end
  end

  describe "Pkcs11ex.Policy.validate/3" do
    setup do
      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=validate-test")
      der = X509.Certificate.to_der(cert)
      {:ok, pkcs11_cert} = Pkcs11ex.X509.from_der(der)
      spki = Pkcs11ex.X509.spki_sha256(pkcs11_cert)

      {:ok, cert: pkcs11_cert, spki: spki}
    end

    test "returns the registered subject_id when the cert matches a pin", %{
      cert: cert,
      spki: spki
    } do
      :ok = PinnedRegistry.put(spki, :acme_corp)
      assert {:ok, :acme_corp} = PinnedRegistry.validate(cert, [], [])
    end

    test "returns :untrusted_signer when SPKI isn't pinned", %{cert: cert} do
      assert {:error, :untrusted_signer} = PinnedRegistry.validate(cert, [], [])
    end
  end

  describe "JWS.verify/3 integration" do
    setup do
      software_key = X509.PrivateKey.new_rsa(2048)
      cert = X509.Certificate.self_signed(software_key, "/CN=jws-pin-test")
      der = X509.Certificate.to_der(cert)
      {:ok, pkcs11_cert} = Pkcs11ex.X509.from_der(der)
      spki = Pkcs11ex.X509.spki_sha256(pkcs11_cert)

      previous_policy = Application.get_env(:pkcs11ex, :trust_policy)
      Application.put_env(:pkcs11ex, :trust_policy, PinnedRegistry)
      Application.put_env(:pkcs11ex, :allowed_algs, [:PS256])

      on_exit(fn -> Application.put_env(:pkcs11ex, :trust_policy, previous_policy) end)

      {:ok, software_key: software_key, der: der, spki: spki}
    end

    test "verify accepts when SPKI is pinned", %{software_key: key, der: der, spki: spki} do
      :ok = PinnedRegistry.put(spki, :acme_corp)

      payload = "hello pin"
      jws = manually_build_jws(payload, key, der)

      assert {:ok, :acme_corp} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "verify rejects with :unknown_signer before any signature math", %{
      software_key: key,
      der: der
    } do
      payload = "hello pin"
      # Same key/cert as the accepting test, but no put/2.
      jws = manually_build_jws(payload, key, der)

      assert {:error, :unknown_signer} = Pkcs11ex.JWS.verify(jws, payload)
    end

    test "off-boarding via delete/1 immediately revokes verify access", %{
      software_key: key,
      der: der,
      spki: spki
    } do
      :ok = PinnedRegistry.put(spki, :acme_corp)
      payload = "hello pin"
      jws = manually_build_jws(payload, key, der)

      assert {:ok, :acme_corp} = Pkcs11ex.JWS.verify(jws, payload)

      :ok = PinnedRegistry.delete(spki)

      assert {:error, :unknown_signer} = Pkcs11ex.JWS.verify(jws, payload)
    end
  end

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
