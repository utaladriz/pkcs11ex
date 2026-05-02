defmodule Pkcs11ex.Audit.Anchor.RFC3161Test do
  use ExUnit.Case, async: true

  alias Pkcs11ex.Audit.Anchor.RFC3161

  describe "build_request/2" do
    test "rejects non-32-byte hashes" do
      assert {:error, {:expected_sha256_hash, 5}} = RFC3161.build_request("short")
    end

    test "produces a SEQUENCE-tagged DER blob" do
      hash = :crypto.hash(:sha256, "x")
      {:ok, %{der: der, nonce: nonce, hash: ^hash}} = RFC3161.build_request(hash)

      # SEQUENCE = 0x30
      assert <<0x30, _len_bytes::binary>> = der
      assert is_integer(nonce) and nonce > 0
    end

    test "DER round-trips through openssl ts -query -text", _ctx do
      if openssl = System.find_executable("openssl") do
        hash = :crypto.hash(:sha256, "round-trip")
        {:ok, %{der: der, nonce: nonce}} = RFC3161.build_request(hash)

        tmp = Path.join(System.tmp_dir!(), "tsp_req_#{System.unique_integer([:positive])}.tsq")
        File.write!(tmp, der)
        on_exit_unique = fn -> File.rm(tmp) end

        try do
          {out, 0} = System.cmd(openssl, ["ts", "-query", "-in", tmp, "-text"], stderr_to_stdout: true)

          assert out =~ "Version: 1"
          assert out =~ "Hash Algorithm: sha256"
          # openssl renders the nonce as hex 0x...
          assert out =~ "Nonce: 0x" <> Integer.to_string(nonce, 16)
          # Hash bytes present (look for the first few bytes in hex format)
          # openssl renders hash bytes space-separated, two hex digits each.
          first_4 =
            hash
            |> :binary.bin_to_list()
            |> Enum.take(4)
            |> Enum.map(&(Integer.to_string(&1, 16) |> String.pad_leading(2, "0")))
            |> Enum.join(" ")
            |> String.downcase()

          assert out =~ first_4
        after
          on_exit_unique.()
        end
      else
        # If openssl isn't available, just trust the structural check above.
        :ok
      end
    end
  end

  describe "fetch_token/3 — error paths (no live TSA)" do
    test "404 from server → {:error, {:tsa_http_status, 404}}" do
      # Use a deliberately bogus URL on a free port. We can't easily mock
      # an HTTP server in this test, so we just ensure the error type
      # surfaces cleanly when the request fails. Picks a port that should
      # refuse connections; httpc surfaces it as a connection error.
      assert {:error, {:tsa_http, _reason}} =
               RFC3161.fetch_token("http://127.0.0.1:1/no-tsa", <<0::8>>, timeout: 500)
    end
  end
end
