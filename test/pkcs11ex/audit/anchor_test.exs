defmodule Pkcs11ex.Audit.AnchorTest do
  @moduledoc """
  `Pkcs11ex.Audit.anchor_head/3` end-to-end with a local mock TSA.

  We don't run a real RFC 3161 server in tests — that's an :tsa-tagged
  integration concern. The mock here is just enough to exercise the
  audit-side wiring: receive a POST, return a canned binary, assert it
  was stored verbatim in the next audit entry.
  """

  use ExUnit.Case, async: false

  alias Pkcs11ex.Audit
  alias Pkcs11ex.Audit.Storage.InMemory

  @canned_tst <<0x30, 0x05, 0x02, 0x01, 0x42, 0x05, 0x00>>

  setup do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
    {:ok, port} = :inet.port(listener)

    # Spawn a one-shot acceptor that reads the request, sends a 200 with
    # @canned_tst as the body, then exits.
    parent = self()

    server_pid =
      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listener, 5_000)
        # Read until we get \r\n\r\n then drain Content-Length bytes.
        request = read_full_request(sock)
        send(parent, {:received_request, byte_size(request)})

        body = @canned_tst

        response = [
          "HTTP/1.1 200 OK\r\n",
          "Content-Type: application/timestamp-reply\r\n",
          "Content-Length: ",
          Integer.to_string(byte_size(body)),
          "\r\nConnection: close\r\n\r\n",
          body
        ]

        :ok = :gen_tcp.send(sock, response)
        :gen_tcp.close(sock)
        :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      Process.alive?(server_pid) && Process.exit(server_pid, :shutdown)
    end)

    {:ok, tsa_url: "http://127.0.0.1:#{port}/"}
  end

  defp read_full_request(sock) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} -> data
      {:error, _} -> <<>>
    end
  end

  setup do
    name = :"audit_anchor_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({InMemory, name: name})
    {:ok, audit: Audit.new(InMemory, name)}
  end

  test "anchor_head appends an entry carrying the TST + anchored seq/hash", %{
    audit: audit,
    tsa_url: tsa_url
  } do
    {:ok, head} = Audit.append(audit, "first")
    {:ok, _} = Audit.append(audit, "second")
    {:ok, target_head} = Audit.head(audit)

    assert {:ok, anchor_entry} = Audit.anchor_head(audit, tsa_url, timeout: 5_000)

    assert anchor_entry.payload.kind == :rfc3161_anchor
    assert anchor_entry.payload.anchored_seq == target_head.seq
    assert anchor_entry.payload.anchored_hash == target_head.content_hash
    assert anchor_entry.payload.tst == @canned_tst
    assert anchor_entry.payload.tsa_url == tsa_url
    assert is_integer(anchor_entry.payload.nonce)
    refute anchor_entry == head
  end

  test "anchor_head extends the chain — verify/1 still succeeds afterwards", %{
    audit: audit,
    tsa_url: tsa_url
  } do
    Audit.append(audit, "a")
    Audit.append(audit, "b")
    {:ok, _} = Audit.anchor_head(audit, tsa_url, timeout: 5_000)
    Audit.append(audit, "c")

    assert :ok = Audit.verify(audit)
  end

  test "anchor_head on empty chain returns :empty_chain", %{audit: audit} do
    # No appends — head is empty. We bypass the mock here since the
    # error must come from the empty-chain check before any HTTP.
    assert {:error, :empty_chain} =
             Audit.anchor_head(audit, "http://example.invalid", timeout: 100)
  end
end
