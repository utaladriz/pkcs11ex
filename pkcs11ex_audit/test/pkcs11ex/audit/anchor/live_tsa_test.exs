defmodule Pkcs11ex.Audit.Anchor.LiveTSATest do
  @moduledoc """
  Live RFC 3161 integration test against a real public Time-Stamping
  Authority. Excluded by default — set `PKCS11EX_TSA_TESTS=1` to run
  (or `mix test --include tsa`).

  These tests cost a real network round trip to DigiCert and depend on
  external availability. They exist to validate that the hand-rolled
  RFC 3161 request DER (TimeStampReq) actually round-trips through a
  production TSA, not just our unit-test mocks.

  Override the TSA endpoint with `PKCS11EX_TSA_URL` if needed.
  """

  use ExUnit.Case, async: false

  alias Pkcs11ex.Audit
  alias Pkcs11ex.Audit.Anchor.RFC3161
  alias Pkcs11ex.Audit.Storage.InMemory

  @moduletag :tsa

  # DigiCert is the most universally available free public TSA. No auth,
  # rate-limited but generous.
  @default_tsa "http://timestamp.digicert.com"

  # CMS SignedData OID (1.2.840.113549.1.7.2) DER-encoded — the unmistakable
  # marker of an RFC 3161 TimeStampToken inside the TimeStampResp.
  @signed_data_oid_bytes <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02>>

  setup_all do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  setup do
    name = :"audit_live_tsa_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({InMemory, name: name})
    tsa_url = System.get_env("PKCS11EX_TSA_URL") || @default_tsa
    {:ok, audit: Audit.new(InMemory, name), tsa_url: tsa_url}
  end

  test "fetch_token round-trips a real TimeStampResp from the TSA", %{tsa_url: tsa_url} do
    hash = :crypto.hash(:sha256, "live tsa probe #{System.unique_integer([:positive])}")
    {:ok, %{der: der}} = RFC3161.build_request(hash)

    assert {:ok, body} = RFC3161.fetch_token(tsa_url, der, timeout: 15_000)
    assert byte_size(body) > 100, "TimeStampResp suspiciously small: #{byte_size(body)} bytes"
    assert <<0x30, _rest::binary>> = body, "TimeStampResp must start with DER SEQUENCE"

    # Quick PKIStatusInfo sanity check: directly after the outer SEQUENCE
    # length, the first inner element is PKIStatusInfo (a SEQUENCE) whose
    # first child is the status INTEGER. Granted = 0, GrantedWithMods = 1.
    {:ok, status} = pki_status(body)

    assert status in [0, 1],
           "TSA returned non-granted PKIStatus #{inspect(status)} — token rejected"

    # The TST itself is a CMS SignedData. The OID identifying it must be
    # present somewhere in the response body.
    assert :binary.match(body, @signed_data_oid_bytes) != :nomatch,
           "Response body lacks the CMS SignedData OID — not a real TST"
  end

  test "anchor_head stores the live TST and chain still verifies", %{
    audit: audit,
    tsa_url: tsa_url
  } do
    {:ok, _} = Audit.append(audit, "live anchor target")

    assert {:ok, anchor_entry} =
             Audit.anchor_head(audit, tsa_url, timeout: 15_000)

    assert anchor_entry.payload.kind == :rfc3161_anchor
    assert is_binary(anchor_entry.payload.tst)
    assert byte_size(anchor_entry.payload.tst) > 100
    assert anchor_entry.payload.tsa_url == tsa_url

    Audit.append(audit, "post-anchor entry")
    assert :ok = Audit.verify(audit)
  end

  # Walks the outer DER and pulls the status INTEGER out of PKIStatusInfo.
  # Tolerant of definite-length forms — that's all the TSAs we target use.
  defp pki_status(<<0x30, rest::binary>>) do
    with {:ok, _outer_body, _} <- der_take_length(rest),
         {:ok, status_info} <- der_first_child_after_length(rest),
         <<0x30, status_inner::binary>> <- status_info,
         {:ok, status_body, _} <- der_take_length(status_inner),
         <<0x02, int_inner::binary>> <- status_body,
         {:ok, int_bytes, _} <- der_take_length(int_inner) do
      {:ok, :binary.decode_unsigned(int_bytes, :big)}
    else
      other -> {:error, {:unparsable_pki_status, other}}
    end
  end

  defp pki_status(_), do: {:error, :not_der_sequence}

  defp der_take_length(<<len, rest::binary>>) when len < 128 do
    case rest do
      <<value::binary-size(len), tail::binary>> -> {:ok, value, tail}
      _ -> {:error, :short_value}
    end
  end

  defp der_take_length(<<first, rest::binary>>) when first >= 128 do
    n = first - 128

    case rest do
      <<len_bytes::binary-size(n), after_len::binary>> ->
        len = :binary.decode_unsigned(len_bytes, :big)

        case after_len do
          <<value::binary-size(len), tail::binary>> -> {:ok, value, tail}
          _ -> {:error, :short_value}
        end

      _ ->
        {:error, :short_length}
    end
  end

  defp der_first_child_after_length(bytes) do
    case der_take_length(bytes) do
      {:ok, body, _tail} -> {:ok, body}
      err -> err
    end
  end
end
