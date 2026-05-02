defmodule Pkcs11ex.Audit.Anchor.RFC3161 do
  @moduledoc """
  RFC 3161 Time-Stamp Protocol — anchor an audit chain head against an
  external Time-Stamping Authority (TSA).

  The library doesn't trust the operator's clock for "this entry was
  inserted at time T" — `Pkcs11ex.Audit.Entry.inserted_at` is whatever
  the operator says. RFC 3161 fixes that: send the chain head's
  `content_hash` to a third-party TSA, get back a TimeStampToken (TST,
  a CMS SignedData) that binds the hash to a TSA-attested time. Store
  the TST as an audit entry. Auditors verify the TST against the TSA's
  certificate chain to bound when the chain reached that state.

  ## Request structure (RFC 3161 §2.4.1)

      TimeStampReq ::= SEQUENCE {
        version          INTEGER  { v1(1) },
        messageImprint   MessageImprint,
        reqPolicy        TSAPolicyId      OPTIONAL,
        nonce            INTEGER          OPTIONAL,
        certReq          BOOLEAN          DEFAULT FALSE,
        extensions       [0] IMPLICIT Extensions OPTIONAL
      }

      MessageImprint ::= SEQUENCE {
        hashAlgorithm    AlgorithmIdentifier,
        hashedMessage    OCTET STRING
      }

  This module emits SHA-256 only and includes a 64-bit random nonce.

  ## What this module does NOT do

    * Parse the response. The TST is stored opaquely as the entry's
      payload. Verification (TST signature against TSA cert chain) is
      the auditor's job and an entirely separate workflow.
    * Verify the TSA's certificate chain.
    * Pick a TSA. Apps configure their TSA URL.

  ## Network

  Uses OTP `:httpc` (requires `:inets` started; added to extra_applications
  in mix.exs).
  """

  @oid_sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}

  @typedoc "Output of build_request/2 — the encoded request and the random nonce we used."
  @type request :: %{der: binary(), nonce: non_neg_integer(), hash: binary()}

  @doc """
  Build an RFC 3161 TimeStampReq DER over `hash_bytes` (which must be
  exactly 32 bytes — SHA-256 output).

  Returns `{:ok, request}` where `request` is a map with `:der` (the
  bytes to POST), `:nonce` (random integer included in the request), and
  `:hash` (echoed back for the audit entry).
  """
  @spec build_request(binary(), keyword()) :: {:ok, request()} | {:error, term()}
  def build_request(hash_bytes, _opts \\ []) when is_binary(hash_bytes) do
    if byte_size(hash_bytes) != 32 do
      {:error, {:expected_sha256_hash, byte_size(hash_bytes)}}
    else
      nonce = :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned(:big)

      version = der_integer(1)

      sha256_oid_der = encode_sha256_oid()
      null_der = <<5, 0>>
      alg_id = der_sequence(IO.iodata_to_binary([sha256_oid_der, null_der]))

      hashed_message = der_octet_string(hash_bytes)
      message_imprint = der_sequence(IO.iodata_to_binary([alg_id, hashed_message]))

      nonce_der = der_integer(nonce)

      req_der =
        der_sequence(IO.iodata_to_binary([version, message_imprint, nonce_der]))

      {:ok, %{der: req_der, nonce: nonce, hash: hash_bytes}}
    end
  end

  @doc """
  POST a TimeStampReq DER to a TSA over HTTP and return the response bytes.

  Content type is `application/timestamp-query`; response Content-Type
  is expected to be `application/timestamp-reply`. The library doesn't
  parse the response — apps and auditors verify the TST against the
  TSA's certificate chain themselves.
  """
  @spec fetch_token(String.t(), binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def fetch_token(tsa_url, request_der, opts \\ []) when is_binary(tsa_url) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    url = String.to_charlist(tsa_url)
    content_type = ~c"application/timestamp-query"

    request = {url, [], content_type, request_der}

    http_opts = [timeout: timeout, connect_timeout: timeout]
    request_opts = [body_format: :binary]

    case :httpc.request(:post, request, http_opts, request_opts) do
      {:ok, {{_v, 200, _r}, _headers, body}} when is_binary(body) ->
        {:ok, body}

      {:ok, {{_v, 200, _r}, _headers, body}} when is_list(body) ->
        {:ok, IO.iodata_to_binary(body)}

      {:ok, {{_v, status, _r}, _headers, _body}} ->
        {:error, {:tsa_http_status, status}}

      {:error, reason} ->
        {:error, {:tsa_http, reason}}
    end
  end

  # ---------- DER primitives ----------

  defp encode_sha256_oid do
    {:ok, der} = :"CryptographicMessageSyntax-2009".encode(:ContentType, @oid_sha256)
    IO.iodata_to_binary(der)
  end

  defp der_integer(n) when is_integer(n) and n >= 0 do
    bytes = :binary.encode_unsigned(n, :big)

    bytes =
      if :binary.first(bytes) >= 128 do
        # MSB set on the leading byte — prepend 0x00 to keep two's-complement
        # interpretation positive.
        <<0>> <> bytes
      else
        bytes
      end

    der_tlv(0x02, bytes)
  end

  defp der_octet_string(bytes), do: der_tlv(0x04, bytes)

  defp der_sequence(bytes), do: der_tlv(0x30, bytes)

  defp der_tlv(tag, value) do
    len = byte_size(value)

    length_bytes =
      if len < 128 do
        <<len>>
      else
        # Long-form length: high bit set + length bytes.
        encoded = :binary.encode_unsigned(len, :big)
        <<Bitwise.bor(0x80, byte_size(encoded))::8, encoded::binary>>
      end

    <<tag::8, length_bytes::binary, value::binary>>
  end
end
