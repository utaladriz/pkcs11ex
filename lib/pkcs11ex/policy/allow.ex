defmodule Pkcs11ex.Policy.Allow do
  @moduledoc """
  Test-only trust policy that accepts any signer with a parseable cert in the
  JWS `x5c` header. **Refuses to start under `Mix.env() == :prod`.**

  Used as the default in test environments. Production deployments must use
  `Pkcs11ex.Policy.PinnedRegistry` (allowlist by SPKI hash) or
  `Pkcs11ex.Policy.CASignedAllowlist` (CA + per-subject allowlist).

  This policy intentionally violates the hard invariant in `specs.md` §7.1
  ("sender-supplied certs are untrusted input until allowlist match") and
  exists only to make round-trip tests possible without setting up a registry.
  The Mix-env guard ensures it cannot be misused in production by accident.
  """

  @behaviour Pkcs11ex.Policy

  @impl true
  def resolve(%{"x5c" => [b64_der | _rest_chain]} = _header, _opts) when is_binary(b64_der) do
    with {:ok, der} <- decode_b64(b64_der),
         {:ok, cert} <- Pkcs11ex.X509.from_der(der) do
      {:ok, cert, []}
    else
      _ -> {:error, :invalid_cert}
    end
  end

  def resolve(_header, _opts), do: {:error, :unknown_signer}

  @impl true
  def validate(_cert, _chain, _opts) do
    if Mix.env() == :prod do
      raise "Pkcs11ex.Policy.Allow is forbidden under Mix.env() == :prod. " <>
              "Configure :trust_policy to PinnedRegistry or a custom policy."
    end

    {:ok, :anyone}
  end

  defp decode_b64(b64) do
    # x5c is standard base64 (RFC 4648), not base64url, per RFC 7515 §4.1.6.
    case Base.decode64(b64) do
      {:ok, der} -> {:ok, der}
      :error -> {:error, :invalid_x5c_b64}
    end
  end
end
