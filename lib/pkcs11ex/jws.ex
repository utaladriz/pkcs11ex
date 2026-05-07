defmodule Pkcs11ex.JWS do
  @moduledoc """
  Convenience wrapper around `SignCore.JWS` pre-configured with the
  PKCS#11 signer. Supports both detached (RFC 7797, default) and
  attached (RFC 7515) JWS via the `attached: true` opt; supports
  optional `:x5c` when a `kid` extra-header is supplied (verifier
  resolves the cert via `:kid_certs`).
  """

  @doc """
  Sign via the configured PKCS#11 slot.

  Defaults to detached (RFC 7797). Pass `attached: true` for
  RFC 7515 attached form (payload encoded in the middle segment).
  """
  @spec sign(iodata(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(payload, opts) when is_list(opts) do
    SignCore.JWS.sign(payload, normalise_signer(opts))
  end

  @doc """
  Verify. Delegates to `SignCore.JWS.verify/3` — auto-detects
  detached vs attached from the JWS wire format. For detached,
  pass the payload as the second arg. For attached, pass `nil` (or
  the payload, which will be cross-checked).
  """
  @spec verify(binary(), iodata() | nil, keyword()) :: {:ok, term()} | {:error, term()}
  def verify(jws, payload \\ nil, opts \\ []) when is_binary(jws) do
    SignCore.JWS.verify(jws, payload, opts)
  end

  defp normalise_signer(opts) do
    case Keyword.get(opts, :signer) do
      %Pkcs11ex.Signer{} ->
        opts

      {slot_ref, key_ref} when is_atom(slot_ref) and is_atom(key_ref) ->
        Keyword.put(opts, :signer, %Pkcs11ex.Signer{slot_ref: slot_ref, key_ref: key_ref})

      atom when is_atom(atom) and not is_nil(atom) ->
        Keyword.put(opts, :signer, %Pkcs11ex.Signer{slot_ref: atom})

      nil ->
        Keyword.put(opts, :signer, %Pkcs11ex.Signer{
          module: Keyword.get(opts, :module),
          slot_id: Keyword.get(opts, :slot_id),
          key_label: Keyword.get(opts, :key_label)
        })
    end
  end
end
