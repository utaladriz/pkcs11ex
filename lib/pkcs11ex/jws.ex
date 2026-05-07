defmodule Pkcs11ex.JWS do
  @moduledoc """
  Convenience wrapper around `SignCore.JWS` pre-configured with the
  PKCS#11 signer. Same shape as `Pkcs11ex.PDF`.
  """

  @doc "JWS RFC 7797 detached sign via the configured PKCS#11 slot."
  @spec sign(iodata(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(payload, opts) when is_list(opts) do
    SignCore.JWS.sign(payload, normalise_signer(opts))
  end

  @doc "JWS verify. Delegates to `SignCore.JWS.verify/3`."
  @spec verify(binary(), iodata(), keyword()) :: {:ok, term()} | {:error, term()}
  def verify(jws, payload, opts \\ []) when is_binary(jws) do
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
