defmodule Pkcs11ex.XML do
  @moduledoc """
  Convenience wrapper around `SignCore.XML` pre-configured with the
  PKCS#11 signer. Same shape as `Pkcs11ex.PDF`.
  """

  @doc "XAdES B-B / B-T sign via the configured PKCS#11 slot."
  @spec sign(binary() | iodata(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(doc, opts) when is_list(opts) do
    SignCore.XML.sign(doc, normalise_signer(opts))
  end

  @doc "XAdES verify. Delegates to `SignCore.XML.verify/2`."
  @spec verify(binary() | iodata(), keyword()) :: {:ok, term()} | {:error, term()}
  def verify(doc, opts \\ []), do: SignCore.XML.verify(doc, opts)

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
