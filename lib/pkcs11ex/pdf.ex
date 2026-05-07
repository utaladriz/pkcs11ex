defmodule Pkcs11ex.PDF do
  @moduledoc """
  Convenience wrapper around `SignCore.PDF` pre-configured with the
  PKCS#11 signer.

      Pkcs11ex.PDF.sign(pdf,
        signer: {:legal_proxy, :signing},
        alg: :PS256,
        x5c: leaf_der
      )

  is shorthand for

      SignCore.PDF.sign(pdf,
        signer: %Pkcs11ex.Signer{slot_ref: :legal_proxy, key_ref: :signing},
        alg: :PS256,
        x5c: leaf_der
      )

  Verify is signer-independent — it just delegates to
  `SignCore.PDF.verify/2`.
  """

  @doc "PAdES B-B / B-T sign via the configured PKCS#11 slot."
  @spec sign(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(pdf_bytes, opts) when is_binary(pdf_bytes) and is_list(opts) do
    SignCore.PDF.sign(pdf_bytes, normalise_signer(opts))
  end

  @doc "PAdES verify. Delegates to `SignCore.PDF.verify/2`."
  @spec verify(binary(), keyword()) :: {:ok, term()} | {:error, term()}
  def verify(pdf_bytes, opts \\ []), do: SignCore.PDF.verify(pdf_bytes, opts)

  # Translate the historical `signer: {slot_ref, key_ref}` and
  # explicit-module ergonomics into a `Pkcs11ex.Signer` struct
  # that implements the SignCore.Signer protocol.
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
