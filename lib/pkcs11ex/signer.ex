defmodule Pkcs11ex.Signer do
  @moduledoc """
  PKCS#11 implementation of the `SignCore.Signer` protocol.

  Routes signing requests from `SignCore.PDF.sign/2`,
  `SignCore.XML.sign/2`, and `SignCore.JWS.sign/2` through the
  Layer-2 `Pkcs11ex.sign_bytes/2` entry point.

  ## Construction

  Two equivalent forms — pick whichever matches the calling code:

      # Slot-ref form (recommended for production deployments
      # using the application's slot supervisor)
      %Pkcs11ex.Signer{slot_ref: :legal_proxy, key_ref: :signing}

      # Explicit-module form (one-shot CLI tasks, tests)
      %Pkcs11ex.Signer{module: pkcs11_module, slot_id: 0, key_label: "platform"}

  Either form is passed as `signer:` in the format adapters'
  options. The convenience wrappers `Pkcs11ex.PDF.sign/2`,
  `Pkcs11ex.XML.sign/2`, `Pkcs11ex.JWS.sign/2` accept the bare
  tuple `{slot_ref, key_ref}` and construct this struct internally.
  """

  defstruct [:slot_ref, :key_ref, :module, :slot_id, :key_label]

  @type t :: %__MODULE__{
          slot_ref: atom() | nil,
          key_ref: atom() | nil,
          module: term() | nil,
          slot_id: non_neg_integer() | nil,
          key_label: String.t() | nil
        }

  @doc """
  Convenience constructor for the slot-ref form.

      Pkcs11ex.Signer.new(slot_ref: :legal_proxy, key_ref: :signing)
  """
  @spec new(keyword()) :: t()
  def new(opts) when is_list(opts) do
    struct!(__MODULE__, opts)
  end

  defimpl SignCore.Signer do
    @doc """
    Routes the signature request through `Pkcs11ex.sign_bytes/2`.

    The signer's struct fields are merged into the opts the format
    adapter built (which already carry `:alg`, `:encoding_context`,
    plus any caller-supplied PKCS#11 keying opts), so a `Pkcs11ex.Signer`
    constructed once and used many times still works.
    """
    def sign(%Pkcs11ex.Signer{} = signer, tbs, opts) do
      forwarded = signer_opts(signer, opts)
      Pkcs11ex.sign_bytes(tbs, forwarded)
    end

    defp signer_opts(%Pkcs11ex.Signer{slot_ref: ref, key_ref: kref}, opts)
         when is_atom(ref) and not is_nil(ref) do
      [{:signer, {ref, kref}} | Keyword.delete(opts, :signer)]
    end

    defp signer_opts(%Pkcs11ex.Signer{module: mod, slot_id: sid, key_label: label}, opts)
         when not is_nil(mod) do
      opts
      |> Keyword.delete(:signer)
      |> Keyword.put(:module, mod)
      |> Keyword.put(:slot_id, sid)
      |> Keyword.put(:key_label, label)
    end

    defp signer_opts(_signer, opts) do
      # No fields populated — keep opts as-is and let sign_bytes
      # surface the missing-key error.
      opts
    end
  end
end
