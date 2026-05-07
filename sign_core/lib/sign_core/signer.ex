defprotocol SignCore.Signer do
  @moduledoc """
  Pluggable signature-source contract used by `SignCore.PDF.sign/2`,
  `SignCore.XML.sign/2`, and `SignCore.JWS.sign/2`.

  Implementations carry whatever state is needed to produce a raw
  signature over arbitrary bytes — a PKCS#11 slot reference, a
  loaded PKCS#12 bundle, a cloud KMS handle, etc. Each provider
  ships a struct that implements this protocol.

  ## Contract

    * `sign(signer, tbs, opts)` returns `{:ok, raw_signature}` or
      `{:error, reason}`.
    * `tbs` is the bytes the format adapter wants signed (e.g.,
      DER-encoded `signedAttrs` for CMS, canonical `<ds:SignedInfo>`
      for XML-DSig, the JWS signing input for JWS).
    * `opts` carries the algorithm + format hints — at minimum
      `:alg` (atom — `:PS256`, `:RS256`, ...) and
      `:encoding_context` (`:der` or `:jose`). Implementations
      ignore opts they don't recognise.
    * The returned `raw_signature` is in the wire format the
      requested `:encoding_context` expects:
        - `:der` — for ECDSA, DER `SEQUENCE(r, s)`; for RSA, raw octets.
        - `:jose` — for ECDSA, fixed-size `r ‖ s`; for RSA, raw octets.

  ## Why a protocol

  Different providers carry different state: pkcs11ex's signer is a
  small struct (`%Pkcs11ex.Signer{slot_ref, key_ref}`) that resolves
  to a running `Pkcs11ex.Slot.Server` lookup. soft_signer's signer
  is a struct holding the loaded RSA key plus optional cert chain
  (`%SoftSigner.PKCS12{rsa_key, leaf, chain}`). A protocol
  dispatches over the struct type cleanly.

  ## Implementing for a new provider

      defmodule MyProvider.Signer do
        defstruct [:state]
      end

      defimpl SignCore.Signer, for: MyProvider.Signer do
        def sign(%MyProvider.Signer{} = signer, tbs, opts) do
          alg = Keyword.fetch!(opts, :alg)
          encoding_context = Keyword.get(opts, :encoding_context, :der)

          # Compute the raw signature however your provider does it,
          # then format for the requested context via the algorithm
          # adapter (which knows e.g. ES256 raw -> DER conversion).
          with {:ok, raw} <- do_sign(signer.state, tbs, alg),
               {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
            adapter.encode_signature(raw, encoding_context)
          end
        end
      end
  """

  @doc """
  Sign `tbs` and return the raw signature bytes formatted for the
  requested `:encoding_context` (defaulting to `:der`).
  """
  @spec sign(t(), binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def sign(signer, tbs, opts)
end
