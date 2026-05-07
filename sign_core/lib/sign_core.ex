defmodule SignCore do
  @moduledoc """
  Signer-agnostic primitives for PDF (PAdES B-B / B-T) and XML
  (XAdES B-B / B-T) signing on top of CMS / XML-DSig.

  Apps wire in their own signature source by implementing the
  `SignCore.Signer` protocol on a struct of their choosing:

    * `pkcs11ex` — PKCS#11 hardware tokens / cloud HSMs.
      `%Pkcs11ex.Signer{slot_ref: ..., key_ref: ...}`
    * `soft_signer` — software keys from PKCS#12 / PKCS#8 PEM.
      `%SoftSigner.PKCS12{...}`, `%SoftSigner.PKCS8{...}`

  Once a signer is constructed, the format adapters look the same
  to callers regardless of where the bytes get signed:

      {:ok, signed_pdf} =
        SignCore.PDF.sign(pdf,
          signer: signer,
          alg: :PS256,
          x5c: leaf_der
        )

      {:ok, _subject_id} =
        SignCore.PDF.verify(signed_pdf)

  Verification is signer-independent — `SignCore.PDF.verify/2` and
  `SignCore.XML.verify/2` only need the leaf cert's SPKI from the
  embedded chain, plus a `SignCore.Policy` decision on whether to
  trust it. Verify-only deployments can depend on `:sign_core` alone
  and ship no signer implementation at all.
  """
end
