defmodule SoftSigner do
  @moduledoc """
  Software-key implementations of the `SignCore.Signer` protocol —
  PKCS#12 (.p12 / .pfx) bundles and PKCS#8 PEM private keys.

  Used together with `sign_core` to produce PDF / XML / JWS
  signatures from filesystem-resident keys, for deployments where
  no PKCS#11 hardware is available (or where multiple key sources
  coexist with hardware tokens via `pkcs11ex`).

  ## PKCS#12

      {:ok, signer} = SoftSigner.PKCS12.load("invoice.p12", password: "...")

      {:ok, signed_pdf} =
        SignCore.PDF.sign(pdf,
          signer: signer,
          alg: :PS256,
          x5c: SoftSigner.PKCS12.cert_chain(signer)
        )

  ## Architectural notes

  Software signing is a deliberate choice — by design, deployments
  that mandate HSM-only signing should depend on `pkcs11ex` and
  not include `soft_signer` in their dep graph. The library
  boundary is the audit story.
  """
end
