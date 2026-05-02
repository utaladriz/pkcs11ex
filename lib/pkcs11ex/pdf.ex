defmodule Pkcs11ex.PDF do
  @moduledoc """
  PAdES (PDF Advanced Electronic Signature) format adapter.

  > #### Skeleton — Phase 4a deferred {: .warning}
  >
  > This module reserves the public API surface for PDF / PAdES B-B
  > signing per `docs/specs/api.md` §3.3. The full implementation is
  > **not** in v1. `sign/2` and `verify/2` return
  > `{:error, :not_implemented_in_v1}`.
  >
  > What's needed to ship a real implementation:
  >
  >   1. **CMS SignedData construction** — the cryptographic primitive that
  >      both PAdES and CAdES embed. The OTP `CryptographicMessageSyntax-2009`
  >      ASN.1 codec exposes the building blocks; wiring them up with the
  >      attribute-value open-type encoding is the work item.
  >   2. **PDF byte-range manipulation** — append an incremental update with
  >      a `/Sig` dictionary containing the `/ByteRange` tuple and a
  >      placeholder `/Contents`. Hash the bytes covered by `/ByteRange`,
  >      build the CMS over that hash, inject CMS DER into `/Contents`. No
  >      mature pure-Elixir PDF library exists; either roll a minimal
  >      appender or wrap a Rust crate (`lopdf`, `pdf`) via the existing
  >      Rustler bridge.
  >
  > Out of scope for v1: PAdES B-T (timestamp), B-LT, B-LTA — see
  > `specs.md` §10 Non-Goals and the Phase 5 audit-log roadmap.

  ## Anticipated surface

      Pkcs11ex.PDF.sign(pdf_bytes, signer: {:platform, :signing}, alg: :PS256)
      Pkcs11ex.PDF.verify(signed_pdf_bytes)

  When implemented, `sign/2` accepts `iodata()` (or `Enumerable.t()` for
  streaming multi-GB PDFs), produces a signed PDF as `iodata()`, and signs
  via the same `:signer` ergonomics as `Pkcs11ex.JWS.sign/2`.
  """

  @typedoc "Anticipated returns once Phase 4a lands."
  @type sign_result :: {:ok, iodata()} | {:error, term()}

  @type verify_result :: {:ok, subject_id :: term()} | {:error, term()}

  @doc """
  Sign a PDF with PAdES B-B. Not implemented in v1.

  Returns `{:error, :not_implemented_in_v1}` until Phase 4a ships.
  """
  @spec sign(iodata(), keyword()) :: sign_result()
  def sign(_pdf_bytes, _opts), do: {:error, :not_implemented_in_v1}

  @doc """
  Verify a PAdES-signed PDF. Not implemented in v1.
  """
  @spec verify(iodata(), keyword()) :: verify_result()
  def verify(_signed_pdf, _opts \\ []), do: {:error, :not_implemented_in_v1}
end
