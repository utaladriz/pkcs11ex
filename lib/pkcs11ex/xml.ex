defmodule Pkcs11ex.XML do
  @moduledoc """
  XML-DSig + XAdES B-B format adapter.

  > #### Skeleton — Phase 4b deferred {: .warning}
  >
  > This module reserves the public API surface for XML / XAdES B-B
  > signing per `docs/specs/api.md` §3.4. The full implementation is
  > **not** in v1. `sign/2` and `verify/2` return
  > `{:error, :not_implemented_in_v1}`.
  >
  > What's needed to ship a real implementation:
  >
  >   1. **Canonicalization (C14N)** — RFC 3076 / 3741. The hard part:
  >      no Elixir-native C14N implementation we'd trust ships today.
  >      Reuse will likely require porting Apache Santuario (Java) or
  >      wrapping `libxmlsec` (C) via the Rustler bridge.
  >   2. **`<Signature>` element wiring** — build `<SignedInfo>` with
  >      Reference + Transform + DigestValue, sign the canonicalized
  >      `<SignedInfo>` via the existing PKCS#11 path, write the result
  >      into `<SignatureValue>`.
  >   3. **XAdES `<QualifyingProperties>`** for B-B (signed signature
  >      properties: `<SigningTime>`, `<SigningCertificateV2>`).
  >
  > XML parsing/serialization is fine — OTP's `:xmerl` is sufficient.
  > The blocker is C14N.
  >
  > Out of scope for v1: XAdES B-T (timestamp), B-LT, B-LTA — see
  > `specs.md` §10 Non-Goals and the Phase 5 audit-log roadmap.

  ## Anticipated surface

      Pkcs11ex.XML.sign(xml_doc, signer: {:platform, :signing}, alg: :PS256)
      Pkcs11ex.XML.verify(signed_xml_doc)

  Input/output uses `:xmerl.document()` records (parsed) or `binary()`
  (raw XML bytes); the adapter handles whichever the caller has.
  """

  @type sign_result :: {:ok, term()} | {:error, term()}
  @type verify_result :: {:ok, subject_id :: term()} | {:error, term()}

  @doc """
  Sign an XML document with XML-DSig + XAdES B-B. Not implemented in v1.

  Returns `{:error, :not_implemented_in_v1}` until Phase 4b ships.
  """
  @spec sign(term() | binary(), keyword()) :: sign_result()
  def sign(_doc, _opts), do: {:error, :not_implemented_in_v1}

  @doc """
  Verify a signed XML document. Not implemented in v1.
  """
  @spec verify(term() | binary(), keyword()) :: verify_result()
  def verify(_signed_doc, _opts \\ []), do: {:error, :not_implemented_in_v1}
end
