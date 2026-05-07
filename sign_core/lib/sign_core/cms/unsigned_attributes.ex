defmodule SignCore.CMS.UnsignedAttributes do
  @moduledoc """
  Builders for CMS `unsignedAttrs` — the optional set on a SignerInfo
  that carries data computed *after* signing (signature timestamps,
  countersignatures, etc.). The values aren't covered by the
  signature math.

  v1 ships only the PAdES B-T / CAdES B-T attribute:
  `id-aa-signatureTimeStampToken` (RFC 3161 §3.3.4 / RFC 5126
  §6.1.1) — an RFC 3161 TimeStampToken anchoring the SignerInfo's
  `signature` field.
  """

  alias SignCore.CMS.OIDs

  @doc """
  Builds the `id-aa-signatureTimeStampToken` Attribute with the
  supplied TimeStampToken DER (a CMS ContentInfo per RFC 3161
  §2.4.2). The TST is embedded verbatim inside the Attribute's
  attrValues SET — no parsing or validation happens here.
  """
  @spec signature_timestamp(binary()) :: {:Attribute, tuple(), [{:asn1_OPENTYPE, binary()}]}
  def signature_timestamp(tst_der) when is_binary(tst_der) do
    {:Attribute, OIDs.id_aa_signature_timestamp(), [{:asn1_OPENTYPE, tst_der}]}
  end
end
