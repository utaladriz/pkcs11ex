defmodule SignCore.Algorithm.PS256 do
  @moduledoc """
  PS256 algorithm adapter — RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt.

  Per JOSE convention (RFC 7518), the salt length matches the hash output (32
  bytes for SHA-256). The PKCS#11 mechanism used is `CKM_SHA256_RSA_PKCS_PSS`,
  which performs the digest inside the HSM in a single shot — appropriate for
  payloads that fit in memory. Streaming / pre-hashed paths
  (`CKM_RSA_PKCS_PSS` over a precomputed digest) land in a later step.

  Signature encoding is identity in both `:jose` and `:der` contexts: PSS
  produces a fixed-width byte string matching the modulus, and JWS/CMS both
  consume that byte string verbatim.
  """

  @behaviour SignCore.Algorithm

  @impl true
  def alg, do: :PS256

  @impl true
  def compatible_key_types, do: [:rsa]

  @impl true
  def hash, do: :sha256

  @impl true
  def signing_mechanism, do: :ck_sha256_rsa_pkcs_pss

  @impl true
  def verifying_mechanism, do: :ck_sha256_rsa_pkcs_pss

  @impl true
  def encode_signature(raw, _ctx) when is_binary(raw), do: {:ok, raw}

  @impl true
  def decode_signature(sig, _ctx) when is_binary(sig), do: {:ok, sig}
end
