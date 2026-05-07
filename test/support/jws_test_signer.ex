defmodule JWSTestSigner do
  @moduledoc false
  # Software RSA signer that fulfils the SignCore.Signer protocol for
  # JWS round-trip tests. Compiled only under `:test` (see `elixirc_paths/1`
  # in mix.exs) so protocol consolidation in :dev / :prod is unaffected
  # by its presence.

  defstruct [:rsa_key]

  defimpl SignCore.Signer do
    def sign(%JWSTestSigner{rsa_key: key}, tbs, opts) do
      alg = Keyword.fetch!(opts, :alg)
      encoding_context = Keyword.get(opts, :encoding_context, :der)

      raw =
        case alg do
          :PS256 ->
            :public_key.sign(tbs, :sha256, key,
              rsa_padding: :rsa_pkcs1_pss_padding,
              rsa_pss_saltlen: 32,
              rsa_mgf1_md: :sha256
            )

          :RS256 ->
            :public_key.sign(tbs, :sha256, key)
        end

      with {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
        adapter.encode_signature(raw, encoding_context)
      end
    end
  end
end
