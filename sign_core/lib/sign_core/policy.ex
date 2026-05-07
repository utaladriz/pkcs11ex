defmodule SignCore.Policy do
  @moduledoc """
  Behaviour for trust policies.

  See `docs/specs/api.md` §2.3 for the canonical contract. The verify pipeline
  treats sender-supplied certificates as **untrusted input**: `resolve/2` MUST
  return `{:error, :unknown_signer}` when the candidate certificate (or its
  identity hint) does not match an allowlist the verifier maintains.

  Cryptographic verification only runs after `resolve/2` succeeds AND
  `validate/3` returns `{:ok, subject_id}`.
  """

  @type header :: map()
  @type cert :: SignCore.X509.t()
  @type chain :: [cert()]
  @type subject_id :: term()

  @callback resolve(header(), opts :: keyword()) ::
              {:ok, cert(), chain()} | {:error, term()}

  @callback validate(cert(), chain(), opts :: keyword()) ::
              {:ok, subject_id()} | {:error, term()}
end
