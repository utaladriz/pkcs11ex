defmodule SignCore.Algorithm do
  @moduledoc """
  Behaviour for algorithm adapters.

  Adapts a JOSE `alg` to a PKCS#11 mechanism, the wire signature encoding for
  a given context (JOSE vs. X.509/CMS), and the canonical hash. See
  `docs/specs/api.md` §2.1.

  Implementations registered under `:algorithms` are accepted by the algorithm
  allowlist; unknown atoms surface as `:unsupported_alg`.
  """

  @type alg :: atom()
  @type key_type :: :rsa | :ec | :ed25519
  @type hash :: :sha256 | :sha384 | :sha512 | :none
  @type mechanism :: atom()
  @type encoding_context :: :jose | :der
  @type signature :: binary()

  @doc "The JOSE `alg` atom this adapter handles."
  @callback alg() :: alg()

  @doc "Key types compatible with this algorithm."
  @callback compatible_key_types() :: [key_type(), ...]

  @doc "Canonical hash function for this algorithm."
  @callback hash() :: hash()

  @doc """
  Atom describing the PKCS#11 mechanism used for signing.

  The Rust bridge translates the atom into a `CK_MECHANISM` plus parameters.
  Elixir never builds PKCS#11 binary structures directly.
  """
  @callback signing_mechanism() :: mechanism()

  @doc "Atom describing the PKCS#11 mechanism used for verification."
  @callback verifying_mechanism() :: mechanism()

  @doc """
  Transform a raw PKCS#11 signature into the wire format required by the
  given encoding context.

    * `:jose` — JWS / JOSE format (e.g., ES256 raw `r‖s`).
    * `:der`  — X.509 / CMS format (e.g., ES256 DER `SEQUENCE(r, s)`).

  Most algorithms (PS256, RS256) are identity in both contexts.
  """
  @callback encode_signature(raw :: binary(), encoding_context()) ::
              {:ok, signature()} | {:error, term()}

  @doc """
  Inverse of `encode_signature/2`. Used on verify to feed PKCS#11 the format
  it expects.
  """
  @callback decode_signature(signature(), encoding_context()) ::
              {:ok, raw :: binary()} | {:error, term()}

  # ---------- Public helpers (used by Layer 2 primitives) ----------

  @doc """
  Returns the algorithm-adapter module for an `alg` atom.

  Looks up `Application.get_env(:pkcs11ex, :algorithms)` first, falling back
  to the built-in registry. Returns `{:error, :unsupported_alg}` if the alg
  is not registered.
  """
  @spec lookup(alg()) :: {:ok, module()} | {:error, :unsupported_alg}
  def lookup(alg) when is_atom(alg) do
    registered = Application.get_env(:pkcs11ex, :algorithms, %{})

    case Map.get(registered, alg) || Map.get(builtins(), alg) do
      nil -> {:error, :unsupported_alg}
      mod -> {:ok, mod}
    end
  end

  @doc "The built-in algorithm registry."
  @spec builtins() :: %{atom() => module()}
  def builtins do
    %{
      PS256: SignCore.Algorithm.PS256
      # RS256, ES256, EdDSA — added in later phases.
    }
  end
end
