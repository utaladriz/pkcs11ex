defmodule Pkcs11ex.X509 do
  @moduledoc """
  Backwards-compat alias for `SignCore.X509`. The struct, types,
  and functions live in `sign_core` post-monorepo-split; this module
  re-exposes them under the historical `Pkcs11ex.X509` name so
  callers don't have to update their `alias` lines.
  """

  defdelegate from_der(der), to: SignCore.X509
  defdelegate spki_sha256(cert), to: SignCore.X509
end
