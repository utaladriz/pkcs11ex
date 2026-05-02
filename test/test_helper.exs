defmodule Pkcs11ex.Test.SoftHSM do
  @moduledoc false

  @candidates [
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.dylib",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
  ]

  @doc "Returns the path to a SoftHSM2 driver if installed, or nil."
  def driver_path do
    System.get_env("PKCS11EX_SOFTHSM_LIB") ||
      Enum.find(@candidates, &File.regular?/1)
  end

  @doc "Returns true when the SoftHSM2 driver is locally available."
  def available?, do: driver_path() != nil
end

excludes =
  if Pkcs11ex.Test.SoftHSM.available?() do
    []
  else
    IO.puts(
      "[pkcs11ex] SoftHSM2 not detected; tests tagged :softhsm will be skipped. " <>
        "Set PKCS11EX_SOFTHSM_LIB or install softhsm to enable them."
    )

    [softhsm: true]
  end

ExUnit.start(exclude: excludes)
