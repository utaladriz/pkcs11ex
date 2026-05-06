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

  @doc """
  Returns a fresh `Pkcs11ex.Native` module resource for SoftHSM2.

  PKCS#11 mandates one `C_Initialize` per process per `.so`. Each test gets
  its own Module via this function; between tests, the previous Module's
  ResourceArc must be released (process dies + GC) before `C_Initialize`
  can succeed again. We force `:erlang.garbage_collect/0` ahead of the load
  to flush any orphan resources.

  SoftHSM2 also caches the slot list at C_Initialize time — see
  `init_token!/4` for the workaround.
  """
  def module do
    if path = driver_path() do
      load_with_retries(path, 5)
    end
  end

  defp load_with_retries(_path, 0), do: raise("module_load failed after retries")

  defp load_with_retries(path, attempts_left) do
    case Pkcs11ex.Native.module_load(path) do
      {:ok, m} ->
        m

      {:error, _} ->
        force_gc_all()
        Process.sleep(50)
        load_with_retries(path, attempts_left - 1)
    end
  end

  defp force_gc_all do
    Enum.each(Process.list(), fn pid ->
      try do
        :erlang.garbage_collect(pid)
      rescue
        _ -> :ok
      end
    end)
  end

  @doc """
  Initialize a fresh SoftHSM2 token via `softhsm2-util` and return its slot id.

  Parses `--init-token` stdout for the reassigned slot id rather than calling
  `Pkcs11ex.Native.list_slots/1` afterwards — cryptoki's `Slot::try_from(slot_id)`
  works for any valid slot id whether or not it's in the cached list.
  """
  def init_token!(softhsm2_util, label, user_pin, so_pin) do
    {out, 0} =
      System.cmd(
        softhsm2_util,
        ["--init-token", "--free", "--label", label, "--pin", user_pin, "--so-pin", so_pin],
        stderr_to_stdout: true
      )

    case Regex.run(~r/reassigned to slot (\d+)/, out) do
      [_, slot_str] ->
        String.to_integer(slot_str)

      _ ->
        raise "softhsm2-util didn't report a reassigned slot id; output: #{out}"
    end
  end

  @doc "Counterpart to init_token!/4 — best-effort cleanup of a token by label."
  def delete_token(softhsm2_util, label) do
    _ =
      System.cmd(softhsm2_util, ["--delete-token", "--token", label], stderr_to_stdout: true)

    :ok
  end
end

defmodule Pkcs11ex.Test.Conformance do
  @moduledoc """
  Detection helpers for external standards-conformance tools used by
  the `:conformance`-tagged test suite. Each tool is tried via
  `System.find_executable/1`; the test setup skips with a friendly
  install hint when missing.

  Tools currently used:

    * `pdfsig` (Poppler) — `brew install poppler`
    * `xmlsec1` (libxmlsec1) — `brew install libxmlsec1`

  Tests that need these tools should also `@moduletag :conformance`
  so they're auto-excluded by default. `mix test --include
  conformance` opts in.
  """

  def pdfsig_path, do: System.find_executable("pdfsig")
  def xmlsec1_path, do: System.find_executable("xmlsec1")
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

# `:conformance` is opt-in (`mix test --include conformance`). Hits real
# external verifiers (pdfsig, xmlsec1) and SoftHSM together — slow and
# system-dependent.
excludes = [conformance: true] ++ excludes

# Tool availability is detected at compile time inside each conformance
# test module — missing tools cause the test bodies to compile out
# entirely, replaced by a single "skipped" placeholder.

unless Pkcs11ex.Test.Conformance.pdfsig_path() do
  IO.puts("[pkcs11ex] pdfsig not on PATH; conformance/PDF tests will skip.")
end

unless Pkcs11ex.Test.Conformance.xmlsec1_path() do
  IO.puts("[pkcs11ex] xmlsec1 not on PATH; conformance/XML tests will skip.")
end

ExUnit.start(exclude: excludes)
