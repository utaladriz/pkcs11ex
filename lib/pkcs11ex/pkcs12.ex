defmodule Pkcs11ex.PKCS12 do
  @moduledoc """
  Read-only loader for PKCS#12 (`.p12` / `.pfx`) bundles.

  **Never returns private key material**, even if the bundle contains one — only
  a `:has_private_key` boolean. This is a deliberate design choice: `pkcs11ex`
  does not sign with software keys (`specs.md` §10 Non-Goals). Use this loader
  for trust-material extraction (`x5c` certs, trust anchors) and pair it with
  `mix pkcs11ex.import_p12` (Phase 2) when you want to provision the key into a
  PKCS#11 token.

  ## Implementation

  v1 shells out to the `openssl pkcs12` CLI (passwords passed via env vars,
  never command line). OTP's `:public_key` doesn't ship PKCS#12 support, and
  rolling our own ASN.1 parser for the format's many encryption variants is a
  significant undertaking. A native Rust replacement via the existing Rustler
  bridge is on the roadmap; the public API is stable across the swap.

  Requires `openssl` on `PATH`.
  """

  alias SignCore.X509

  defmodule Bundle do
    @moduledoc """
    A parsed PKCS#12 bundle.

    `:leaf` is the first cert in the bundle (the end-entity cert in typical
    tax-certificate bundles); `:chain` is the rest in bundle order. Use
    `SignCore.X509.spki_sha256/1` if you need the leaf's pinning hash.

    `:has_private_key` is `true` when the bundle's structure includes a key
    bag (whether or not the password was correct enough to decrypt it). The
    actual key bytes are never part of this struct.

    `:friendly_name` is `nil` in v1; PKCS#12 friendlyName extraction lands
    with the native parser.
    """
    defstruct [:leaf, :chain, :has_private_key, :friendly_name]

    @type t :: %__MODULE__{
            leaf: X509.t(),
            chain: [X509.t()],
            has_private_key: boolean(),
            friendly_name: String.t() | nil
          }
  end

  @type source :: Path.t() | binary()
  @type opts :: [
          password: binary(),
          max_chain: pos_integer()
        ]

  @doc """
  Loads, parses, and returns a `Pkcs11ex.PKCS12.Bundle`.

  `source` is either a filesystem path (string that resolves to a regular file)
  or raw bundle bytes (binary that does not).

  ## Options

    * `:password` — bundle password. Required for encrypted bundles. Pass `nil`
      or omit only for the rare unencrypted bundle.
    * `:max_chain` — hard cap on chain length (default `8`). Bundles with more
      certificates fail with `:p12_chain_too_long`.

  ## Errors

  Returns one of:
    * `:p12_invalid` — bundle bytes are malformed or unparseable.
    * `:p12_password_incorrect` — decryption failed.
    * `:p12_chain_too_long` — chain exceeded `:max_chain`.
    * `{:p12_unsupported_kdf, oid}` — bundle uses a KDF/cipher OID OpenSSL doesn't recognize.
    * `:openssl_not_found` — the `openssl` CLI is not on `PATH`.
  """
  @spec load(source(), opts()) :: {:ok, Bundle.t()} | {:error, term()}
  def load(source, opts \\ [])

  def load(source, opts) when is_binary(source) do
    case openssl_executable() do
      nil ->
        {:error, :openssl_not_found}

      openssl ->
        bytes =
          if File.regular?(source) do
            File.read!(source)
          else
            source
          end

        do_load(bytes, opts, openssl)
    end
  end

  @doc "Same as `load/2` but raises `Pkcs11ex.Error` on failure."
  @spec load!(source(), opts()) :: Bundle.t()
  def load!(source, opts \\ []) do
    case load(source, opts) do
      {:ok, bundle} -> bundle
      {:error, reason} -> raise Pkcs11ex.Error, reason: reason
    end
  end

  # ---------- Internals ----------

  defp do_load(bytes, opts, openssl) do
    password = Keyword.get(opts, :password) || ""
    max_chain = Keyword.get(opts, :max_chain, 8)

    with_tmp(bytes, fn path ->
      with {:ok, pem_certs} <- run_extract_certs(openssl, path, password),
           {:ok, ders} <- decode_pem_certs(pem_certs),
           :ok <- check_chain_length(ders, max_chain),
           {:ok, certs} <- decode_x509s(ders),
           [leaf | chain] <- certs,
           {:ok, has_pk} <- detect_private_key(openssl, path, password) do
        {:ok, %Bundle{leaf: leaf, chain: chain, has_private_key: has_pk, friendly_name: nil}}
      else
        # do_load expects a single result; tuple-pattern in `with` drops through
        # to the else branch as-is, so existing {:error, _} pass through.
        [] -> {:error, :p12_invalid}
        {:error, _} = err -> err
      end
    end)
  end

  defp run_extract_certs(openssl, path, password) do
    args = [
      "pkcs12",
      "-in",
      path,
      "-password",
      "env:PKCS11EX_P12_PWD",
      "-nokeys",
      "-nodes"
    ]

    case System.cmd(openssl, args,
           env: [{"PKCS11EX_P12_PWD", password}],
           stderr_to_stdout: true
         ) do
      {pem, 0} -> {:ok, pem}
      {output, _} -> {:error, classify_openssl_error(output)}
    end
  end

  defp detect_private_key(openssl, path, password) do
    args = [
      "pkcs12",
      "-in",
      path,
      "-password",
      "env:PKCS11EX_P12_PWD",
      "-info",
      "-nokeys",
      "-noout"
    ]

    case System.cmd(openssl, args,
           env: [{"PKCS11EX_P12_PWD", password}],
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        # OpenSSL's -info output mentions "Keybag" or "Shrouded Keybag" when a
        # private key bag is present in the PKCS#12 structure. We don't
        # decrypt the key — we only confirm its presence.
        has_key = String.contains?(output, "Keybag") or String.contains?(output, "Shrouded")

        {:ok, has_key}

      _ ->
        # If -info itself failed, default conservatively to false; the cert
        # extraction must have succeeded for us to reach here, so the bundle
        # is structurally valid.
        {:ok, false}
    end
  end

  defp decode_pem_certs(pem) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, :p12_invalid}

      entries ->
        ders = for {:Certificate, der, _} <- entries, do: der

        if ders == [], do: {:error, :p12_invalid}, else: {:ok, ders}
    end
  end

  defp decode_x509s(ders) do
    Enum.reduce_while(ders, {:ok, []}, fn der, {:ok, acc} ->
      case X509.from_der(der) do
        {:ok, cert} -> {:cont, {:ok, [cert | acc]}}
        err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      err -> err
    end
  end

  defp check_chain_length(ders, max_chain) when length(ders) > max_chain,
    do: {:error, :p12_chain_too_long}

  defp check_chain_length(_, _), do: :ok

  defp classify_openssl_error(output) do
    out_lower = String.downcase(output)

    cond do
      String.contains?(out_lower, "mac verify failure") ->
        :p12_password_incorrect

      String.contains?(out_lower, "wrong password") ->
        :p12_password_incorrect

      String.contains?(out_lower, "invalid password") ->
        :p12_password_incorrect

      String.contains?(out_lower, "unknown algorithm") ->
        unsupported_kdf_from_output(output)

      String.contains?(out_lower, "unsupported algorithm") ->
        unsupported_kdf_from_output(output)

      true ->
        :p12_invalid
    end
  end

  defp unsupported_kdf_from_output(output) do
    case Regex.run(~r/(\d+(?:\.\d+)+)/, output) do
      [_, oid] -> {:p12_unsupported_kdf, oid}
      _ -> {:p12_unsupported_kdf, :unknown}
    end
  end

  defp with_tmp(bytes, fun) do
    path =
      Path.join(System.tmp_dir!(), "pkcs11ex_p12_#{System.unique_integer([:positive])}.p12")

    File.write!(path, bytes)

    try do
      fun.(path)
    after
      File.rm(path)
    end
  end

  defp openssl_executable do
    System.get_env("PKCS11EX_OPENSSL") || System.find_executable("openssl")
  end
end
