defmodule SoftSigner.PKCS12 do
  @moduledoc """
  Software signer backed by a PKCS#12 (`.p12` / `.pfx`) bundle.

  Loads the bundle once via `load/2` (uses the `openssl pkcs12` CLI
  for decryption — pure-Erlang PKCS#12 decode is fragile across
  vendor encodings) and returns a struct that implements
  `SignCore.Signer`. Sign operations route through
  `:public_key.sign/3` with the right padding for the requested
  algorithm.

  ## Threat model — key material is BEAM-resident

  The decoded RSA private key is held as an Erlang `RSAPrivateKey`
  record on the returned `%SoftSigner.PKCS12{}` struct. **It lives
  in BEAM heap memory for the entire lifetime of any reference to
  the struct** — including indirect references via process state,
  ETS tables, supervised GenServer state, etc. The BEAM has no
  zeroization primitive for managed binaries / integers, and the GC
  may retain freed copies well after the explicit reference is gone.

  Use this signer only when the threat model accepts that the key:

    * is readable by anyone with BEAM-process memory access (other
      OS processes with `/proc/<pid>/mem` rights, core dumps,
      hibernation snapshots, swapped pages on a memory-pressured
      host, attached debuggers);
    * is recoverable from a kernel core dump or crash dump;
    * may transiently appear in `:erlang.process_info/2` output for
      processes holding the struct.

  For threat models that exclude any of these (regulated tax
  certificates, banking integration keys, anything that must never
  be software-copyable), use `pkcs11ex` instead — the key stays
  inside the HSM / token across the PKCS#11 boundary and never
  enters the BEAM.

  This package is named `soft_signer` precisely to make the
  hardware-vs-software distinction part of the dependency graph: a
  deployment that omits `:soft_signer` from its `mix.lock` cannot
  software-sign by package boundary, not just by configuration.

  ## Usage

      {:ok, signer} = SoftSigner.PKCS12.load("path/to/bundle.p12", password: "secret")

      {:ok, signed_pdf} =
        SignCore.PDF.sign(pdf,
          signer: signer,
          alg: :PS256,
          x5c: SoftSigner.PKCS12.cert_chain(signer)
        )

  ## Cert chain

  PKCS#12 bundles carry the leaf cert (and often intermediate
  CA certs). `cert_chain/1` returns them as a list of DER binaries,
  leaf first — drop straight into the `:x5c` opt of any format
  adapter.
  """

  defstruct [:rsa_key, :leaf_der, :chain_ders]

  @type t :: %__MODULE__{
          rsa_key: tuple(),
          leaf_der: binary(),
          chain_ders: [binary()]
        }

  @doc """
  Load a PKCS#12 bundle from `path` and return a `%SoftSigner.PKCS12{}`
  struct ready for `SignCore.Signer.sign/3`.

  Required opts:

    * `:password` — bundle password (string).

  Optional:

    * `:openssl` — path to the `openssl` CLI. Default
      `System.find_executable("openssl")`.

  Returns `{:error, {:openssl, message}}` if the CLI is missing or
  the bundle won't decrypt.
  """
  @spec load(Path.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def load(path, opts) when is_binary(path) and is_list(opts) do
    password = Keyword.fetch!(opts, :password)

    openssl =
      Keyword.get(opts, :openssl) || System.find_executable("openssl") ||
        nil

    cond do
      not File.regular?(path) ->
        {:error, {:bundle_not_found, path}}

      is_nil(openssl) ->
        {:error, {:openssl, "openssl CLI not on PATH"}}

      true ->
        with {:ok, key_pem} <-
               run_openssl(openssl, ["pkcs12", "-in", path, "-nocerts", "-nodes"], password),
             {:ok, certs_pem} <-
               run_openssl(openssl, ["pkcs12", "-in", path, "-nokeys", "-nodes"], password),
             {:ok, rsa_key} <- decode_rsa_key(key_pem),
             {:ok, [leaf_der | chain_ders]} <- decode_certs(certs_pem) do
          {:ok, %__MODULE__{rsa_key: rsa_key, leaf_der: leaf_der, chain_ders: chain_ders}}
        end
    end
  end

  @doc """
  Returns the bundle's certificate chain as a list of DER binaries,
  leaf first. Drop into any format adapter's `:x5c` opt.
  """
  @spec cert_chain(t()) :: [binary()]
  def cert_chain(%__MODULE__{leaf_der: leaf, chain_ders: chain}), do: [leaf | chain]

  defimpl SignCore.Signer do
    def sign(%SoftSigner.PKCS12{rsa_key: key}, tbs, opts) do
      alg = Keyword.fetch!(opts, :alg)
      encoding_context = Keyword.get(opts, :encoding_context, :der)

      with {:ok, raw} <- do_sign(key, tbs, alg),
           {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
        adapter.encode_signature(raw, encoding_context)
      end
    end

    defp do_sign(key, tbs, :PS256) do
      {:ok,
       :public_key.sign(tbs, :sha256, key,
         rsa_padding: :rsa_pkcs1_pss_padding,
         rsa_pss_saltlen: 32,
         rsa_mgf1_md: :sha256
       )}
    rescue
      e -> {:error, classify_sign_error(e)}
    end

    defp do_sign(key, tbs, :RS256) do
      {:ok, :public_key.sign(tbs, :sha256, key)}
    rescue
      e -> {:error, classify_sign_error(e)}
    end

    defp do_sign(_key, _tbs, alg),
      do: {:error, {:unsupported_alg, alg}}

    # `:public_key.sign/3` raises specific exception shapes for
    # well-known failure modes; surface them as typed atoms so callers
    # can branch on the cause (`SignCore.JWS.verify` already has
    # `:incompatible_alg`). Anything else falls back to
    # `{:soft_sign_failed, message}` with the original message
    # preserved for debugging.
    defp classify_sign_error(%MatchError{}), do: :incompatible_alg
    defp classify_sign_error(%ArgumentError{}), do: :incompatible_alg
    defp classify_sign_error(%FunctionClauseError{}), do: :incompatible_alg
    defp classify_sign_error(e), do: {:soft_sign_failed, Exception.message(e)}
  end

  # ---------- internals ----------

  defp run_openssl(openssl, args, password) do
    env = [{"PKCS11EX_P12_PWD", password}]
    full_args = args ++ ["-password", "env:PKCS11EX_P12_PWD"]

    case System.cmd(openssl, full_args, env: env, stderr_to_stdout: true) do
      {output, 0} ->
        {:ok, output}

      {output, _} ->
        if output =~ ~r/mac verify (failure|error)/i do
          {:error, {:openssl, "PKCS#12 password incorrect"}}
        else
          {:error, {:openssl, "openssl pkcs12 failed: " <> String.slice(output, 0, 200)}}
        end
    end
  end

  defp decode_rsa_key(pem) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, {:openssl, "no PEM entries in extracted key"}}

      entries ->
        case find_rsa(entries) do
          {:ok, rsa} -> {:ok, rsa}
          :error -> {:error, {:openssl, "no RSA private key in extracted key PEM"}}
        end
    end
  end

  defp find_rsa(entries) do
    Enum.find_value(entries, :error, fn entry ->
      case entry do
        {:RSAPrivateKey, _, _} = e ->
          {:ok, :public_key.pem_entry_decode(e)}

        {:PrivateKeyInfo, _, _} = e ->
          case :public_key.pem_entry_decode(e) do
            rsa when is_tuple(rsa) and tuple_size(rsa) == 11 and elem(rsa, 0) == :RSAPrivateKey ->
              {:ok, rsa}

            _ ->
              nil
          end

        _ ->
          nil
      end
    end)
  end

  defp decode_certs(pem) do
    ders =
      :public_key.pem_decode(pem)
      |> Enum.flat_map(fn
        {:Certificate, der, _} -> [der]
        _ -> []
      end)

    if ders == [] do
      {:error, {:openssl, "no Certificate entries in extracted PEM"}}
    else
      {:ok, ders}
    end
  end
end
