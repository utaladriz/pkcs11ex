defmodule SoftSigner.PKCS8 do
  @moduledoc """
  Software signer backed by a PKCS#8 PEM private key plus a
  separate certificate (PEM, single or chained).

  Different shape from `SoftSigner.PKCS12`: PKCS#12 bundles carry
  the cert with the key, so cert-chain extraction is automatic.
  PKCS#8 is just the key, so the caller supplies the cert
  separately. This split is common in cloud deployments where
  TLS-style key + cert files live next to each other on disk.

  Supports both encrypted (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
  and unencrypted PKCS#8, plus the older PKCS#1
  `-----BEGIN RSA PRIVATE KEY-----` format.

  ## Usage

      # From file paths:
      {:ok, signer} =
        SoftSigner.PKCS8.load(
          key_path: "/keys/legal-proxy.key.pem",
          cert_path: "/keys/legal-proxy.cert.pem",
          password: "secret"     # only needed if the key is encrypted
        )

      # From in-memory PEM strings (the same opts but suffix `_pem`):
      {:ok, signer} =
        SoftSigner.PKCS8.load(
          key_pem: File.read!("/keys/legal-proxy.key.pem"),
          cert_pem: File.read!("/keys/legal-proxy.cert.pem")
        )

      {:ok, signed_pdf} =
        SignCore.PDF.sign(pdf,
          signer: signer,
          alg: :PS256,
          x5c: SoftSigner.PKCS8.cert_chain(signer)
        )

  ## Options

  Required (key — pick one):
    * `:key_path` — filesystem path to a PEM file.
    * `:key_pem` — PEM bytes already in memory.

  Required (cert — pick one):
    * `:cert_path` — filesystem path to a PEM file. May contain
      a single cert or a chain (leaf first, then intermediates).
    * `:cert_pem` — PEM bytes already in memory.

  Optional:
    * `:password` — required only if the key PEM is encrypted.
      Surfaces `{:error, :wrong_password}` on a mismatch.
  """

  defstruct [:rsa_key, :leaf_der, :chain_ders]

  @type t :: %__MODULE__{
          rsa_key: tuple(),
          leaf_der: binary(),
          chain_ders: [binary()]
        }

  @doc """
  Load a PKCS#8 key + cert chain. See moduledoc for opts.
  """
  @spec load(keyword()) :: {:ok, t()} | {:error, term()}
  def load(opts) when is_list(opts) do
    with {:ok, key_pem} <- read_pem(opts, :key_path, :key_pem, :missing_key),
         {:ok, cert_pem} <- read_pem(opts, :cert_path, :cert_pem, :missing_cert),
         {:ok, rsa_key} <- decode_key(key_pem, Keyword.get(opts, :password)),
         {:ok, [leaf_der | chain_ders]} <- decode_certs(cert_pem) do
      {:ok, %__MODULE__{rsa_key: rsa_key, leaf_der: leaf_der, chain_ders: chain_ders}}
    end
  end

  @doc """
  Returns the cert chain as `[leaf_der | intermediates_der]` —
  drop into any format adapter's `:x5c` opt.
  """
  @spec cert_chain(t()) :: [binary()]
  def cert_chain(%__MODULE__{leaf_der: leaf, chain_ders: chain}), do: [leaf | chain]

  defimpl SignCore.Signer do
    def sign(%SoftSigner.PKCS8{rsa_key: key}, tbs, opts) do
      alg = Keyword.fetch!(opts, :alg)
      encoding_context = Keyword.get(opts, :encoding_context, :der)

      with {:ok, raw} <- do_sign(key, tbs, alg),
           {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
        adapter.encode_signature(raw, encoding_context)
      end
    end

    defp do_sign(key, tbs, :PS256) do
      sig =
        :public_key.sign(tbs, :sha256, key,
          rsa_padding: :rsa_pkcs1_pss_padding,
          rsa_pss_saltlen: 32,
          rsa_mgf1_md: :sha256
        )

      {:ok, sig}
    rescue
      e -> {:error, {:soft_sign_failed, Exception.message(e)}}
    end

    defp do_sign(key, tbs, :RS256) do
      {:ok, :public_key.sign(tbs, :sha256, key)}
    rescue
      e -> {:error, {:soft_sign_failed, Exception.message(e)}}
    end

    defp do_sign(_key, _tbs, alg),
      do: {:error, {:unsupported_alg, alg}}
  end

  # ---------- internals ----------

  defp read_pem(opts, path_key, pem_key, missing_atom) do
    case {Keyword.get(opts, path_key), Keyword.get(opts, pem_key)} do
      {nil, nil} ->
        {:error, missing_atom}

      {path, nil} when is_binary(path) ->
        if File.regular?(path) do
          {:ok, File.read!(path)}
        else
          {:error, {:pem_not_found, path}}
        end

      {nil, pem} when is_binary(pem) ->
        {:ok, pem}

      {_path, pem} when is_binary(pem) ->
        # If both supplied, the in-memory PEM wins (caller's choice).
        {:ok, pem}
    end
  end

  defp decode_key(pem, password) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, :no_pem_entries}

      entries ->
        case find_key_entry(entries) do
          nil ->
            {:error, :no_rsa_private_key}

          entry ->
            decode_entry(entry, password)
        end
    end
  end

  defp find_key_entry(entries) do
    Enum.find(entries, fn
      {:RSAPrivateKey, _, _} -> true
      {:PrivateKeyInfo, _, _} -> true
      {:EncryptedPrivateKeyInfo, _, _} -> true
      _ -> false
    end)
  end

  # OTP 28 quirk: `BEGIN ENCRYPTED PRIVATE KEY` PEMs come back from
  # `:public_key.pem_decode/1` tagged as `:PrivateKeyInfo` rather than
  # `:EncryptedPrivateKeyInfo`. So we can't distinguish encrypted from
  # unencrypted purely by the tag — we have to try decoding and read
  # the failure mode:
  #
  #   * `pem_entry_decode/1` (no password) on an encrypted entry
  #     raises `FunctionClauseError` -> :password_required
  #   * `pem_entry_decode/2` (with password) on a wrong password
  #     raises `MatchError` from inside :public_key -> :wrong_password
  #   * successful decode -> classify the resulting term

  defp decode_entry(entry, nil) do
    decoded = :public_key.pem_entry_decode(entry)
    classify_decoded(decoded)
  rescue
    FunctionClauseError -> {:error, :password_required}
    e -> {:error, {:pem_decode_failed, Exception.message(e)}}
  end

  defp decode_entry(entry, password) when is_binary(password) do
    decoded = :public_key.pem_entry_decode(entry, String.to_charlist(password))
    classify_decoded(decoded)
  rescue
    MatchError -> {:error, :wrong_password}
    e -> {:error, {:pem_decode_failed, Exception.message(e)}}
  end

  defp classify_decoded(rsa)
       when is_tuple(rsa) and tuple_size(rsa) == 11 and elem(rsa, 0) == :RSAPrivateKey,
       do: {:ok, rsa}

  defp classify_decoded(_), do: {:error, :not_an_rsa_private_key}

  defp decode_certs(pem) do
    ders =
      :public_key.pem_decode(pem)
      |> Enum.flat_map(fn
        {:Certificate, der, _} -> [der]
        _ -> []
      end)

    if ders == [] do
      {:error, :no_cert_entries}
    else
      {:ok, ders}
    end
  end
end
