defmodule Mix.Tasks.Pkcs11ex.ImportP12 do
  @shortdoc "Import a PKCS#12 bundle into a configured PKCS#11 slot"

  @moduledoc """
  Imports the private key + leaf certificate from a PKCS#12 (`.p12` / `.pfx`)
  bundle into a configured PKCS#11 slot.

  Intended for: SoftHSM provisioning in dev/CI, one-shot loading of taxpayer
  / legal-proxy certificates into write-permitted file-backed tokens, fixture
  setup in test suites. **Not** suitable for production HSMs (most reject
  software-key import by design; cloud HSMs do so categorically).

  See `docs/specs/api.md` §5.1 for the canonical contract.

  ## Usage

      mix pkcs11ex.import_p12 \\
        --in legal_proxy.p12 \\
        --slot legal_proxy \\
        --label proxy-signing-key \\
        [--cert-label proxy-cert] \\
        [--id 0x01]

  ## Required flags

    * `--in PATH` — path to the `.p12` / `.pfx` bundle.
    * `--slot SLOT_REF` — atom of a configured slot (must exist in
      `:pkcs11ex` `:slots` config, must be write-permitted).
    * `--label LABEL` — `CKA_LABEL` for the imported private key.

  ## Optional flags

    * `--cert-label LABEL` — `CKA_LABEL` for the certificate. Defaults to `--label`.
    * `--id HEX` — `CKA_ID` (hex-encoded). Auto-generated if omitted.
    * `--password-from-env VAR` — read P12 password from env var (CI).
    * `--pin-from-env VAR` — read user PIN from env var (CI).

  ## Prompts

  When `--password-from-env` / `--pin-from-env` are not used, the task
  prompts for the bundle password and the slot's user PIN with terminal
  echo disabled.

  ## Threat model — plaintext key in BEAM heap

  This task is the only path in `pkcs11ex` that handles a software
  RSA private key in cleartext. The key flows through BEAM-managed
  binaries:

    1. `openssl pkcs12 -in <bundle> -nocerts -nodes` extracts the key
       as a PEM blob into the task's stdout (captured by `System.cmd`
       into a binary).
    2. `:public_key.pem_decode/1` and `pem_entry_decode/1` produce an
       Erlang `RSAPrivateKey` record — modulus, private exponent, the
       five CRT parameters, all as integers / binaries on the BEAM heap.
    3. The components are marshaled across the NIF as binaries, then
       the NIF zeroizes its Rust-side copies (cryptoki + `Zeroizing`).

    Step 1 and step 2 BEAM heap memory cannot be wiped — the BEAM has
    no zeroization primitive for managed binaries / integers, and the
    GC may keep them around well past the task's nominal lifetime.

  **The only mitigations are:**

    * Run the task in a short-lived process; let the BEAM exit
      immediately after the import.
    * Don't run on a multi-tenant box where another process can read
      `/proc/<pid>/maps` or trigger a core dump.
    * Treat the bundle on disk as the canonical secret — the BEAM-heap
      copy is a temporary echo of it.

  Use `pkcs11ex` directly (HSM-only path) for any key that should
  never have a software copy in memory. This task is for provisioning
  fixtures, dev/CI, and importing dormant taxpayer / legal-proxy
  certificates into write-permitted file-backed tokens.

  Both the bundle password and the user PIN are passed once into the
  flow and not stored after this task returns. They transit BEAM
  memory the same way and are subject to the same caveats.
  """

  use Mix.Task

  alias Pkcs11ex.Native.RsaPrivateComponents

  @switches [
    in: :string,
    slot: :string,
    label: :string,
    cert_label: :string,
    id: :string,
    password_from_env: :string,
    pin_from_env: :string
  ]

  @impl Mix.Task
  def run(argv) do
    {opts, _args, invalid} = OptionParser.parse(argv, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    Mix.Task.run("app.start")

    in_path = require_opt!(opts, :in)
    slot_ref = require_opt!(opts, :slot) |> String.to_atom()
    key_label = require_opt!(opts, :label)
    cert_label = opts[:cert_label] || key_label
    id_bin = decode_id(opts[:id])

    unless File.regular?(in_path) do
      Mix.raise("bundle not found: #{in_path}")
    end

    p12_password = fetch_secret(opts, :password_from_env, "PKCS#12 bundle password: ")
    user_pin = fetch_secret(opts, :pin_from_env, "Slot #{slot_ref} user PIN: ")

    with {:ok, key_pem, cert_pem} <- extract_p12(in_path, p12_password),
         {:ok, components} <- parse_rsa_components(key_pem),
         {:ok, cert_der, subject_der} <- parse_cert(cert_pem) do
      args = [
        components: components,
        cert_der: cert_der,
        subject_der: subject_der,
        key_label: key_label,
        cert_label: cert_label,
        id: id_bin
      ]

      case Pkcs11ex.Slot.Server.import_keypair(slot_ref, args, pin: user_pin) do
        :ok ->
          Mix.shell().info(
            "Imported keypair into slot #{slot_ref}: " <>
              "key #{inspect(key_label)}, cert #{inspect(cert_label)}"
          )

        {:error, :slot_not_found} ->
          Mix.raise(
            "slot #{inspect(slot_ref)} is not running. Configure it under " <>
              ":pkcs11ex :slots and ensure the application is started."
          )

        {:error, reason} ->
          Mix.raise("import failed: #{inspect(reason)}")
      end
    else
      {:error, reason} -> Mix.raise("#{reason}")
    end
  end

  # ---------- argument plumbing ----------

  defp require_opt!(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> value
      :error -> Mix.raise("--#{String.replace(to_string(key), "_", "-")} is required")
    end
  end

  defp decode_id(nil), do: ""

  defp decode_id("0x" <> hex), do: decode_id(hex)

  defp decode_id(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> bytes
      :error -> Mix.raise("--id must be hex (e.g., 0x01 or 01)")
    end
  end

  defp fetch_secret(opts, env_key, prompt) do
    case opts[env_key] do
      nil -> prompt_secret(prompt)
      var -> System.get_env(var) || Mix.raise("env var #{var} not set")
    end
  end

  defp prompt_secret(prompt) do
    # Terminal-echo-off prompt. Falls back to plain IO.gets if stdio isn't a
    # TTY (e.g., redirected) — operators using non-interactive contexts should
    # use --password-from-env / --pin-from-env instead.
    Mix.shell().info(prompt)

    case :io.get_password() do
      {:error, _} ->
        case Mix.shell().prompt("") |> String.trim() do
          "" -> Mix.raise("empty secret")
          val -> val
        end

      :eof ->
        Mix.raise("EOF reading secret")

      data when is_list(data) ->
        result = data |> List.to_string() |> String.trim_trailing("\n")
        if result == "", do: Mix.raise("empty secret"), else: result
    end
  end

  # ---------- PKCS#12 extraction (openssl) ----------

  defp extract_p12(path, password) do
    case System.find_executable("openssl") do
      nil ->
        {:error, "openssl CLI not on PATH"}

      openssl ->
        env = [{"PKCS11EX_P12_PWD", password}]

        with {:ok, certs_pem} <-
               run_openssl(
                 openssl,
                 ["pkcs12", "-in", path, "-password", "env:PKCS11EX_P12_PWD", "-nokeys", "-nodes"],
                 env
               ),
             {:ok, key_pem} <-
               run_openssl(
                 openssl,
                 ["pkcs12", "-in", path, "-password", "env:PKCS11EX_P12_PWD", "-nocerts", "-nodes"],
                 env
               ) do
          {:ok, key_pem, certs_pem}
        end
    end
  end

  defp run_openssl(openssl, args, env) do
    case System.cmd(openssl, args, env: env, stderr_to_stdout: true) do
      {output, 0} ->
        {:ok, output}

      {output, _} ->
        # OpenSSL's wording for "wrong P12 password" varies across
        # versions: "mac verify failure" (1.0.x), "Mac verify error"
        # (3.x). Match a case-insensitive prefix that catches both.
        cond do
          output =~ ~r/mac verify (failure|error)/i ->
            {:error, "PKCS#12 password incorrect"}

          true ->
            {:error, "openssl pkcs12 failed: #{String.slice(output, 0, 200)}"}
        end
    end
  end

  # ---------- PEM parsing ----------

  defp parse_rsa_components(pem) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, "no PEM entries found in extracted key"}

      entries ->
        case find_rsa_private_key(entries) do
          {:ok, rsa_record} ->
            {:ok,
             %RsaPrivateComponents{
               modulus: int_to_bin(elem(rsa_record, 2)),
               public_exponent: int_to_bin(elem(rsa_record, 3)),
               private_exponent: int_to_bin(elem(rsa_record, 4)),
               prime1: int_to_bin(elem(rsa_record, 5)),
               prime2: int_to_bin(elem(rsa_record, 6)),
               exponent1: int_to_bin(elem(rsa_record, 7)),
               exponent2: int_to_bin(elem(rsa_record, 8)),
               coefficient: int_to_bin(elem(rsa_record, 9))
             }}

          :error ->
            {:error, "no RSA private key found in extracted key PEM"}
        end
    end
  end

  defp find_rsa_private_key(entries) do
    Enum.reduce_while(entries, :error, fn entry, _ ->
      case entry do
        {:RSAPrivateKey, _, _} = e ->
          {:halt, {:ok, :public_key.pem_entry_decode(e)}}

        {:PrivateKeyInfo, _, _} = e ->
          # PKCS#8 — decode then check inner type. RSAPrivateKey has 11 elements
          # (tag + 9 fields + otherPrimeInfos).
          case :public_key.pem_entry_decode(e) do
            rsa when is_tuple(rsa) and tuple_size(rsa) == 11 and elem(rsa, 0) == :RSAPrivateKey ->
              {:halt, {:ok, rsa}}

            _ ->
              {:cont, :error}
          end

        _ ->
          {:cont, :error}
      end
    end)
  end

  defp int_to_bin(n) when is_integer(n) and n >= 0,
    do: :binary.encode_unsigned(n, :big)

  defp parse_cert(pem) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, "no PEM entries found in extracted cert"}

      entries ->
        case Enum.find(entries, fn {tag, _, _} -> tag == :Certificate end) do
          {:Certificate, der, _} ->
            plain = :public_key.pkix_decode_cert(der, :plain)
            tbs = elem(plain, 1)
            subject = elem(tbs, 6)
            subject_der = :public_key.der_encode(:Name, subject)
            {:ok, der, subject_der}

          nil ->
            {:error, "no Certificate found in extracted cert PEM"}
        end
    end
  end
end
