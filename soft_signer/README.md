# soft_signer

Software-key implementations of `SignCore.Signer` for PKCS#12 (`.p12` / `.pfx`) bundles and PKCS#8 PEM private keys.

Part of the [`pkcs11ex` family](https://github.com/utaladriz/pkcs11ex). Pair with [`sign_core`](https://hex.pm/packages/sign_core) to sign PDFs, XMLs, or JWS payloads with filesystem-resident keys.

## When to use

- Vendor-issued PKCS#12 bundles (e.g., government tax-authority signing certs)
- Cloud / server deployments where keys live as PEM files alongside certs
- Dev/test environments where standing up a SoftHSM2 instance is overkill
- Migration paths from legacy systems that ship `.p12` instead of HSM access

If your production deployment runs against a hardware HSM, use [`pkcs11ex`](https://hex.pm/packages/pkcs11ex) instead — keep `soft_signer` out of the dep tree to enforce "no software signing" at the package boundary.

## PKCS#12

```elixir
{:ok, signer} = SoftSigner.PKCS12.load("invoice-signer.p12", password: "...")

{:ok, signed_pdf} =
  SignCore.PDF.sign(pdf,
    signer: signer,
    alg: :PS256,
    x5c: SoftSigner.PKCS12.cert_chain(signer)   # P12 carries its own chain
  )
```

P12 decryption shells out to the `openssl pkcs12` CLI — pure-Erlang PKCS#12 decode is fragile across vendor encodings, so we let openssl handle the bytes-to-PEM step. Sign math runs through `:public_key.sign/3` with PSS padding for `:PS256` or PKCS#1 v1.5 for `:RS256`.

Errors:

- `{:error, :bundle_not_found}` — file path doesn't exist
- `{:error, {:openssl, "PKCS#12 password incorrect"}}` — bad password
- `{:error, {:openssl, msg}}` — other openssl failures

## PKCS#8 PEM (key + separate cert)

```elixir
{:ok, signer} =
  SoftSigner.PKCS8.load(
    key_path: "/keys/legal-proxy.key.pem",
    cert_path: "/keys/legal-proxy.cert.pem",
    password: "..."        # only if the PEM is encrypted
  )

{:ok, signed_pdf} =
  SignCore.PDF.sign(pdf,
    signer: signer,
    alg: :PS256,
    x5c: SoftSigner.PKCS8.cert_chain(signer)
  )
```

Supports:

- Unencrypted PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
- Encrypted PKCS#8 (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) with `:password`
- PKCS#1 RSA (`-----BEGIN RSA PRIVATE KEY-----`) — the older format

You can supply key and cert from in-memory PEM strings instead of paths:

```elixir
{:ok, signer} =
  SoftSigner.PKCS8.load(
    key_pem: System.get_env("SIGNING_KEY_PEM"),
    cert_pem: File.read!("/keys/legal-proxy.cert.pem")
  )
```

The cert PEM may contain a single certificate or a chain (leaf first, then intermediates). Errors:

- `{:error, :missing_key}` / `{:error, :missing_cert}` — neither path nor pem supplied
- `{:error, {:pem_not_found, path}}` — supplied path doesn't exist
- `{:error, :no_pem_entries}` — file isn't valid PEM
- `{:error, :no_rsa_private_key}` — PEM has no key entry
- `{:error, :no_cert_entries}` — cert PEM has no `Certificate` entries
- `{:error, :password_required}` — encrypted key, no `:password` supplied
- `{:error, :wrong_password}` — encrypted key, bad password

## Why two structs not one

Both `SoftSigner.PKCS12` and `SoftSigner.PKCS8` produce the same internal shape (`%{rsa_key, leaf_der, chain_ders}`) and share their `defimpl SignCore.Signer` logic. They're separate modules because the **load contract** differs:

- PKCS#12 takes a single file path and a password. The cert chain comes for free.
- PKCS#8 takes separate key + cert sources. The cert chain is whatever the caller supplies.

Keeping them separate makes the type signature of each load function unambiguous and avoids a Boolean opt to switch between modes.

## Algorithm support

- `:PS256` — RSASSA-PSS, SHA-256, MGF1-SHA-256, salt length 32 (the JOSE convention)
- `:RS256` — RSASSA-PKCS1-v1_5, SHA-256

Adding ECDSA / Ed25519 is a small extension to the `defimpl` block; not implemented yet because the production keys we've encountered are all RSA-2048.

## License

Apache 2.0.
