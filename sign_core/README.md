# sign_core

Signer-agnostic primitives for digital signatures over PDF (PAdES), XML (XAdES), and JWS — designed to plug into whatever signature source your deployment has.

Part of the [`pkcs11ex` family](https://github.com/utaladriz/pkcs11ex). Use this package alone if you only need to **verify** signed documents; pair with [`pkcs11ex`](../) for HSM signing or [`soft_signer`](../soft_signer/) for software-key signing.

## What's in here

- **`SignCore.Signer`** — the protocol every signer implements
- **`SignCore.PDF`** — PAdES B-B and B-T sign + verify
- **`SignCore.XML`** — XAdES B-B and B-T sign + verify (XML-DSig + ETSI EN 319 132-1)
- **`SignCore.JWS`** — JWS detached signatures (RFC 7797)
- **`SignCore.CMS`** — RFC 5652 CMS / SignedData encoding (used by PDF)
- **`SignCore.X509`** — thin wrapper around OTP's `:public_key`-decoded certificates
- **`SignCore.Policy`** — pluggable trust policy (allowlist before signature math)
- **`SignCore.Algorithm`** — PS256, RS256 algorithm adapters

## Verify-only deployment

This package alone is enough to verify signed documents. No NIF, no openssl, no PKCS#11 stack.

```elixir
# mix.exs
def deps, do: [{:sign_core, "~> 1.0"}]
```

```elixir
# Configure your trust policy (see docs/specs/api.md §2.3)
Application.put_env(:pkcs11ex, :trust_policy, MyApp.SignerAllowlist)

# Verify
{:ok, subject_id} = SignCore.PDF.verify(signed_pdf_bytes)
{:ok, subject_id} = SignCore.XML.verify(signed_xml_bytes)
{:ok, subject_id} = SignCore.JWS.verify(jws, payload)
```

## Signing

Pick a signer provider and pass it as `:signer`:

```elixir
{:ok, signed_pdf} =
  SignCore.PDF.sign(pdf,
    signer: my_signer,           # any struct that implements SignCore.Signer
    alg: :PS256,
    x5c: leaf_der                # cert chain for the embedded x5c
  )
```

See [`pkcs11ex`](../) for HSM signers or [`soft_signer`](../soft_signer/) for PKCS#12 / PKCS#8 PEM signers.

## Implementing a custom signer

```elixir
defmodule MyApp.KMSSigner do
  defstruct [:key_id, :region]
end

defimpl SignCore.Signer, for: MyApp.KMSSigner do
  def sign(%MyApp.KMSSigner{key_id: kid, region: r}, tbs, opts) do
    alg = Keyword.fetch!(opts, :alg)
    encoding_context = Keyword.get(opts, :encoding_context, :der)

    with {:ok, raw} <- call_kms(kid, r, tbs, alg),
         {:ok, adapter} <- SignCore.Algorithm.lookup(alg) do
      adapter.encode_signature(raw, encoding_context)
    end
  end
end
```

That's all. The format adapters (PDF/XML/JWS) don't need to know your provider exists.

## Architectural invariants

- **Allowlist before math.** Every verify path resolves the sender's certificate against `SignCore.Policy` before doing any cryptographic verification. Attacker-supplied PDFs/XMLs can't push verify into expensive math without first matching the allowlist.
- **Append-attack detection.** PAdES verify checks `c + d == byte_size(pdf)` before parsing the CMS — bytes appended after the signed range are refused with `:incremental_update_after_signature`.
- **No software signing in this package.** This package builds the bytes-to-be-signed and assembles the output, but never produces a signature. That's the signer's job. Verify-only deployments shipping just `sign_core` cannot sign by package boundary.

See [`docs/specs/specs.md`](../docs/specs/specs.md) for the canonical specifications.

## License

Apache 2.0. The vendored `xmerl_c14n` (BSD-2) lives in `lib/sign_core/xml/c14n/`; see that directory's `LICENSE.md` for its original copyright.
