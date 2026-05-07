# soft_signer changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`SoftSigner.PKCS12` and `SoftSigner.PKCS8` `do_sign/3` surface typed atom errors** for well-known sign-side failure modes. EC key with PSS opts, missing OTP padding combos, and similar `:public_key.sign/3` failures now return `{:error, :incompatible_alg}` instead of `{:error, {:soft_sign_failed, "..."}}`. Anything else still falls back to the stringified message wrapper for debugging.
- **Both signer moduledocs now spell out the BEAM-heap threat model.** Implementation unchanged; the doc makes it explicit that the decoded RSA private key is BEAM-resident for the lifetime of any reference to the struct, and that the package boundary between `:soft_signer` and `:pkcs11ex` is the deployment-topology mitigation.

## [0.1.0]

Initial release. Software-key implementations of the `SignCore.Signer` protocol.

### Added

- **`SoftSigner.PKCS12`** — load PKCS#12 (`.p12` / `.pfx`) bundles via the `openssl pkcs12` CLI, sign via `:public_key.sign/3`. Cert chain extraction (`cert_chain/1`) returns the leaf + intermediates leaf-first for direct use in `:x5c`. Friendly errors for `:bundle_not_found`, `{:openssl, "PKCS#12 password incorrect"}`, etc.
- **`SoftSigner.PKCS8`** — load PKCS#8 PEM private keys (encrypted or unencrypted) plus a separately supplied certificate (single or chain). Both file-path opts (`:key_path` / `:cert_path`) and in-memory PEM string opts (`:key_pem` / `:cert_pem`) supported. Distinguishes encrypted-without-password (`:password_required`) from wrong-password (`:wrong_password`) via the OTP-28 PEM-decode failure mode classification.
- **`SignCore.Signer` protocol implementations** for both structs — RSASSA-PSS (`:PS256`) and RSASSA-PKCS1-v1_5 (`:RS256`) signature math.

### Compatibility

- Requires `:sign_core` `~> 0.1`.
- Requires `openssl` CLI on PATH for PKCS#12 decryption (no pure-Erlang PKCS#12 decode — the format's encryption variants are too vendor-specific to roll safely).

### Architectural notes

- The boundary between `pkcs11ex` (hardware) and `soft_signer` (software) is enforced by the Hex dep tree: deployments that omit `:soft_signer` from their `mix.lock` cannot software-sign by package boundary, not just by configuration.
