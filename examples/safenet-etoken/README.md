# SafeNet eToken — `pkcs11ex` demo

Signs a one-page PDF with a SafeNet eToken's hardware-resident
RSA-2048 key, then self-verifies and (if available) cross-verifies
with Poppler's `pdfsig`.

## Prerequisites

- macOS with **SafeNet Authentication Client** installed (driver
  expected at `/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib`).
- An eToken plugged in with at least one RSA-2048 keypair.
- Optional: `brew install poppler` for the `pdfsig` cross-check.

## Run

```sh
PKCS11EX_SAFENET_PIN=<pin> \
PKCS11EX_SAFENET_KEY_LABEL=<label> \
  MIX_ENV=test mix run examples/safenet-etoken/demo.exs
```

`PKCS11EX_SAFENET_KEY_LABEL=""` (empty) is valid for self-generated
SafeNet keys with no `CKA_LABEL` set — the NIF auto-matches by
class.

`MIX_ENV=test` is required to load the `:x509` Hex package
(test-only dep) used to build a wrapper cert around the eToken's
public key. In production you'd use a CA-issued cert that already
wraps the same public key (skipping the wrapper-cert step).

## Expected output

```
--- wrote 9441-byte PDF to /Users/.../signed_demo.pdf
--- Pkcs11ex.PDF.verify: OK (subject_id=:anyone)
--- pdfsig: Signature is Valid
```

`signed_demo.pdf` opens cleanly in Preview / Acrobat. The
`/Sig` field is invisible (no widget rectangle) — that's by design
in v1; visible signature appearance streams are a Phase 4b.x
feature.

## What the demo proves

| Layer | Check |
|---|---|
| Hardware | RSA-PSS sign returns a 256-byte signature from the eToken |
| Layer 2 | `Pkcs11ex.sign_bytes/2` routes through `Slot.Server` |
| Layer 3 | `Pkcs11ex.PDF.sign/2` produces a PAdES B-B PDF |
| Self-verify | `Pkcs11ex.PDF.verify/2` validates math against the cert's SPKI |
| Third-party | `pdfsig` validates the same math independently |

## Caveats

- The wrapper cert is software-self-signed and not in any system
  trust store, so `pdfsig` reports `Certificate Validation:
  Unknown issue`. That's about chain trust, not signature math.
  The math passes both verifiers.
- The PIN is read from env. Wrong PINs decrement the eToken's
  hardware-persistent attempt counter (default lock-out at 5
  wrong tries). Don't iterate on it without verifying it works
  via something like the SafeNet Authentication Client GUI first.
