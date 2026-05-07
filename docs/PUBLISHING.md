# Publishing to Hex

This monorepo ships **four** Hex packages that depend on each other:

```
sign_core           ← no inter-package deps
  ↑
  ├── pkcs11ex      ← depends on sign_core (+ optional pkcs11ex_audit)
  ├── soft_signer   ← depends on sign_core
  └── pkcs11ex_audit ← no inter-package deps (sister of pkcs11ex)
```

Hex won't accept a package whose `mix.exs` declares a `path:` dep, so the inter-package deps in `pkcs11ex` and `soft_signer` are wired with a runtime fallback:

- **Path dep** when a sibling sub-directory exists (monorepo dev).
- **Hex dep** when it doesn't (Hex consumer's tree, _or_ when `HEX_PUBLISH=1` is set inside the monorepo).

## Publish order

Versions of dependent packages must be on Hex before their dependents publish:

```
1. sign_core          ← publish first
2. pkcs11ex_audit     ← independent, can go anywhere
3. pkcs11ex           ← needs sign_core (+ pkcs11ex_audit) on Hex
4. soft_signer        ← needs sign_core on Hex
```

## Per-package commands

```sh
# 1) sign_core (no inter-package deps)
cd sign_core
mix hex.build                        # dry-run; writes sign_core-X.Y.Z.tar
mix hex.publish                      # publishes to Hex

# 2) pkcs11ex_audit (no inter-package deps)
cd pkcs11ex_audit
mix hex.build
mix hex.publish

# 3) pkcs11ex — flip path deps to Hex deps via HEX_PUBLISH=1
cd ..
HEX_PUBLISH=1 mix hex.build          # confirms requirements list shows
                                     # `:sign_core` and `:pkcs11ex_audit` as Hex deps
HEX_PUBLISH=1 mix hex.publish

# 4) soft_signer — same treatment for sign_core
cd soft_signer
HEX_PUBLISH=1 mix hex.build
HEX_PUBLISH=1 mix hex.publish
```

## Verifying a build before publishing

```sh
HEX_PUBLISH=1 mix hex.build
tar -xOf <package>-<version>.tar metadata.config | grep -A 4 requirements
```

You want to see Hex requirements (`{:sign_core, "~> 0.1"}`), not path deps. The build refuses to proceed otherwise.

## Versioning

Each package versions independently. Bump the package's own `@version` in its `mix.exs` and add a `## [X.Y.Z]` entry to its `CHANGELOG.md`.

When bumping `sign_core` with breaking changes:

1. Bump `sign_core` (e.g. `0.1.0` → `0.2.0`).
2. Update the `@sign_core_version` constant in `pkcs11ex/mix.exs` and `soft_signer/mix.exs` to match the new version constraint (e.g. `"~> 0.1"` → `"~> 0.2"`).
3. Bump those dependent packages too if their public API changes.

## CI / future automation

A GitHub Actions workflow that runs `mix hex.publish --replace` on tag push (`v*`) per package isn't set up yet. For the initial publishes, the manual flow above is fine.
