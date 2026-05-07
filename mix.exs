defmodule Pkcs11ex.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/utaladriz/pkcs11ex"
  @sign_core_version "~> 0.1"
  @pkcs11ex_audit_version "~> 0.1"

  def project do
    [
      app: :pkcs11ex,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      # Protocol consolidation freezes the impl table at compile
      # time; disable for tests so test-only `defimpl` blocks (e.g.
      # `JWSTestSigner` in test/pkcs11ex/jws_test.exs) work.
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      source_url: @source_url,
      name: "pkcs11ex",
      test_coverage: [tool: ExCoveralls],
      dialyzer: [plt_add_apps: [:mix, :ex_unit]]
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.html": :test,
        "coveralls.json": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :inets, :ssl, :xmerl],
      mod: {Pkcs11ex.Application, []}
    ]
  end

  defp deps do
    [
      # Runtime
      {:rustler, "~> 0.36"},
      {:nimble_options, "~> 1.1"},
      {:telemetry, "~> 1.3"},
      {:jason, "~> 1.4"},
      {:plug, "~> 1.16", optional: true},

      # Signer-agnostic format adapters (PDF/PAdES, XML/XAdES, JWS).
      # `pkcs11ex` provides a `Pkcs11ex.Signer` impl of
      # `SignCore.Signer` that routes signing through the PKCS#11
      # NIF; verify-only and software-keyed deployments depend on
      # `:sign_core` directly without pulling the NIF.
      sign_core_dep(),

      # Test-only fixture support: building X.509 certs that wrap a
      # SoftHSM-resident public key so verify can mathematically check
      # SoftHSM-produced signatures.
      {:x509, "~> 0.8", only: :test},

      # Sister library — opt-in audit trail. `optional: true` tells
      # consumers of `pkcs11ex` that they can omit `pkcs11ex_audit`
      # from their own deps; `Pkcs11ex.JWS.sign`'s `:audit_to` hook
      # gates on `Code.ensure_loaded?(Pkcs11ex.Audit)` at runtime.
      pkcs11ex_audit_dep(),

      # Dev / test only
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end

  # Path dep when developing inside the monorepo; Hex dep when
  # running from a published `pkcs11ex` package (no sibling
  # `sign_core/` directory present in the consumer's tree).
  #
  # `HEX_PUBLISH=1` forces the Hex dep regardless of local files —
  # use it when running `mix hex.publish` from inside the monorepo,
  # since Hex refuses to publish a package with a path dep.
  defp sign_core_dep do
    if monorepo_dev?("sign_core"),
      do: {:sign_core, path: "sign_core"},
      else: {:sign_core, @sign_core_version}
  end

  defp pkcs11ex_audit_dep do
    if monorepo_dev?("pkcs11ex_audit"),
      do: {:pkcs11ex_audit, path: "pkcs11ex_audit", optional: true},
      else: {:pkcs11ex_audit, @pkcs11ex_audit_version, optional: true}
  end

  defp monorepo_dev?(subdir) do
    System.get_env("HEX_PUBLISH") in [nil, ""] and
      File.dir?(subdir) and
      File.regular?(Path.join(subdir, "mix.exs"))
  end

  defp description do
    "Hardware-backed digital signatures for Elixir, via PKCS#11. " <>
      "Layered library with first-class adapters for JWS (RFC 7797), PDF (PAdES), " <>
      "and XML (XML-DSig / XAdES). Backed by HSMs and hardware tokens through a " <>
      "Rust/Rustler bridge."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Specs" => "#{@source_url}/blob/main/docs/specs/specs.md"
      },
      maintainers: ["utaladriz"],
      files: ~w(
        lib
        native/pkcs11ex_nif/src
        native/pkcs11ex_nif/Cargo.toml
        native/pkcs11ex_nif/Cargo.lock
        .formatter.exs
        mix.exs
        README.md
        LICENSE
        CHANGELOG.md
        docs/specs
      )
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "CHANGELOG.md",
        "docs/specs/specs.md",
        "docs/specs/api.md"
      ],
      source_ref: "v#{@version}",
      source_url: @source_url,
      groups_for_modules: [
        "Layer 2 — Primitives": [Pkcs11ex],
        "Signer (SignCore.Signer impl)": [Pkcs11ex.Signer],
        "Convenience wrappers": [
          Pkcs11ex.JWS,
          Pkcs11ex.PDF,
          Pkcs11ex.XML,
          Pkcs11ex.X509
        ],
        Operational: [
          Pkcs11ex.Slot,
          Pkcs11ex.PIN,
          Pkcs11ex.PKCS12,
          Pkcs11ex.Config
        ]
      ]
    ]
  end
end
