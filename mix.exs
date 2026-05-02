defmodule Pkcs11ex.MixProject do
  use Mix.Project

  @version "0.0.1"
  @source_url "https://github.com/utaladriz/pkcs11ex"

  def project do
    [
      app: :pkcs11ex,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
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
      extra_applications: [:logger, :crypto, :public_key, :inets, :ssl],
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

      # Test-only fixture support: building X.509 certs that wrap a SoftHSM-resident
      # public key so verify can mathematically check SoftHSM-produced signatures.
      {:x509, "~> 0.8", only: :test},

      # Sister library — opt-in audit trail. The path dep keeps the
      # monorepo working for dev/test; `optional: true` tells consumers
      # of `pkcs11ex` that they can omit `pkcs11ex_audit` from their own
      # deps and `Pkcs11ex.JWS.sign` will gate the `:audit_to` hook on
      # `Code.ensure_loaded?(Pkcs11ex.Audit)` at runtime.
      {:pkcs11ex_audit, path: "pkcs11ex_audit", optional: true},

      # Dev / test only
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
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
      groups_for_modules: [
        "Layer 2 — Primitives": [Pkcs11ex],
        "Layer 3 — Format Adapters": [
          Pkcs11ex.JWS,
          Pkcs11ex.PDF,
          Pkcs11ex.XML
        ],
        Behaviours: [Pkcs11ex.Algorithm, Pkcs11ex.Format, Pkcs11ex.Policy],
        Algorithms: [
          Pkcs11ex.Algorithm.PS256,
          Pkcs11ex.Algorithm.RS256,
          Pkcs11ex.Algorithm.ES256
        ],
        Policies: [
          Pkcs11ex.Policy.PinnedRegistry,
          Pkcs11ex.Policy.CASignedAllowlist,
          Pkcs11ex.Policy.Allow,
          Pkcs11ex.Policy.Helpers
        ],
        Operational: [Pkcs11ex.Slot, Pkcs11ex.PIN, Pkcs11ex.PKCS12]
      ]
    ]
  end
end
