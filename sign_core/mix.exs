defmodule SignCore.MixProject do
  use Mix.Project

  @version "0.1.2"
  @source_url "https://github.com/utaladriz/pkcs11ex"

  def project do
    [
      app: :sign_core,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      name: "sign_core"
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key, :inets, :ssl, :xmerl]]
  end

  defp deps do
    [
      {:telemetry, "~> 1.3"},
      {:jason, "~> 1.4"},

      # Test-only fixture support: building X.509 certs that wrap a
      # signer-resident public key so verify can mathematically check
      # signer-produced signatures.
      {:x509, "~> 0.8", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Signer-agnostic PDF (PAdES B-B/B-T) and XML (XAdES B-B/B-T) signing primitives. " <>
      "Wire in your own signature source (PKCS#11 hardware via `pkcs11ex`, " <>
      "PKCS#12 / PKCS#8 software keys via `soft_signer`, cloud KMS, etc.) by " <>
      "implementing the `SignCore.Signer` protocol."
  end

  defp package do
    [
      licenses: ["Apache-2.0", "BSD-2-Clause"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/sign_core/CHANGELOG.md"
      },
      maintainers: ["Ubaldo Taladriz"],
      files:
        ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md) ++
          ["lib/sign_core/xml/c14n/LICENSE.md"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end
end
