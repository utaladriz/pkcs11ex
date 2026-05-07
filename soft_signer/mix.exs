defmodule SoftSigner.MixProject do
  use Mix.Project

  @version "0.0.1"
  @source_url "https://github.com/utaladriz/pkcs11ex"

  def project do
    [
      app: :soft_signer,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      source_url: @source_url,
      name: "soft_signer"
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    [
      {:sign_core, path: "../sign_core"},
      {:x509, "~> 0.8", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Software-key implementation of `SignCore.Signer` for PKCS#12 (.p12 / .pfx) " <>
      "bundles and PKCS#8 PEM private keys. Use with `sign_core` to produce " <>
      "PAdES / XAdES / JWS signatures from filesystem-resident keys."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      maintainers: ["utaladriz"]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}"
    ]
  end
end
