defmodule SoftSigner.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/utaladriz/pkcs11ex"
  @sign_core_version "~> 0.1"

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
      homepage_url: @source_url,
      name: "soft_signer"
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    [
      sign_core_dep(),
      {:x509, "~> 0.8", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  # Path dep when developing inside the monorepo (sibling `sign_core/`
  # exists relative to this package); Hex dep otherwise — that's what
  # consumers of the published Hex package see.
  #
  # `HEX_PUBLISH=1` forces the Hex dep regardless of local files —
  # use it when running `mix hex.publish` from inside the monorepo,
  # since Hex refuses to publish a package with a path dep.
  defp sign_core_dep do
    if monorepo_dev?(), do: {:sign_core, path: "../sign_core"}, else: {:sign_core, @sign_core_version}
  end

  defp monorepo_dev? do
    System.get_env("HEX_PUBLISH") in [nil, ""] and
      File.dir?("../sign_core") and
      File.regular?("../sign_core/mix.exs")
  end

  defp description do
    "Software-key implementation of `SignCore.Signer` for PKCS#12 (.p12 / .pfx) " <>
      "bundles and PKCS#8 PEM private keys (encrypted or not). Use with `sign_core` " <>
      "to produce PAdES / XAdES / JWS signatures from filesystem-resident keys."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/soft_signer/CHANGELOG.md"
      },
      maintainers: ["Ubaldo Taladriz"],
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
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
