defmodule Pkcs11exAudit.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/utaladriz/pkcs11ex"

  def project do
    [
      app: :pkcs11ex_audit,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      name: "pkcs11ex_audit"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :inets, :ssl]
    ]
  end

  defp deps do
    [
      # Dev-only — required by `mix hex.publish` to build the docs
      # tarball that uploads to hexdocs.pm. Not pulled into runtime
      # by consumers (`only: :dev, runtime: false`).
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Append-only hash-chained audit log + RFC 3161 timestamp anchoring " <>
      "for pkcs11ex. Sister library; opt-in dep for deployments that " <>
      "need tamper-evident signature audit trails."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Main library" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/pkcs11ex_audit/CHANGELOG.md"
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
      source_url: @source_url,
      groups_for_modules: [
        "Public API": [Pkcs11ex.Audit, Pkcs11ex.Audit.Entry],
        Storage: [Pkcs11ex.Audit.Storage, Pkcs11ex.Audit.Storage.InMemory],
        Anchoring: [Pkcs11ex.Audit.Anchor.RFC3161]
      ]
    ]
  end
end
