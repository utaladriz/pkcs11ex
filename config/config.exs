import Config

config :pkcs11ex,
  signature_header: "JWS-Signature",
  allowed_algs: [:PS256],
  telemetry_prefix: [:pkcs11ex],
  trust_policy: Pkcs11ex.Policy.PinnedRegistry,
  session_timeout: :timer.minutes(5)

# Per-environment overrides (config/dev.exs, config/test.exs, config/prod.exs).
# Only loaded if the file exists, so a downstream consumer of pkcs11ex doesn't
# require all three.
env_config = "#{config_env()}.exs"

if File.exists?(Path.join(__DIR__, env_config)) do
  import_config env_config
end
