import Config

# Tests run with the Allow policy (which itself refuses to start under :prod).
# Real verification tests will switch to PinnedRegistry with fixture certs.
config :pkcs11ex,
  trust_policy: Pkcs11ex.Policy.Allow,
  # Skip on-disk driver and SHA-256 pin checks in tests; fixtures are typically
  # configured in-memory or with non-existent paths.
  check_files: false

# Optional SoftHSM2 integration tests — opt in via env var.
#
# if System.get_env("PKCS11EX_SOFTHSM_LIB") do
#   config :pkcs11ex,
#     slots: [
#       test_softhsm: [
#         type: :soft_hsm,
#         driver: System.get_env("PKCS11EX_SOFTHSM_LIB"),
#         slot_match: {:slot_id, String.to_integer(System.get_env("PKCS11EX_SOFTHSM_SLOT", "0"))},
#         keys: [signing: [label: "test-signing-key"]]
#       ]
#     ]
# end
