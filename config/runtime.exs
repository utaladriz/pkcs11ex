import Config

# Runtime configuration. This file is evaluated at boot time on the target host,
# not at compile time — read host- and environment-specific values here.
#
# See docs/specs/api.md §1 for the full schema. Sketch:
#
#   config :pkcs11ex,
#     allowed_algs: [:PS256],
#     default_slot: :platform,
#     trust_policy: MyApp.TrustPolicy,
#     driver_pins: %{
#       "/usr/lib/libeTPkcs11.so" =>
#         System.fetch_env!("PKCS11EX_SAFENET_DRIVER_SHA256")
#     },
#     slots: [
#       platform: [
#         type: :cloud_hsm,
#         driver: "/opt/google/kmsp11/libkmsp11.so",
#         driver_config: System.fetch_env!("KMSP11_CONFIG"),
#         keys: [
#           signing: [label: "platform-signing-key", cert_label: "platform-cert"]
#         ]
#       ]
#     ]
#
# Avoid storing PINs or P12 passwords in config — they belong in `pin_callback`
# implementations the host application provides.
