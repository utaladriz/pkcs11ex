import Config

# Drop this into your application's config/runtime.exs.
#
# Required env vars:
#   PKCS11EX_KMSP11_LIB     — path to libkmsp11.so / libkmsp11.dylib
#                              (default: /opt/google/kmsp11/libkmsp11.so)
#   PKCS11EX_KMSP11_CONFIG  — path to kmsp11.yaml (this directory has a sample)
#
# Authentication: libkmsp11 reads Application Default Credentials. On GCE /
# GKE / Cloud Run with Workload Identity, that's automatic — no secrets in
# config. For local dev, run `gcloud auth application-default login` first.

config :pkcs11ex,
  allowed_algs: [:PS256],
  default_slot: :gcp,
  slots: [
    gcp: [
      type: :cloud_hsm,
      driver: System.get_env("PKCS11EX_KMSP11_LIB", "/opt/google/kmsp11/libkmsp11.so"),
      driver_config: System.fetch_env!("PKCS11EX_KMSP11_CONFIG"),
      # No :pin_callback — :cloud_hsm slots authenticate via cloud
      # credentials, not PKCS#11 user PIN. Pkcs11ex.Config rule 5 actively
      # rejects pin_callback on a :cloud_hsm slot.
      keys: [
        # Each key entry's :label is the KMS key name (the --key argument
        # to `gcloud kms keys create`). libkmsp11 maps CKA_LABEL → KMS
        # key resource name 1:1.
        signing: [label: "signing-key", cert_label: "signing-cert"]
      ]
    ]
  ]
