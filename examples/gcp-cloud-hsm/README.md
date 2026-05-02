# Using `pkcs11ex` with GCP Cloud HSM

End-to-end setup for signing with a key stored in [GCP Cloud HSM](https://cloud.google.com/kms/docs/hsm) via Google's PKCS#11 provider, **`libkmsp11`**.

## What you need

1. A GCP project with the **Cloud KMS** and **Cloud HSM** APIs enabled.
2. A KMS **key ring** and a **HSM-protected** asymmetric signing key (the algorithm in this example is `RSA_SIGN_PSS_2048_SHA256`).
3. **Workload Identity Federation** (recommended) or a service-account key file granting the runtime principal the `roles/cloudkms.signerVerifier` role on the key.
4. **`libkmsp11.so`** installed on the host that will run your Elixir application.

`pkcs11ex` itself doesn't talk to GCP — it talks to `libkmsp11.so`, which talks to GCP. As far as `pkcs11ex` is concerned, this is just another PKCS#11 module.

## 1. Create the KMS key

```sh
PROJECT="your-gcp-project"
LOCATION="us-central1"
KEYRING="pkcs11ex-demo"
KEY="signing-key"

gcloud kms keyrings create $KEYRING \
  --project=$PROJECT --location=$LOCATION

gcloud kms keys create $KEY \
  --project=$PROJECT --location=$LOCATION --keyring=$KEYRING \
  --purpose=asymmetric-signing \
  --default-algorithm=rsa-sign-pss-2048-sha256 \
  --protection-level=hsm
```

## 2. Install `libkmsp11.so`

Download the latest release from <https://github.com/GoogleCloudPlatform/kms-integrations/releases> for your platform. The library is typically installed at:

- Linux: `/opt/google/kmsp11/libkmsp11.so`
- macOS: `/opt/google/kmsp11/libkmsp11.dylib`

`pkcs11ex` accepts either path.

## 3. Configure `libkmsp11`

Create `kmsp11.yaml` (see `kmsp11.yaml` in this directory). Adjust:

- `key_ring`: full resource name of your keyring.
- `service_account`: leave unset to use Application Default Credentials (recommended in GCE/GKE/Cloud Run; relies on Workload Identity Federation). Otherwise point at a service-account JSON keyfile.

The library also reads its config path from the **`KMS_PKCS11_CONFIG`** env var. **`pkcs11ex` sets this for you** when you supply the `:driver_config` option in your slot config — see step 4.

## 4. Configure `pkcs11ex`

Drop the contents of `runtime.exs` (in this directory) into your application's `config/runtime.exs`. The relevant block:

```elixir
config :pkcs11ex,
  allowed_algs: [:PS256],
  default_slot: :gcp,
  slots: [
    gcp: [
      type: :cloud_hsm,
      driver: System.get_env("PKCS11EX_KMSP11_LIB", "/opt/google/kmsp11/libkmsp11.so"),
      driver_config: System.fetch_env!("PKCS11EX_KMSP11_CONFIG"),
      keys: [
        signing: [label: "signing-key"]
      ]
    ]
  ]
```

Key points:

- **`type: :cloud_hsm`** — `pkcs11ex` skips PKCS#11 user PIN; cloud auth flows through libkmsp11's own configuration. Calling `Pkcs11ex.Slot.login/2` on this slot returns `{:error, :no_pin_required}`.
- **`driver_config`** — absolute path to your `kmsp11.yaml`. `pkcs11ex` writes this to the `KMS_PKCS11_CONFIG` env var before `dlopen`, which is how libkmsp11 finds its config.
- **`keys.signing.label`** — must match the KMS key's name (the `--key` argument from step 1). libkmsp11 maps PKCS#11 `CKA_LABEL` to KMS resource names directly.

## 5. Sign

```elixir
{:ok, signature} =
  Pkcs11ex.sign_bytes("payment instruction bytes",
    signer: {:gcp, :signing},
    alg: :PS256
  )
```

Or as a JWS detached:

```elixir
{:ok, jws} =
  Pkcs11ex.JWS.sign(payload,
    signer: {:gcp, :signing},
    alg: :PS256,
    x5c: leaf_cert_der
  )
```

## Authentication notes

- **Recommended (zero secrets in your app):** run on GCE / GKE / Cloud Run with Workload Identity Federation. libkmsp11 picks up Application Default Credentials from the metadata server. Leave `service_account` unset in `kmsp11.yaml`.
- **Service account keyfile:** set the `GOOGLE_APPLICATION_CREDENTIALS` env var to the keyfile path. Discouraged for production.
- **For local development:** `gcloud auth application-default login` populates ADC for your shell session.

## Tested versions

- `libkmsp11` 1.6+
- GCP Cloud HSM (FIPS 140-2 L3 protection level)
- `pkcs11ex` ≥ Phase 3
