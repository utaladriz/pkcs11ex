defmodule Pkcs11ex.Native do
  @moduledoc false
  # Rustler-backed bridge into native/pkcs11ex_nif.
  # Public callers should never reach this module directly — they go through
  # Pkcs11ex.* surface functions which wrap NIF calls with Elixir-side concerns
  # (allowlist gates, policy resolution, telemetry).

  use Rustler, otp_app: :pkcs11ex, crate: "pkcs11ex_nif"

  @typedoc "Opaque resource referencing a loaded PKCS#11 module."
  @type module_resource :: reference()

  # Stubs — replaced by the Rust-side #[rustler::nif] exports at NIF load time.
  def version, do: :erlang.nif_error(:nif_not_loaded)
  def module_load(_path), do: :erlang.nif_error(:nif_not_loaded)
  def module_load_pinned(_path, _expected_sha256_hex), do: :erlang.nif_error(:nif_not_loaded)
  def list_slots(_module), do: :erlang.nif_error(:nif_not_loaded)

  def sign(_module, _slot_id, _pin, _mechanism, _key_label, _data),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify(_module, _slot_id, _mechanism, _key_label, _data, _signature),
    do: :erlang.nif_error(:nif_not_loaded)

  def generate_rsa_keypair(_module, _slot_id, _pin, _label, _bits),
    do: :erlang.nif_error(:nif_not_loaded)

  def export_rsa_public_key(_module, _slot_id, _key_label),
    do: :erlang.nif_error(:nif_not_loaded)

  # ---------- Stateful session API (Phase 2) ----------

  def session_open(_module, _slot_id), do: :erlang.nif_error(:nif_not_loaded)
  def session_login(_session, _pin), do: :erlang.nif_error(:nif_not_loaded)
  def session_logout(_session), do: :erlang.nif_error(:nif_not_loaded)

  def sign_with_session(_session, _mechanism, _key_label, _data),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify_with_session(_session, _mechanism, _key_label, _data, _signature),
    do: :erlang.nif_error(:nif_not_loaded)

  # ---------- Provisioning (mix pkcs11ex.import_p12) ----------

  def import_rsa_private_key(_session, _label, _id, _components),
    do: :erlang.nif_error(:nif_not_loaded)

  def import_x509_certificate(_session, _label, _id, _subject_der, _cert_der),
    do: :erlang.nif_error(:nif_not_loaded)

  defmodule RsaPrivateComponents do
    @moduledoc false
    # Mirrors pkcs11ex_nif::RsaPrivateComponents. Used by the import_p12 mix
    # task; never appears on the runtime sign/verify path.
    defstruct [
      :modulus,
      :public_exponent,
      :private_exponent,
      :prime1,
      :prime2,
      :exponent1,
      :exponent2,
      :coefficient
    ]

    @type t :: %__MODULE__{
            modulus: binary(),
            public_exponent: binary(),
            private_exponent: binary(),
            prime1: binary(),
            prime2: binary(),
            exponent1: binary(),
            exponent2: binary(),
            coefficient: binary()
          }
  end

  defmodule SlotInfo do
    @moduledoc false
    # Mirrors the Rust-side `pkcs11ex_nif::SlotInfo` struct, used as the return
    # shape of `list_slots/1`.
    defstruct [:slot_id, :description, :manufacturer, :token_present, :token_label]

    @type t :: %__MODULE__{
            slot_id: non_neg_integer(),
            description: String.t(),
            manufacturer: String.t(),
            token_present: boolean(),
            token_label: String.t()
          }
  end
end
