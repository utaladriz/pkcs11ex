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
