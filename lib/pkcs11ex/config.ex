defmodule Pkcs11ex.Config do
  @moduledoc """
  Configuration schema and validator for `pkcs11ex`.

  See `docs/specs/api.md` §1 for the canonical schema. This module is the
  authoritative implementation of that schema. Boot-time validation runs from
  `Pkcs11ex.Application.start/2`; bad configuration prevents the OTP
  application from starting.

  Two-stage validation:

    1. **Schema validation** via `NimbleOptions` — type-checks every key.
    2. **Cross-field invariants** — the eleven rules documented in `api.md`
       §1.5 (allowlist non-empty, default_slot exists, pin_callback rules,
       key/cert exclusivity, driver existence, driver pin SHA-256 match, etc.).

  All failures raise `Pkcs11ex.Error` with `reason: :invalid_config` and a
  `:path` indicating the offending config key.
  """

  alias NimbleOptions

  @known_algs [:PS256, :RS256, :ES256, :EdDSA]
  @slot_types [:cloud_hsm, :token, :soft_hsm]
  @reauth_modes [:prompt, :fail]

  @type alg :: :PS256 | :RS256 | :ES256 | :EdDSA
  @type slot_type :: :cloud_hsm | :token | :soft_hsm

  @type t :: %__MODULE__{
          signature_header: String.t(),
          allowed_algs: [alg(), ...],
          default_slot: atom() | nil,
          trust_policy: module(),
          session_timeout: non_neg_integer(),
          driver_pins: %{optional(String.t()) => String.t()},
          slots: keyword(),
          algorithms: %{optional(atom()) => module()},
          telemetry_prefix: [atom()]
        }

  defstruct [
    :signature_header,
    :allowed_algs,
    :default_slot,
    :trust_policy,
    :session_timeout,
    :driver_pins,
    :slots,
    :algorithms,
    :telemetry_prefix
  ]

  # ---------- NimbleOptions schemas ----------

  @key_keys [
    label: [type: {:or, [:string, nil]}, default: nil],
    id: [type: {:or, [:string, nil]}, default: nil],
    cert_label: [type: {:or, [:string, nil]}, default: nil],
    cert_id: [type: {:or, [:string, nil]}, default: nil],
    alg: [type: {:or, [{:in, @known_algs}, nil]}, default: nil]
  ]

  @slot_keys [
    type: [type: {:in, @slot_types}, required: true],
    driver: [type: :string, required: true],
    driver_config: [type: {:or, [:string, nil]}, default: nil],
    slot_match: [
      type:
        {:or,
         [
           {:tuple, [{:in, [:slot_id]}, :non_neg_integer]},
           {:tuple, [{:in, [:token_label]}, :string]}
         ]},
      default: {:slot_id, 0}
    ],
    pin_callback: [type: {:or, [:mfa, nil]}, default: nil],
    keys: [
      type: :keyword_list,
      default: [],
      keys: [*: [type: :keyword_list, keys: @key_keys]]
    ],
    allowed_algs: [
      type: {:or, [{:list, {:in, @known_algs}}, nil]},
      default: nil
    ],
    session_pool_size: [type: {:or, [:pos_integer, nil]}, default: nil],
    lazy: [type: {:or, [:boolean, nil]}, default: nil],
    reauthentication: [type: {:in, @reauth_modes}, default: :prompt]
  ]

  @schema [
    signature_header: [type: :string, default: "JWS-Signature"],
    allowed_algs: [type: {:list, {:in, @known_algs}}, default: [:PS256]],
    default_slot: [type: :atom, default: nil],
    trust_policy: [type: :atom, default: Pkcs11ex.Policy.PinnedRegistry],
    session_timeout: [type: :non_neg_integer, default: 300_000],
    driver_pins: [type: {:map, :string, :string}, default: %{}],
    slots: [
      type: :keyword_list,
      default: [],
      keys: [*: [type: :keyword_list, keys: @slot_keys]]
    ],
    algorithms: [type: {:map, :atom, :atom}, default: %{}],
    telemetry_prefix: [type: {:list, :atom}, default: [:pkcs11ex]]
  ]

  @doc "Returns the canonical NimbleOptions schema (top-level only)."
  @spec schema() :: keyword()
  def schema, do: @schema

  @doc """
  Loads, validates, and structures the configuration.

  ## Options

    * `:env` — keyword list to validate. Defaults to
      `Application.get_all_env(:pkcs11ex)`.
    * `:check_files` — when `true` (default), validates that each slot's driver
      exists on disk and that any `:driver_pins` SHA-256 matches the on-disk
      file. Tests pass `false` to skip these checks.

  ## Errors

  Raises `Pkcs11ex.Error` with `reason: :invalid_config` on any failure. The
  exception's `:path` indicates the offending config key.
  """
  @spec load!(opts :: keyword()) :: t()
  def load!(opts \\ []) do
    raw = Keyword.get_lazy(opts, :env, fn -> Application.get_all_env(:pkcs11ex) end)
    check_files? = Keyword.get(opts, :check_files, true)

    raw
    |> validate_schema!()
    |> apply_runtime_defaults()
    |> validate_invariants!(check_files?)
    |> to_struct()
  end

  # ---------- Stage 1: schema validation ----------

  # Keys read from Application env that are loader-only (not part of the schema).
  @loader_keys [:check_files]

  defp validate_schema!(raw) do
    raw = Keyword.drop(raw, @loader_keys)

    case NimbleOptions.validate(raw, @schema) do
      {:ok, validated} ->
        validated

      {:error, %NimbleOptions.ValidationError{} = err} ->
        raise Pkcs11ex.Error,
          reason: :invalid_config,
          path: err.keys_path,
          context: %{message: Exception.message(err)}
    end
  end

  # ---------- Defaults that depend on other fields ----------

  defp apply_runtime_defaults(opts) do
    slots =
      opts
      |> Keyword.fetch!(:slots)
      |> Enum.map(fn {ref, slot} -> {ref, default_lazy(slot)} end)

    Keyword.put(opts, :slots, slots)
  end

  defp default_lazy(slot) do
    case slot[:lazy] do
      nil -> Keyword.put(slot, :lazy, slot[:type] == :token)
      _ -> slot
    end
  end

  # ---------- Stage 2: cross-field invariants (api.md §1.5) ----------

  defp validate_invariants!(opts, check_files?) do
    opts
    |> check_allowed_algs_non_empty!()
    |> check_default_slot_exists!()
    |> check_token_slots_have_pin_callback!()
    |> check_cloud_hsm_slots_lack_pin_callback!()
    |> check_keys_have_label_or_id!()
    |> check_keys_cert_label_xor_id!()
    |> check_per_slot_allowed_algs_intersection!()
    |> check_unique_driver_configs!()
    |> check_session_pool_size_slot_type!()
    |> maybe_check_drivers_exist!(check_files?)
    |> maybe_check_driver_pins!(check_files?)
  end

  # Rule 1
  defp check_allowed_algs_non_empty!(opts) do
    case opts[:allowed_algs] do
      [] -> raise_config_error([:allowed_algs], ":allowed_algs must be non-empty")
      _ -> opts
    end
  end

  # Rule 3
  defp check_default_slot_exists!(opts) do
    case opts[:default_slot] do
      nil ->
        opts

      ref ->
        if Keyword.has_key?(opts[:slots], ref) do
          opts
        else
          raise_config_error(
            [:default_slot],
            ":default_slot #{inspect(ref)} is not defined in :slots"
          )
        end
    end
  end

  # Rule 4
  defp check_token_slots_have_pin_callback!(opts) do
    Enum.each(opts[:slots], fn {ref, slot} ->
      if slot[:type] == :token and is_nil(slot[:pin_callback]) do
        raise_config_error(
          [:slots, ref, :pin_callback],
          ":pin_callback is required for slot type :token"
        )
      end
    end)

    opts
  end

  # Rule 5
  defp check_cloud_hsm_slots_lack_pin_callback!(opts) do
    Enum.each(opts[:slots], fn {ref, slot} ->
      if slot[:type] == :cloud_hsm and not is_nil(slot[:pin_callback]) do
        raise_config_error(
          [:slots, ref, :pin_callback],
          ":pin_callback is forbidden for slot type :cloud_hsm"
        )
      end
    end)

    opts
  end

  # Rule 8
  defp check_keys_have_label_or_id!(opts) do
    for {slot_ref, slot} <- opts[:slots], {key_ref, key} <- slot[:keys] do
      if is_nil(key[:label]) and is_nil(key[:id]) do
        raise_config_error(
          [:slots, slot_ref, :keys, key_ref],
          "key must specify at least one of :label or :id"
        )
      end
    end

    opts
  end

  # Rule 9
  defp check_keys_cert_label_xor_id!(opts) do
    for {slot_ref, slot} <- opts[:slots], {key_ref, key} <- slot[:keys] do
      if not is_nil(key[:cert_label]) and not is_nil(key[:cert_id]) do
        raise_config_error(
          [:slots, slot_ref, :keys, key_ref],
          "key cannot specify both :cert_label and :cert_id"
        )
      end
    end

    opts
  end

  # Rule 10
  defp check_per_slot_allowed_algs_intersection!(opts) do
    global = MapSet.new(opts[:allowed_algs])

    Enum.each(opts[:slots], fn {ref, slot} ->
      case slot[:allowed_algs] do
        nil ->
          :ok

        list ->
          if MapSet.disjoint?(global, MapSet.new(list)) do
            raise_config_error(
              [:slots, ref, :allowed_algs],
              "per-slot :allowed_algs has empty intersection with global allowlist"
            )
          end
      end
    end)

    opts
  end

  # Rule 12: session_pool_size > 1 is only valid for cloud_hsm and soft_hsm.
  # Token slots tie login state to a single session — pooling silently
  # breaks PIN-protected access.
  defp check_session_pool_size_slot_type!(opts) do
    Enum.each(opts[:slots], fn {ref, slot} ->
      case slot[:session_pool_size] do
        n when is_integer(n) and n > 1 ->
          if slot[:type] not in [:cloud_hsm, :soft_hsm] do
            raise_config_error(
              [:slots, ref, :session_pool_size],
              ":session_pool_size > 1 requires :type :cloud_hsm or :soft_hsm; " <>
                "got :type #{inspect(slot[:type])}"
            )
          end

        _ ->
          :ok
      end
    end)

    opts
  end

  # Rule 11
  defp check_unique_driver_configs!(opts) do
    opts[:slots]
    |> Enum.group_by(fn {_ref, slot} -> slot[:driver] end)
    |> Enum.each(fn {driver, entries} ->
      configs = entries |> Enum.map(fn {_ref, slot} -> slot[:driver_config] end) |> Enum.uniq()

      if length(configs) > 1 do
        offenders = Enum.map(entries, fn {ref, _slot} -> ref end)

        raise_config_error(
          [:slots],
          "slots #{inspect(offenders)} share driver #{inspect(driver)} but supply " <>
            "different :driver_config; PKCS#11 modules are loaded once per .so per process"
        )
      end
    end)

    opts
  end

  # Rule 6
  defp maybe_check_drivers_exist!(opts, false), do: opts

  defp maybe_check_drivers_exist!(opts, true) do
    Enum.each(opts[:slots], fn {ref, slot} ->
      driver = slot[:driver]

      unless File.regular?(driver) do
        raise_config_error(
          [:slots, ref, :driver],
          "driver path #{inspect(driver)} does not exist"
        )
      end
    end)

    opts
  end

  # Rule 7
  defp maybe_check_driver_pins!(opts, false), do: opts

  defp maybe_check_driver_pins!(opts, true) do
    Enum.each(opts[:driver_pins], fn {path, expected} ->
      actual = path |> File.read!() |> sha256_hex()
      expected_lower = String.downcase(expected)

      if actual != expected_lower do
        raise Pkcs11ex.Error,
          reason: {:driver_pin_mismatch, path},
          path: [:driver_pins, path],
          context: %{
            message: "driver SHA-256 mismatch for #{path}",
            expected: expected_lower,
            got: actual
          }
      end
    end)

    opts
  end

  # ---------- Helpers ----------

  defp sha256_hex(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp raise_config_error(path, message) do
    raise Pkcs11ex.Error, reason: :invalid_config, path: path, context: %{message: message}
  end

  defp to_struct(opts), do: struct(__MODULE__, opts)
end
