defmodule Pkcs11ex.SlotSupervisor do
  @moduledoc false

  use Supervisor

  alias Pkcs11ex.Native
  alias Pkcs11ex.Slot

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    config = Pkcs11ex.Application.config()

    # PKCS#11 modules: one `C_Initialize` per process per `.so`. Load each
    # unique driver once here and share the resulting Module ResourceArc
    # across every Slot.Server that needs it. Keeping the modules stored on
    # the supervisor's process dictionary (or :persistent_term) is fine for
    # the supervisor's lifetime — the supervisor itself outlives all child
    # slot servers, so the resources stay alive.
    modules =
      config.slots
      |> driver_configs()
      |> Enum.into(%{}, fn {driver, driver_config} ->
        if driver_config, do: apply_driver_config_env(driver, driver_config)
        {:ok, mod} = load_module(driver, config.driver_pins)
        {driver, mod}
      end)

    :persistent_term.put({__MODULE__, :modules}, modules)

    slot_children =
      Enum.flat_map(config.slots, fn {ref, slot_config} ->
        module = Map.fetch!(modules, slot_config[:driver])
        size = slot_config[:session_pool_size] || 1

        Pkcs11ex.Slot.Pool.register(ref, size)

        for idx <- 1..size do
          Supervisor.child_spec(
            {Slot.Server,
             slot_ref: ref,
             worker_index: idx,
             slot_config: slot_config,
             driver_pins: config.driver_pins,
             module: module},
            id: {Slot.Server, ref, idx}
          )
        end
      end)

    Supervisor.init(slot_children, strategy: :one_for_one)
  end

  @doc "Returns the loaded Module resource for `driver_path`, or nil."
  @spec module_for(String.t()) :: term() | nil
  def module_for(driver_path) do
    Map.get(:persistent_term.get({__MODULE__, :modules}, %{}), driver_path)
  end

  defp load_module(driver, driver_pins) do
    case Map.get(driver_pins, driver) do
      nil -> Native.module_load(driver)
      sha256_hex -> Native.module_load_pinned(driver, sha256_hex)
    end
  end

  # Per-driver `:driver_config`. Config validation (Pkcs11ex.Config rule 11)
  # guarantees at most one `:driver_config` per driver path.
  defp driver_configs(slots) do
    slots
    |> Enum.reduce(%{}, fn {_ref, slot_config}, acc ->
      Map.put_new(acc, slot_config[:driver], slot_config[:driver_config])
    end)
    |> Enum.to_list()
  end

  # Vendor-specific config-file passthrough at module load time.
  #
  # libkmsp11 (GCP Cloud HSM PKCS#11 provider) reads `KMS_PKCS11_CONFIG`
  # from the process env. Other PKCS#11 modules either don't need a config
  # file or use their own conventions; we only set this env var when the
  # driver path looks like libkmsp11 to avoid polluting unrelated drivers.
  #
  # The cleaner alternative is `CK_C_INITIALIZE_ARGS.pReserved`, but cryptoki
  # exposes that as an unsafe API. The env-var path is process-wide but
  # that's fine because §1.5 rule 11 of the config schema forbids two slots
  # sharing the same `.so` with different `:driver_config` values.
  defp apply_driver_config_env(driver, driver_config) do
    cond do
      String.contains?(driver, "kmsp11") ->
        System.put_env("KMS_PKCS11_CONFIG", driver_config)

      true ->
        # Drivers that read a different env var or a fixed-path config
        # can be added here as we encounter them.
        :ok
    end
  end
end
