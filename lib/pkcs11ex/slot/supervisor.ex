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
      |> Enum.map(fn {_ref, slot_config} -> slot_config[:driver] end)
      |> Enum.uniq()
      |> Enum.into(%{}, fn driver ->
        {:ok, mod} = load_module(driver, config.driver_pins)
        {driver, mod}
      end)

    :persistent_term.put({__MODULE__, :modules}, modules)

    slot_children =
      Enum.map(config.slots, fn {ref, slot_config} ->
        module = Map.fetch!(modules, slot_config[:driver])

        Supervisor.child_spec(
          {Slot.Server, slot_ref: ref, slot_config: slot_config, driver_pins: config.driver_pins, module: module},
          id: {Slot.Server, ref}
        )
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
end
