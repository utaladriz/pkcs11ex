defmodule Pkcs11ex.Application do
  @moduledoc false

  use Application

  @persistent_term_key __MODULE__

  @impl true
  def start(_type, _args) do
    check_files? = Application.get_env(:pkcs11ex, :check_files, true)
    config = Pkcs11ex.Config.load!(check_files: check_files?)
    :persistent_term.put(@persistent_term_key, config)

    children = [
      # PinnedRegistry is started unconditionally (lightweight: one GenServer +
      # one ETS table). Deployments that use a different :trust_policy can
      # leave it idle; deployments that swap in/out at runtime get it for free.
      Pkcs11ex.Policy.PinnedRegistry
      # Phase 1 will add:
      #   - Pkcs11ex.SlotSupervisor (per-slot session pools)
    ]

    opts = [strategy: :one_for_one, name: Pkcs11ex.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @doc """
  Returns the validated configuration set during application boot.
  """
  @spec config() :: Pkcs11ex.Config.t()
  def config, do: :persistent_term.get(@persistent_term_key)
end
