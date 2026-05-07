defmodule Pkcs11ex.PIN do
  @moduledoc """
  PIN-handling helpers.

  See `docs/specs/specs.md` §5.2 for the layered PIN model. The library's
  primary API for PIN material is the per-slot `:pin_callback` config; this
  module provides convenience helpers for one-shot scripts and tests where
  registering a callback is overkill.
  """

  @doc """
  Run `fun` with a slot logged in via `pin`, then log out.

  Useful for scripts and tests where a registered `:pin_callback` isn't
  appropriate. The PIN binary is passed once into `Pkcs11ex.Slot.login/2`,
  which immediately forwards it to the NIF; it's not retained in any
  GenServer state.

      Pkcs11ex.PIN.with_pin(:legal_proxy, System.get_env("TOKEN_PIN"), fn ->
        {:ok, jws} = SignCore.JWS.sign(payload,
          # ... slot-aware sign opts (Phase 2 step 3 will route via :signer)
        )
      end)

  Always logs out afterwards, even if `fun` raises.
  """
  @spec with_pin(atom(), binary(), (-> result)) :: result | {:error, term()}
        when result: any()
  def with_pin(slot_ref, pin, fun) when is_binary(pin) and is_function(fun, 0) do
    case Pkcs11ex.Slot.login(slot_ref, pin) do
      :ok ->
        try do
          fun.()
        after
          _ = Pkcs11ex.Slot.logout(slot_ref)
        end

      {:error, _} = err ->
        err
    end
  end
end
