defmodule Pkcs11ex.Error do
  @moduledoc """
  Library exception used for `!`-variant raises and for configuration failures
  that prevent the OTP application from starting.

  Fields:
    * `:reason` — an atom or tagged tuple from `docs/specs/api.md` §4.1.
    * `:path` — for configuration errors, the key path of the offending entry
      (e.g., `[:slots, :legal_proxy, :pin_callback]`); `nil` otherwise.
    * `:context` — extra diagnostic data; a map.
  """

  @type t :: %__MODULE__{
          reason: atom() | {atom(), term()},
          path: [atom()] | nil,
          context: map()
        }

  defexception [:reason, :path, context: %{}]

  @impl true
  def message(%__MODULE__{reason: reason, path: path, context: context}) do
    parts =
      [
        "pkcs11ex: ",
        format_reason(reason),
        format_path(path),
        format_context(context)
      ]

    IO.iodata_to_binary(parts)
  end

  defp format_reason({tag, payload}), do: "#{inspect(tag)} (#{inspect(payload)})"
  defp format_reason(reason) when is_atom(reason), do: inspect(reason)
  defp format_reason(reason), do: inspect(reason)

  defp format_path(nil), do: ""
  defp format_path([]), do: ""
  defp format_path(path) when is_list(path), do: " at " <> Enum.map_join(path, ".", &to_string/1)

  defp format_context(ctx) when ctx == %{}, do: ""

  defp format_context(ctx) when is_map(ctx) do
    case Map.get(ctx, :message) do
      nil -> " — " <> inspect(ctx)
      msg -> " — " <> msg
    end
  end
end
