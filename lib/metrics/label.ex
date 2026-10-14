defmodule Sovite.Metrics.Label do
  @moduledoc false

  @doc "Converts a metadata value to a label value."
  @spec value(term()) :: String.t()
  def value(value) when is_binary(value) do
    if String.valid?(value), do: value, else: inspect(value)
  end

  def value(nil), do: ""
  def value(value) when is_atom(value), do: Atom.to_string(value)
  def value(value) when is_integer(value), do: Integer.to_string(value)

  def value(value) when is_tuple(value) do
    if :inet.is_ip_address(value), do: List.to_string(:inet.ntoa(value)), else: inspect(value)
  end

  def value(value), do: inspect(value)
end
