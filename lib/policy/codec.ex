defmodule Sovite.Policy.Codec do
  @moduledoc false
  # Reads attribute blocks incrementally, for the client and the server:
  # feed it data as it arrives, get a block when its empty line is in.

  defstruct buffer: "", attrs: %{}, count: 0, size: 0

  @type t :: %__MODULE__{
          buffer: binary(),
          attrs: %{optional(String.t()) => String.t()},
          count: non_neg_integer(),
          size: non_neg_integer()
        }

  @type limits :: %{
          max_line: pos_integer() | :infinity,
          max_attributes: pos_integer() | :infinity,
          max_size: pos_integer() | :infinity
        }

  @type error :: :malformed | :line_too_long | :too_many_attributes | :too_large

  @name ~r/\A[A-Za-z0-9_][A-Za-z0-9_.\-]*\z/

  @spec new() :: t()
  def new, do: %__MODULE__{}

  @spec valid_name?(String.t()) :: boolean()
  def valid_name?(name), do: Regex.match?(@name, name)

  # What is left after the last block read.
  @spec buffer(t()) :: binary()
  def buffer(%__MODULE__{buffer: buffer}), do: buffer

  # `max_line` counts the bytes of a line without its newline, and
  # `max_size` those of the attribute lines of a block.
  @spec read(t(), binary(), limits()) ::
          {:ok, %{optional(String.t()) => String.t()}, t()} | {:more, t()} | {:error, error()}
  def read(%__MODULE__{} = reader, data, limits) do
    lines(%{reader | buffer: reader.buffer <> data}, limits)
  end

  defp lines(reader, limits) do
    case :binary.split(reader.buffer, "\n") do
      [line, rest] ->
        line = trim_cr(line)

        cond do
          line == "" -> {:ok, reader.attrs, %__MODULE__{buffer: rest}}
          over?(byte_size(line), limits.max_line) -> {:error, :line_too_long}
          true -> attribute(line, %{reader | buffer: rest}, limits)
        end

      [partial] ->
        cond do
          over?(byte_size(partial), limits.max_line) -> {:error, :line_too_long}
          over?(reader.size + byte_size(partial), limits.max_size) -> {:error, :too_large}
          true -> {:more, reader}
        end
    end
  end

  defp attribute(line, reader, limits) do
    size = reader.size + byte_size(line) + 1

    with [name, value] <- :binary.split(line, "="),
         true <- valid_name?(name) do
      cond do
        over?(reader.count + 1, limits.max_attributes) ->
          {:error, :too_many_attributes}

        over?(size, limits.max_size) ->
          {:error, :too_large}

        true ->
          attrs = Map.put(reader.attrs, name, value)
          lines(%{reader | attrs: attrs, count: reader.count + 1, size: size}, limits)
      end
    else
      _ -> {:error, :malformed}
    end
  end

  defp trim_cr(line) do
    case byte_size(line) do
      0 -> line
      n -> if :binary.last(line) == ?\r, do: binary_part(line, 0, n - 1), else: line
    end
  end

  defp over?(_value, :infinity), do: false
  defp over?(value, limit), do: value > limit
end
