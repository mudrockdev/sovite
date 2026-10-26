defmodule Sovite.Rules.Pattern do
  @moduledoc """
  Regular expressions for rules, matched with hard limits, so a pattern
  that backtracks badly (`(a+)+$`) gives up instead of stalling a scan.

      iex> {:ok, pattern} = Sovite.Rules.Pattern.compile("viagra|cialis", "i")
      iex> Sovite.Rules.Pattern.run(pattern, "Cheap VIAGRA here")
      {:match, "VIAGRA"}

  Patterns are PCRE (as `Regex`), matched on UTF-8 with Unicode
  character classes. Flags: `i` (case-insensitive), `m` (`^` and `$` at
  line ends), `s` (`.` matches newlines), and `x` (white space and
  comments in the pattern ignored).
  """

  defstruct [:source, :flags, :compiled]

  @opaque t :: %__MODULE__{source: String.t(), flags: String.t(), compiled: term()}

  @max_source 4096
  @flags %{?i => :caseless, ?m => :multiline, ?s => :dotall, ?x => :extended}

  # How much work one match may do: calls of PCRE's matching function, and
  # how deep it may backtrack. A plain pattern needs a few per byte of
  # subject; a pattern that backtracks without bound reaches them in
  # milliseconds.
  @match_limit 1_000_000
  @depth_limit 10_000

  @doc "Compiles a pattern with `flags` (a string of flag letters)."
  @spec compile(String.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def compile(source, flags \\ "")

  def compile(source, _flags) when byte_size(source) > @max_source,
    do: {:error, "longer than #{@max_source} bytes"}

  def compile(source, flags) when is_binary(source) and is_binary(flags) do
    with {:ok, options} <- options(flags),
         true <- String.valid?(source) || {:error, "not UTF-8"},
         {:ok, compiled} <- re_compile(source, options) do
      {:ok, %__MODULE__{source: source, flags: flags, compiled: compiled}}
    end
  end

  defp options(flags) do
    flags
    |> String.to_charlist()
    |> Enum.reduce_while({:ok, [:unicode, :ucp]}, fn flag, {:ok, acc} ->
      case Map.fetch(@flags, flag) do
        {:ok, option} -> {:cont, {:ok, [option | acc]}}
        :error -> {:halt, {:error, "unknown flag #{inspect(<<flag::utf8>>)}"}}
      end
    end)
  end

  defp re_compile(source, options) do
    case :re.compile(source, options) do
      {:ok, compiled} -> {:ok, compiled}
      {:error, {reason, at}} -> {:error, "#{reason} at #{at}"}
    end
  end

  @doc """
  Matches `subject` (UTF-8): the first match, `:nomatch`, or `:limit`
  when the match took more work than the limits allow.
  """
  @spec run(t(), String.t()) :: {:match, String.t()} | :nomatch | :limit
  def run(%__MODULE__{compiled: compiled}, subject) when is_binary(subject) do
    options = [
      {:match_limit, @match_limit},
      {:match_limit_recursion, @depth_limit},
      :report_errors,
      {:capture, :first, :binary}
    ]

    case :re.run(subject, compiled, options) do
      {:match, [match]} -> {:match, match}
      :nomatch -> :nomatch
      {:error, _limit} -> :limit
    end
  end

  @doc "The pattern's source."
  @spec source(t()) :: String.t()
  def source(%__MODULE__{source: source}), do: source
end
