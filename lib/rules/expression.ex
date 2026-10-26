defmodule Sovite.Rules.Expression do
  @moduledoc """
  Boolean expressions over symbols, for composites and conditions:

      iex> {:ok, expression} = Sovite.Rules.Expression.parse("R_SPF_FAIL & !(g:dkim | is:authenticated)")
      iex> Sovite.Rules.Expression.eval(expression, &(&1 == {:symbol, "R_SPF_FAIL"}))
      true

  A term is a symbol name (letters, digits, `_`), `g:name` (any symbol
  of the group matched), `g+:name` (any symbol of the group matched with
  a positive score), or `is:name` (a flag of the message, such as
  `is:authenticated`; the caller sets them). Terms combine with `!`, `&`,
  `|`, and parentheses; `!` binds tightest, then `&`, then `|`.
  """

  @type ref ::
          {:symbol, String.t()}
          | {:group, String.t()}
          | {:group_positive, String.t()}
          | {:flag, String.t()}
  @type t :: ref() | {:not, t()} | {:and, [t()]} | {:or, [t()]}

  @max_length 4096
  @max_depth 64

  @doc "Parses an expression."
  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse(text) when is_binary(text) and byte_size(text) > @max_length,
    do: {:error, "longer than #{@max_length} bytes"}

  def parse(text) when is_binary(text) do
    with {:ok, tokens} <- tokenize(text, []),
         {:ok, expression, []} <- disjunction(tokens, 0) do
      {:ok, expression}
    else
      {:ok, _expression, [token | _]} -> {:error, "unexpected #{describe(token)}"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Evaluates an expression with `matched?`, which tells whether a term holds."
  @spec eval(t(), (ref() -> boolean())) :: boolean()
  def eval({:not, expression}, matched?), do: not eval(expression, matched?)
  def eval({:and, expressions}, matched?), do: Enum.all?(expressions, &eval(&1, matched?))
  def eval({:or, expressions}, matched?), do: Enum.any?(expressions, &eval(&1, matched?))
  def eval(ref, matched?), do: matched?.(ref)

  @doc "Every term of an expression, in order."
  @spec refs(t()) :: [ref()]
  def refs({:not, expression}), do: refs(expression)
  def refs({op, expressions}) when op in [:and, :or], do: Enum.flat_map(expressions, &refs/1)
  def refs(ref), do: [ref]

  @doc "The symbols an expression names outside a negation."
  @spec positive_symbols(t()) :: [String.t()]
  def positive_symbols({:not, _expression}), do: []

  def positive_symbols({op, expressions}) when op in [:and, :or],
    do: Enum.flat_map(expressions, &positive_symbols/1)

  def positive_symbols({:symbol, name}), do: [name]
  def positive_symbols(_ref), do: []

  defp tokenize(<<c, rest::binary>>, acc) when c in [?\s, ?\t, ?\r, ?\n], do: tokenize(rest, acc)

  defp tokenize(<<c, rest::binary>>, acc) when c in [?!, ?&, ?|, ?(, ?)],
    do: tokenize(rest, [c | acc])

  defp tokenize("", acc), do: {:ok, Enum.reverse(acc)}

  defp tokenize(text, acc) do
    case Regex.run(~r/\A(?:(g\+?|is):)?([A-Za-z0-9_]+)/, text) do
      [whole, prefix, name] ->
        rest = binary_part(text, byte_size(whole), byte_size(text) - byte_size(whole))
        tokenize(rest, [ref(prefix, name) | acc])

      nil ->
        {:error, "unexpected #{inspect(String.first(text))}"}
    end
  end

  defp ref("", name), do: {:symbol, name}
  defp ref("g", name), do: {:group, name}
  defp ref("g+", name), do: {:group_positive, name}
  defp ref("is", name), do: {:flag, name}

  defp disjunction(_tokens, depth) when depth > @max_depth,
    do: {:error, "nested deeper than #{@max_depth}"}

  defp disjunction(tokens, depth), do: chain(tokens, depth, ?|, :or, &conjunction/2)

  defp conjunction(tokens, depth), do: chain(tokens, depth, ?&, :and, &unary/2)

  defp chain(tokens, depth, operator, tag, operand) do
    with {:ok, first, rest} <- operand.(tokens, depth) do
      chain_rest(rest, depth, operator, operand, [first])
      |> case do
        {:ok, [single], rest} -> {:ok, single, rest}
        {:ok, many, rest} -> {:ok, {tag, many}, rest}
        error -> error
      end
    end
  end

  defp chain_rest([operator | tokens], depth, operator, operand, acc) do
    with {:ok, next, rest} <- operand.(tokens, depth),
         do: chain_rest(rest, depth, operator, operand, [next | acc])
  end

  defp chain_rest(tokens, _depth, _operator, _operand, acc), do: {:ok, Enum.reverse(acc), tokens}

  defp unary([?! | tokens], depth) do
    with {:ok, expression, rest} <- unary(tokens, depth + 1),
         do: {:ok, {:not, expression}, rest}
  end

  defp unary([?( | tokens], depth) do
    case disjunction(tokens, depth + 1) do
      {:ok, expression, [?) | rest]} -> {:ok, expression, rest}
      {:ok, _expression, _rest} -> {:error, "missing )"}
      error -> error
    end
  end

  defp unary([{_, _} = ref | rest], _depth), do: {:ok, ref, rest}
  defp unary([token | _], _depth), do: {:error, "unexpected #{describe(token)}"}
  defp unary([], _depth), do: {:error, "unexpected end"}

  defp describe({_, name}), do: name
  defp describe(c), do: <<?", c, ?">>
end
