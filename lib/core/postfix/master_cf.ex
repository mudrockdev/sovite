defmodule Sovite.Core.Postfix.MasterCf do
  @moduledoc """
  Reads Postfix's `master.cf`, for `Sovite.Core.Postfix.Migration`.

  Each logical line (see `Sovite.Core.Postfix.MainCf.logical_lines/1`)
  is a service: name, type, private, unpriv, chroot, wakeup, maxproc,
  and the command with its arguments. Arguments are separated by
  whitespace; `{ ... }` groups one argument that contains whitespace.
  `-o name=value` and `-o { name = value }` override a `main.cf`
  parameter for the service.
  """

  alias Sovite.Core.Postfix.MainCf

  @type service :: %{
          name: String.t(),
          type: String.t(),
          private: String.t(),
          unpriv: String.t(),
          chroot: String.t(),
          wakeup: String.t(),
          maxproc: String.t(),
          command: String.t(),
          args: [String.t()],
          options: [{String.t(), String.t()}],
          line: pos_integer()
        }

  # Port numbers of the service names inet services use.
  @ports %{
    "smtp" => 25,
    "submission" => 587,
    "smtps" => 465,
    "submissions" => 465,
    "lmtp" => 24,
    "qmtp" => 209
  }

  @doc "Parses `contents` into services, in file order. Malformed lines are skipped."
  @spec parse(String.t()) :: [service()]
  def parse(contents) do
    for {number, line} <- MainCf.logical_lines(contents),
        service = service(tokens(line), number),
        service != nil,
        do: service
  end

  defp service([name, type, private, unpriv, chroot, wakeup, maxproc, command | args], number) do
    {options, args} = options(args, [], [])

    %{
      name: name,
      type: type,
      private: private,
      unpriv: unpriv,
      chroot: chroot,
      wakeup: wakeup,
      maxproc: maxproc,
      command: command,
      args: args,
      options: options,
      line: number
    }
  end

  defp service(_tokens, _number), do: nil

  defp options(["-o", option | rest], options, args),
    do: options(rest, [option(option) | options], args)

  defp options(["-o" <> option | rest], options, args) when option != "",
    do: options(rest, [option(option) | options], args)

  defp options([arg | rest], options, args),
    do: options(rest, options, [MainCf.ungroup(arg) | args])

  defp options([], options, args), do: {Enum.reverse(options), Enum.reverse(args)}

  defp option(text) do
    case String.split(MainCf.ungroup(text), "=", parts: 2) do
      [name, value] -> {String.trim(name), String.trim(value)}
      [name] -> {String.trim(name), ""}
    end
  end

  @doc """
  Splits a line into whitespace-separated tokens, keeping `{ ... }`
  groups whole.

      iex> Sovite.Core.Postfix.MasterCf.tokens("a  -o { x = 1 } b")
      ["a", "-o", "{ x = 1 }", "b"]
  """
  @spec tokens(String.t()) :: [String.t()]
  def tokens(line) do
    {tokens, current, _depth} =
      line
      |> String.graphemes()
      |> Enum.reduce({[], "", 0}, fn
        "{", {tokens, current, depth} -> {tokens, current <> "{", depth + 1}
        "}", {tokens, current, depth} -> {tokens, current <> "}", max(depth - 1, 0)}
        char, {tokens, current, 0} when char in [" ", "\t"] -> {push(tokens, current), "", 0}
        char, {tokens, current, depth} -> {tokens, current <> char, depth}
      end)

    tokens |> push(current) |> Enum.reverse()
  end

  defp push(tokens, ""), do: tokens
  defp push(tokens, token), do: [token | tokens]

  @doc """
  The address and port of an `inet` service name: `smtp`, `587`,
  `127.0.0.1:10025`, `[::1]:25`. The host is `nil` when the service
  listens on `inet_interfaces`.

      iex> Sovite.Core.Postfix.MasterCf.inet_address("127.0.0.1:10025")
      {:ok, "127.0.0.1", 10025}
      iex> Sovite.Core.Postfix.MasterCf.inet_address("submission")
      {:ok, nil, 587}
  """
  @spec inet_address(String.t()) :: {:ok, String.t() | nil, :inet.port_number()} | :error
  def inet_address(name) do
    {host, port} =
      case Regex.run(~r/\A\[([^\]]+)\]:(.+)\z/, name) do
        [_, host, port] -> {host, port}
        nil -> split_host_port(name)
      end

    with {:ok, port} <- port(port) do
      {:ok, if(host in [nil, "", "*"], do: nil, else: host), port}
    end
  end

  defp split_host_port(name) do
    case String.split(name, ":") do
      [port] -> {nil, port}
      parts -> {parts |> Enum.drop(-1) |> Enum.join(":"), List.last(parts)}
    end
  end

  defp port(port) do
    case Integer.parse(port) do
      {number, ""} when number in 1..65_535 -> {:ok, number}
      _ -> Map.fetch(@ports, port)
    end
  end

  @doc """
  The `name=value` attributes of a `pipe` or `spawn` service, with
  `"argv"` as the list of the command and its arguments.

      iex> Sovite.Core.Postfix.MasterCf.attributes(["flags=Rq", "user=nobody", "argv=/bin/cat", "-n"])
      %{"flags" => "Rq", "user" => "nobody", "argv" => ["/bin/cat", "-n"]}
  """
  @spec attributes([String.t()]) :: %{String.t() => String.t() | [String.t()]}
  def attributes(args), do: attributes(args, %{})

  defp attributes(["argv=" <> program | rest], acc), do: Map.put(acc, "argv", [program | rest])

  defp attributes([arg | rest], acc) do
    case String.split(arg, "=", parts: 2) do
      [name, value] -> attributes(rest, Map.put(acc, name, value))
      [_flag] -> attributes(rest, acc)
    end
  end

  defp attributes([], acc), do: acc

  @doc "The value of `-o name=...` on `service`, or `nil`. The last one wins."
  @spec option(service(), String.t()) :: String.t() | nil
  def option(service, name) do
    Enum.reduce(service.options, nil, fn
      {^name, value}, _acc -> value
      _option, acc -> acc
    end)
  end
end
