defmodule Sovite.SPF.Record do
  @moduledoc """
  Parses SPF records (RFC 7208 §4.5, §12).

      iex> Sovite.SPF.Record.parse("v=spf1 ip4:192.0.2.0/24 -all")
      {:ok, [{:pass, {:ip4, {192, 0, 2, 0}, 24}, "ip4:192.0.2.0/24"}, {:fail, :all, "-all"}]}

  The whole record is parsed before it is evaluated, so a syntax error
  anywhere makes it unusable, as the RFC requires. Mechanism and
  modifier names are matched against fixed tables, so a record never
  creates atoms.

  A record parses to a list of terms in record order:

    * directives, `{qualifier, mechanism, text}`, where `text` is the
      term as written;
    * `{:redirect, domain_spec}` and `{:exp, domain_spec}` modifiers.

  Unknown modifiers are checked for syntax and then left out.
  """

  alias Sovite.SPF.Macro

  @typedoc "What a matching directive returns."
  @type qualifier :: :pass | :fail | :softfail | :neutral

  @typedoc "IPv4 and IPv6 prefix lengths for `a` and `mx`."
  @type cidr :: {0..32, 0..128}

  @type mechanism ::
          :all
          | {:include, Macro.t()}
          | {:a, Macro.t() | nil, cidr()}
          | {:mx, Macro.t() | nil, cidr()}
          | {:ptr, Macro.t() | nil}
          | {:ip4, :inet.ip4_address(), 0..32}
          | {:ip6, :inet.ip6_address(), 0..128}
          | {:exists, Macro.t()}

  @type directive :: {qualifier(), mechanism(), String.t()}
  @type modifier :: {:redirect, Macro.t()} | {:exp, Macro.t()}
  @type spf_term :: directive() | modifier()

  @qualifiers %{?+ => :pass, ?- => :fail, ?~ => :softfail, ?? => :neutral}

  @mechanisms %{
    "all" => :all,
    "include" => :include,
    "a" => :a,
    "mx" => :mx,
    "ptr" => :ptr,
    "ip4" => :ip4,
    "ip6" => :ip6,
    "exists" => :exists
  }

  @doc """
  Returns `true` if the TXT record `text` is an SPF record: it starts
  with `v=spf1`, followed by a space or nothing (RFC 7208 §4.5).

      iex> Sovite.SPF.Record.spf?("v=spf1 -all")
      true
      iex> Sovite.SPF.Record.spf?("v=spf10")
      false
  """
  @spec spf?(String.t()) :: boolean()
  def spf?(<<version::binary-size(6)>>), do: String.downcase(version) == "v=spf1"
  def spf?(<<version::binary-size(6), " ", _::binary>>), do: String.downcase(version) == "v=spf1"
  def spf?(_text), do: false

  @doc """
  Parses an SPF record into its terms.

      iex> Sovite.SPF.Record.parse("v=spf1 a:%{d}/24//64 redirect=_spf.example.com")
      {:ok,
       [
         {:pass, {:a, [{:macro, :d, nil, false, [], false}], {24, 64}}, "a:%{d}/24//64"},
         {:redirect, ["_spf.example.com"]}
       ]}
      iex> Sovite.SPF.Record.parse("v=spf1 ip4:192.0.2.1/33")
      {:error, ~s(invalid term "ip4:192.0.2.1/33")}
  """
  @spec parse(String.t()) :: {:ok, [spf_term()]} | {:error, String.t()}
  def parse(record) when is_binary(record) do
    if spf?(record) do
      <<_version::binary-size(6), rest::binary>> = record

      rest
      |> String.split(" ", trim: true)
      |> parse_terms([])
    else
      {:error, "not an SPF record"}
    end
  end

  defp parse_terms([], terms) do
    terms = Enum.reverse(terms)

    cond do
      Enum.count(terms, &match?({:redirect, _}, &1)) > 1 ->
        {:error, "duplicate redirect modifier"}

      Enum.count(terms, &match?({:exp, _}, &1)) > 1 ->
        {:error, "duplicate exp modifier"}

      true ->
        {:ok, terms}
    end
  end

  defp parse_terms([text | rest], terms) do
    case parse_term(text) do
      {:ok, :ignore} -> parse_terms(rest, terms)
      {:ok, term} -> parse_terms(rest, [term | terms])
      {:error, _} = error -> error
    end
  end

  defp parse_term(text) do
    case Regex.run(~r/\A([a-z][a-z0-9_.\-]*)=(.*)\z/is, text, capture: :all_but_first) do
      [name, value] -> parse_modifier(String.downcase(name), value, text)
      nil -> parse_directive(text)
    end
  end

  defp parse_modifier(name, value, text) when name in ["redirect", "exp"] do
    case Macro.parse(value, :domain_spec) do
      {:ok, spec} -> {:ok, {%{"redirect" => :redirect, "exp" => :exp}[name], spec}}
      {:error, _} -> invalid(text)
    end
  end

  defp parse_modifier(_name, value, text) do
    case Macro.parse(value, :macro_string) do
      {:ok, _} -> {:ok, :ignore}
      {:error, _} -> invalid(text)
    end
  end

  defp parse_directive(text) do
    {qualifier, rest} =
      case text do
        <<char, rest::binary>> when is_map_key(@qualifiers, char) -> {@qualifiers[char], rest}
        _ -> {:pass, text}
      end

    with [name, args] <- Regex.run(~r/\A([a-z][a-z0-9]*)(.*)\z/is, rest, capture: :all_but_first),
         {:ok, type} <- mechanism_type(name, text),
         {:ok, mechanism} <- mechanism(type, args) do
      {:ok, {qualifier, mechanism, text}}
    else
      {:error, _} = error -> error
      _ -> invalid(text)
    end
  end

  defp mechanism_type(name, text) do
    case Map.fetch(@mechanisms, String.downcase(name)) do
      {:ok, type} -> {:ok, type}
      :error -> {:error, "unknown mechanism #{inspect(text)}"}
    end
  end

  defp mechanism(:all, ""), do: {:ok, :all}
  defp mechanism(:include, ":" <> spec), do: with_spec(spec, &{:include, &1})
  defp mechanism(:exists, ":" <> spec), do: with_spec(spec, &{:exists, &1})
  defp mechanism(:ptr, ""), do: {:ok, {:ptr, nil}}
  defp mechanism(:ptr, ":" <> spec), do: with_spec(spec, &{:ptr, &1})
  defp mechanism(:ip4, ":" <> network), do: network(network, 4, 32)
  defp mechanism(:ip6, ":" <> network), do: network(network, 8, 128)

  defp mechanism(type, args) when type in [:a, :mx] do
    # The domain-spec may itself contain "/", so the CIDR lengths are
    # matched at the end.
    with [spec, ip4, ip6] <-
           Regex.run(~r/\A(?::(.+?))?(?:\/([0-9]+))?(?:\/\/([0-9]+))?\z/s, args,
             capture: :all_but_first
           )
           |> pad(3),
         {:ok, ip4} <- prefix(ip4, 32),
         {:ok, ip6} <- prefix(ip6, 128),
         {:ok, spec} <- optional_spec(spec) do
      {:ok, {type, spec, {ip4, ip6}}}
    end
  end

  defp mechanism(_type, _args), do: :error

  defp pad(nil, _count), do: :error
  defp pad(captures, count), do: captures ++ List.duplicate("", count - length(captures))

  defp with_spec(spec, fun) do
    case Macro.parse(spec, :domain_spec) do
      {:ok, spec} -> {:ok, fun.(spec)}
      {:error, _} -> :error
    end
  end

  defp optional_spec(""), do: {:ok, nil}
  defp optional_spec(spec), do: with_spec(spec, & &1)

  defp network(network, size, bits) do
    with {address, length} <- split_length(network),
         {:ok, ip} when tuple_size(ip) == size <- Sovite.Net.parse_ip(address),
         {:ok, length} <- prefix(length, bits) do
      {:ok, {if(size == 4, do: :ip4, else: :ip6), ip, length}}
    else
      _ -> :error
    end
  end

  defp split_length(network) do
    case String.split(network, "/") do
      [address] -> {address, ""}
      [address, length] when length != "" -> {address, length}
      _ -> :error
    end
  end

  # ip4-cidr-length = "/" ( "0" / %x31-39 0*1DIGIT ), at most 32; IPv6
  # likewise up to 128. An empty length is the full address.
  defp prefix("", bits), do: {:ok, bits}

  defp prefix(digits, bits) do
    with true <- String.match?(digits, ~r/\A(0|[1-9][0-9]{0,2})\z/),
         length when length <= bits <- String.to_integer(digits) do
      {:ok, length}
    else
      _ -> :error
    end
  end

  defp invalid(text), do: {:error, "invalid term #{inspect(text)}"}
end
