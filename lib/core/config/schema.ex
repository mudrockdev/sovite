defmodule Sovite.Core.Config.Schema do
  @moduledoc false
  # Validates decoded TOML (string-keyed maps) against a schema and returns
  # atom-keyed maps. Atoms come from the schema only, never from the input.
  #
  # A schema is a list of fields: {key :: atom, type, opts}
  #
  # Types:
  #   :string | :boolean | :hostname | :absolute_path
  #   :file_name               - a single path component, no "/"
  #   :file_name_pattern       - a file name with one "{n}" and optional "{date}"
  #   :strftime                - a Calendar.strftime/2 format
  #   :byte_size               - bytes as an integer or "512K", "100M", "1G"
  #   :duration                - milliseconds, from seconds or "500ms", "30s", "5m", "1h", "1d"
  #   :domain | :mailbox       - validated and lower-cased
  #   :ip_address              - an :inet tuple
  #   :mx_pattern              - a host name or "*." and a host name, lower-cased (MTA-STS)
  #   :cidr                    - {ip, prefix_length}, from "192.0.2.0/24" or a single address
  #   :relayhost               - %{host, port, mx}, from "host", "host:port", "[host]", "[host]:port"
  #   :tls_version             - :"tlsv1.2" | :"tlsv1.3", from "1.2" or "1.3"
  #   :ciphers                 - a list of strong cipher suite names, see Sovite.TLS.ciphers/1
  #   :ldap_filter             - an RFC 4515 filter with %u/%n/%d placeholders
  #   :url                     - an absolute URL; with {:url, schemes} the scheme must be listed
  #   :sender_pattern          - an address, "@domain", or "*"
  #   :tls_destination         - a domain or an address literal ("[192.0.2.1]"), lower-cased
  #   :restriction             - a check name, see Sovite.Core.Restrictions
  #   :transport               - a Sovite.Core.Transport map, from "smtp", "lmtp:unix:/path", ...
  #   :content_filter          - "" (none) or an smtp/lmtp transport with a next hop, kept as text
  #   :milter_address          - %{text, address}, from "inet:host:port", "inet:port@host", "unix:/path"
  #   :delimiter               - address extension delimiter characters, such as "+" or "+-"
  #   :hide_subdomain          - a domain, or "!domain" for an exception
  #   :maildir_template        - an absolute path with {user}, {domain}, {address} placeholders
  #   :pipe_name               - letters, digits, "_", "-"; see Sovite.Core.Transport.pipe_name?/1
  #   :env_name                - an environment variable name
  #   :command                 - a non-empty array of strings, the first an absolute path
  #   :header_name             - a header field name, lower-cased
  #   :dkim_selector           - a DKIM selector: one or more DNS labels
  #   :rate                    - {count, window_ms}, from "100/1h"
  #   :dnsbl_code              - a DNS list reply pattern, see Sovite.Abuse.DNSBL.parse_code/1
  #   {:list, type}            - an array; errors name the index, as in "key[0]"
  #   {:map, key_type, value_type} - a table with arbitrary keys; errors name the key
  #   {:integer, min, max}
  #   {:enum, [atom]}          - the input string must equal one of the atom names
  #   {:section, [field]}      - a nested table
  #
  # Options:
  #   default: value or zero-arity function (defaults are validated too)
  #   required: true

  alias Sovite.Abuse.DNSBL
  alias Sovite.Core.Config.Error
  alias Sovite.Core.{Restrictions, SenderCheck, Transport}
  alias Sovite.LDAP.Filter
  alias Sovite.Message.Received

  @type field :: {atom(), term(), keyword()}

  @spec validate(term(), [field()], [String.t()]) :: {:ok, map()} | {:error, [Error.t()]}
  def validate(input, fields, path \\ [])

  def validate(input, fields, path) when is_map(input) do
    known = MapSet.new(fields, fn {key, _type, _opts} -> Atom.to_string(key) end)

    unknown_errors =
      for key <- input |> Map.keys() |> Enum.sort(), not MapSet.member?(known, key) do
        %Error{path: path ++ [key], reason: "unknown key"}
      end

    {values, field_errors} =
      Enum.reduce(fields, {%{}, []}, fn {key, type, opts}, {values, errors} ->
        name = Atom.to_string(key)

        case validate_field(Map.fetch(input, name), type, opts, path ++ [name]) do
          {:ok, value} -> {Map.put(values, key, value), errors}
          {:error, new_errors} -> {values, errors ++ new_errors}
        end
      end)

    case unknown_errors ++ field_errors do
      [] -> {:ok, values}
      errors -> {:error, errors}
    end
  end

  def validate(_input, _fields, path),
    do: {:error, [%Error{path: path, reason: "expected a table"}]}

  defp validate_field(:error, {:section, fields}, _opts, path), do: validate(%{}, fields, path)

  defp validate_field(:error, type, opts, path) do
    cond do
      Keyword.has_key?(opts, :default) ->
        value =
          case Keyword.fetch!(opts, :default) do
            fun when is_function(fun, 0) -> fun.()
            value -> value
          end

        with {:error, errors} <- check(type, value, path) do
          {:error, Enum.map(errors, &%{&1 | reason: &1.reason <> " (default value)"})}
        end

      Keyword.get(opts, :required, false) ->
        {:error, [%Error{path: path, reason: "is required"}]}

      true ->
        {:ok, nil}
    end
  end

  defp validate_field({:ok, value}, type, _opts, path), do: check(type, value, path)

  defp check({:section, fields}, value, path), do: validate(value, fields, path)

  defp check({:list, type}, values, path) when is_list(values) do
    values
    |> Enum.with_index()
    |> Enum.reduce({[], []}, fn {value, index}, {acc, errors} ->
      case check(type, value, path ++ ["[#{index}]"]) do
        {:ok, value} -> {[value | acc], errors}
        {:error, new_errors} -> {acc, errors ++ new_errors}
      end
    end)
    |> case do
      {acc, []} -> {:ok, Enum.reverse(acc)}
      {_acc, errors} -> {:error, errors}
    end
  end

  defp check({:list, _type}, value, path),
    do: {:error, [%Error{path: path, reason: "expected an array, got #{inspect(value)}"}]}

  defp check({:map, key_type, value_type}, map, path) when is_map(map) do
    map
    |> Enum.sort()
    |> Enum.reduce({%{}, []}, fn {key, value}, {acc, errors} ->
      with {:ok, key} <- check(key_type, key, path ++ [key]),
           {:ok, value} <- check(value_type, value, path ++ [key]) do
        {Map.put(acc, key, value), errors}
      else
        {:error, new_errors} -> {acc, errors ++ new_errors}
      end
    end)
    |> case do
      {acc, []} -> {:ok, acc}
      {_acc, errors} -> {:error, errors}
    end
  end

  defp check({:map, _key_type, _value_type}, value, path),
    do: {:error, [%Error{path: path, reason: "expected a table, got #{inspect(value)}"}]}

  defp check(type, value, path) do
    with {:error, reason} <- cast(type, value) do
      {:error, [%Error{path: path, reason: reason}]}
    end
  end

  defp cast(:string, value) when is_binary(value), do: {:ok, value}
  defp cast(:string, value), do: type_error("a string", value)

  defp cast(:boolean, value) when is_boolean(value), do: {:ok, value}
  defp cast(:boolean, value), do: type_error("true or false", value)

  defp cast({:integer, min, max}, value) when is_integer(value) and value >= min and value <= max,
    do: {:ok, value}

  defp cast({:integer, min, max}, value),
    do: type_error("an integer from #{min} to #{max}", value)

  # Defaults are written as atoms in the schema, so accept those as well.
  defp cast({:enum, allowed}, value) when is_atom(value) do
    if value in allowed, do: {:ok, value}, else: enum_error(allowed, value)
  end

  defp cast({:enum, allowed}, value) when is_binary(value) do
    case Enum.find(allowed, &(Atom.to_string(&1) == value)) do
      nil -> enum_error(allowed, value)
      atom -> {:ok, atom}
    end
  end

  defp cast({:enum, allowed}, value), do: enum_error(allowed, value)

  # Internationalized names are kept in A-labels, the form DNS uses.
  defp cast(:hostname, value) when is_binary(value) do
    hostname = ascii_name(value)

    if Sovite.Validators.hostname?(hostname),
      do: {:ok, hostname},
      else: {:error, "#{inspect(value)} is not a valid hostname"}
  end

  defp cast(:hostname, value), do: type_error("a hostname string", value)

  defp cast(:mx_pattern, value) when is_binary(value) do
    pattern = String.downcase(value, :ascii)

    host =
      case pattern do
        "*." <> host -> host
        host -> host
      end

    if Sovite.Validators.hostname?(host),
      do: {:ok, pattern},
      else: {:error, "#{inspect(value)} is not a host name or *.domain"}
  end

  defp cast(:mx_pattern, value), do: type_error("an MX host pattern", value)

  defp cast(:absolute_path, value) when is_binary(value) do
    if Path.type(value) == :absolute,
      do: {:ok, value},
      else: {:error, "#{inspect(value)} is not an absolute path"}
  end

  defp cast(:absolute_path, value), do: type_error("an absolute path", value)

  defp cast(:file_name, value) when is_binary(value) do
    if value in ["", ".", ".."] or String.contains?(value, ["/", <<0>>]),
      do: {:error, "#{inspect(value)} is not a valid file name"},
      else: {:ok, value}
  end

  defp cast(:file_name, value), do: type_error("a file name", value)

  defp cast(:file_name_pattern, value) when is_binary(value) do
    placeholders = Regex.scan(~r/\{[^}]*\}/, value) |> List.flatten()

    cond do
      match?({:error, _}, cast(:file_name, value)) ->
        {:error, "#{inspect(value)} is not a valid file name"}

      Enum.count(placeholders, &(&1 == "{n}")) != 1 ->
        {:error, "#{inspect(value)} must contain {n} exactly once"}

      unknown = Enum.find(placeholders, &(&1 not in ["{n}", "{date}"])) ->
        {:error, "#{inspect(value)} has unknown placeholder #{unknown}, expected {date} or {n}"}

      true ->
        {:ok, value}
    end
  end

  defp cast(:file_name_pattern, value), do: type_error("a file name", value)

  defp cast(:strftime, value) when is_binary(value) do
    sample = Calendar.strftime(~N[2026-12-31 23:59:59], value)

    if String.contains?(sample, ["/", <<0>>]),
      do: {:error, "#{inspect(value)} must not produce a \"/\""},
      else: {:ok, value}
  rescue
    ArgumentError -> {:error, "#{inspect(value)} is not a valid strftime format"}
  end

  defp cast(:strftime, value), do: type_error("a strftime format string", value)

  defp cast(:domain, value) when is_binary(value) do
    domain = ascii_name(value)

    if Sovite.Validators.domain?(domain),
      do: {:ok, String.downcase(domain, :ascii)},
      else: {:error, "#{inspect(value)} is not a valid domain"}
  end

  defp cast(:domain, value), do: type_error("a domain", value)

  # Lower-cased, since recipients are compared case-insensitively. The
  # local part may be internationalized (RFC 6531); the domain is kept in
  # A-labels.
  defp cast(:mailbox, value) when is_binary(value) do
    case Sovite.Validators.ascii_domain(value) do
      {:ok, mailbox} -> {:ok, String.downcase(mailbox, :ascii)}
      {:error, _} -> {:error, "#{inspect(value)} is not a valid email address"}
    end
  end

  defp cast(:mailbox, value), do: type_error("an email address", value)

  defp cast(:ip_address, value) when is_binary(value) do
    case Sovite.Net.parse_ip(value) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> {:error, "#{inspect(value)} is not a valid IP address"}
    end
  end

  defp cast(:ip_address, value), do: type_error("an IP address", value)

  defp cast(:cidr, value) when is_binary(value) do
    case Sovite.Net.parse_cidr(value) do
      {:ok, network} ->
        {:ok, network}

      {:error, :host_bits_set} ->
        {:error, "#{inspect(value)} has bits set after the prefix length"}

      {:error, _} ->
        {:error, "#{inspect(value)} is not a valid network, expected an address or CIDR"}
    end
  end

  defp cast(:cidr, value), do: type_error("a network", value)

  # Postfix syntax: "[host]" skips the MX lookup. An IP address must be in
  # brackets and is kept as an address literal ("[192.0.2.1]").
  defp cast(:relayhost, value) when is_binary(value) do
    case Transport.parse_host(value, 25) do
      {:ok, host} ->
        {:ok, host}

      :error ->
        {:error,
         "#{inspect(value)} is not a valid relay host, expected \"host\", \"[host]\", or \"[host]:port\""}
    end
  end

  defp cast(:relayhost, value), do: type_error("a relay host", value)

  defp cast(:tls_version, "1.2"), do: {:ok, :"tlsv1.2"}
  defp cast(:tls_version, "1.3"), do: {:ok, :"tlsv1.3"}

  defp cast(:tls_version, value) when is_atom(value) and value in [:"tlsv1.2", :"tlsv1.3"],
    do: {:ok, value}

  defp cast(:tls_version, value), do: type_error(~s("1.2" or "1.3"), value)

  defp cast(:ciphers, value) when is_list(value) do
    case Enum.all?(value, &is_binary/1) && Sovite.TLS.ciphers(value) do
      {:ok, _suites} ->
        {:ok, value}

      {:error, {:unknown_cipher, name}} ->
        {:error, "#{inspect(name)} is not a cipher suite this system supports"}

      {:error, {:weak_cipher, name}} ->
        {:error,
         "#{inspect(name)} is not allowed: only ECDHE with AES-GCM or ChaCha20-Poly1305, and TLS 1.3 suites"}

      false ->
        type_error("an array of cipher suite names", value)
    end
  end

  defp cast(:ciphers, value), do: type_error("an array of cipher suite names", value)

  defp cast(:ldap_filter, value) when is_binary(value) do
    case Filter.parse(value) do
      {:ok, _} -> {:ok, value}
      :error -> {:error, "#{inspect(value)} is not a valid LDAP filter"}
    end
  end

  defp cast(:ldap_filter, value), do: type_error("an LDAP filter", value)

  defp cast(:url, value), do: cast({:url, nil}, value)

  defp cast({:url, schemes}, value) when is_binary(value) do
    case URI.new(value) do
      {:ok, %URI{scheme: scheme, host: host}}
      when is_binary(scheme) and is_binary(host) and host != "" ->
        if schemes == nil or scheme in schemes,
          do: {:ok, value},
          else:
            {:error,
             "#{inspect(value)} must use #{Enum.map_join(schemes, " or ", &(&1 <> "://"))}"}

      _ ->
        {:error, "#{inspect(value)} is not a valid URL"}
    end
  end

  defp cast({:url, _schemes}, value), do: type_error("a URL", value)

  defp cast(:sender_pattern, value) when is_binary(value) do
    value = value |> ascii_pattern() |> String.downcase(:ascii)

    if SenderCheck.valid_pattern?(value),
      do: {:ok, value},
      else: {:error, ~s(#{inspect(value)} is not an address, "@domain", or "*")}
  end

  defp cast(:sender_pattern, value), do: type_error("a sender address pattern", value)

  defp cast(:tls_destination, value) when is_binary(value) do
    value = String.downcase(value, :ascii)

    case Sovite.Validators.parse_address_literal(value) do
      {:ok, ip} ->
        {:ok, Received.address_literal(ip)}

      {:error, _} when value != "" ->
        if Sovite.Validators.domain?(value),
          do: {:ok, value},
          else: {:error, "#{inspect(value)} is not a domain or address literal"}

      {:error, _} ->
        {:error, "#{inspect(value)} is not a domain or address literal"}
    end
  end

  defp cast(:restriction, value) when is_binary(value), do: Restrictions.parse(value)
  defp cast(:restriction, value), do: type_error("a restriction", value)

  defp cast(:transport, value) when is_binary(value) do
    case Transport.parse(value) do
      {:ok, %{transport: nil}} ->
        {:error, "#{inspect(value)} does not name a transport"}

      {:ok, transport} ->
        {:ok, transport}

      :error ->
        {:error,
         "#{inspect(value)} is not a valid transport, such as \"smtp\" or \"lmtp:unix:/path\""}
    end
  end

  defp cast(:transport, value), do: type_error("a transport", value)

  defp cast(:content_filter, value) when is_binary(value) do
    case String.trim(value) do
      "" ->
        {:ok, ""}

      spec ->
        case Transport.parse(spec) do
          {:ok, %{transport: transport, nexthop: nexthop}}
          when transport in [:smtp, :lmtp] and nexthop != nil ->
            {:ok, spec}

          _ ->
            {:error,
             "#{inspect(value)} is not a content filter: use an smtp or lmtp transport with a next hop, such as \"smtp:[127.0.0.1]:10024\""}
        end
    end
  end

  defp cast(:content_filter, value), do: type_error("a transport", value)

  defp cast(:milter_address, value) when is_binary(value) do
    case Sovite.Milter.parse_address(String.trim(value)) do
      {:ok, address} ->
        {:ok, %{text: String.trim(value), address: address}}

      {:error, :invalid_address} ->
        {:error,
         "#{inspect(value)} is not a milter address, such as \"inet:127.0.0.1:11332\" or \"unix:/run/milter.sock\""}
    end
  end

  defp cast(:milter_address, value), do: type_error("a milter address", value)

  defp cast(:delimiter, value) when is_binary(value) do
    if String.length(value) <= 8 and not String.match?(value, ~r/[[:alnum:]@\s"<>.]/u),
      do: {:ok, value},
      else: {:error, "#{inspect(value)} is not a valid delimiter, such as \"+\" or \"+-\""}
  end

  defp cast(:delimiter, value), do: type_error("a string of delimiter characters", value)

  defp cast(:hide_subdomain, "!" <> domain) do
    with {:ok, domain} <- cast(:domain, domain), do: {:ok, "!" <> domain}
  end

  defp cast(:hide_subdomain, value), do: cast(:domain, value)

  defp cast(:maildir_template, value) when is_binary(value) do
    unknown =
      ~r/\{[^}]*\}/
      |> Regex.scan(value)
      |> List.flatten()
      |> Enum.reject(&(&1 in ["{user}", "{domain}", "{address}"]))

    cond do
      Path.type(value) != :absolute ->
        {:error, "#{inspect(value)} is not an absolute path"}

      unknown != [] ->
        {:error, "unknown placeholder #{hd(unknown)}; use {user}, {domain}, or {address}"}

      true ->
        {:ok, value}
    end
  end

  defp cast(:maildir_template, value), do: type_error("a path template", value)

  defp cast(:pipe_name, value) do
    if Transport.pipe_name?(value),
      do: {:ok, value},
      else:
        {:error, "#{inspect(value)} is not a valid name: use letters, digits, \"_\", and \"-\""}
  end

  defp cast(:env_name, value) when is_binary(value) do
    if value =~ ~r/\A[A-Za-z_][A-Za-z0-9_]*\z/,
      do: {:ok, value},
      else: {:error, "#{inspect(value)} is not a valid environment variable name"}
  end

  defp cast(:env_name, value), do: type_error("an environment variable name", value)

  defp cast(:command, [program | _] = command) when is_binary(program) do
    cond do
      not Enum.all?(command, &is_binary/1) -> type_error("an array of strings", command)
      Path.type(program) != :absolute -> {:error, "#{inspect(program)} is not an absolute path"}
      true -> {:ok, command}
    end
  end

  defp cast(:command, value),
    do: type_error("a command: an array with a program's absolute path and its arguments", value)

  defp cast(:header_name, value) when is_binary(value) do
    if value =~ ~r/\A[\x21-\x39\x3b-\x7e]+\z/,
      do: {:ok, String.downcase(value)},
      else: {:error, "#{inspect(value)} is not a header field name"}
  end

  defp cast(:header_name, value), do: type_error("a header field name", value)

  defp cast(:dkim_selector, value) when is_binary(value) do
    if value =~
         ~r/\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z/,
       do: {:ok, value},
       else: {:error, "#{inspect(value)} is not a valid selector: use DNS labels"}
  end

  defp cast(:dkim_selector, value), do: type_error("a DKIM selector", value)

  defp cast(:rate, value) when is_binary(value) do
    with [count, window] <- String.split(value, "/", parts: 2),
         {count, ""} when count in 1..1_000_000_000 <- Integer.parse(String.trim(count)),
         {:ok, window} <- cast(:duration, window) do
      {:ok, {count, window}}
    else
      _ -> rate_error(value)
    end
  end

  defp cast(:rate, value), do: rate_error(value)

  defp cast(:dnsbl_code, value) when is_binary(value), do: DNSBL.parse_code(value)
  defp cast(:dnsbl_code, value), do: type_error(~s(a reply code like "127.0.0.[2..11]"), value)

  defp cast(:duration, value) when is_integer(value) and value > 0, do: {:ok, value * 1000}

  defp cast(:duration, value) when is_binary(value) do
    case Regex.run(~r/\A(\d{1,9})\s*(ms|s|m|h|d)\z/, String.trim(value)) do
      [_, amount, unit] when amount != "0" -> {:ok, String.to_integer(amount) * unit_ms(unit)}
      _ -> duration_error(value)
    end
  end

  defp cast(:duration, value), do: duration_error(value)

  defp cast(:byte_size, value) when is_integer(value) and value > 0, do: {:ok, value}

  defp cast(:byte_size, value) when is_binary(value) do
    case Regex.run(~r/\A(\d+)\s*([KMG]?)B?\z/i, String.trim(value)) do
      [_, digits, unit] ->
        bytes = String.to_integer(digits) * unit_size(String.upcase(unit))
        if bytes > 0, do: {:ok, bytes}, else: byte_size_error(value)

      _ ->
        byte_size_error(value)
    end
  end

  defp cast(:byte_size, value), do: byte_size_error(value)

  defp unit_size(""), do: 1
  defp unit_size("K"), do: 1024
  defp unit_size("M"), do: 1024 * 1024
  defp unit_size("G"), do: 1024 * 1024 * 1024

  defp byte_size_error(value), do: type_error(~s(a size like "512M" or "1G"), value)

  defp unit_ms("ms"), do: 1
  defp unit_ms("s"), do: 1000
  defp unit_ms("m"), do: 60_000
  defp unit_ms("h"), do: 3_600_000
  defp unit_ms("d"), do: 86_400_000

  defp rate_error(value), do: type_error(~s(a rate like "100/1h"), value)

  defp duration_error(value), do: type_error(~s(a duration like "30s", "5m", or "1h"), value)

  # A domain in U-labels as A-labels; anything else as it is, to be
  # checked by the caller.
  defp ascii_name(value) do
    with true <- Sovite.Validators.international?(value),
         {:ok, ascii} <- Sovite.IDNA.to_ascii(value) do
      ascii
    else
      _ -> value
    end
  end

  defp ascii_pattern("@" <> domain), do: "@" <> ascii_name(domain)

  defp ascii_pattern(value) do
    case Sovite.Validators.ascii_domain(value) do
      {:ok, mailbox} -> mailbox
      {:error, _} -> value
    end
  end

  defp type_error(expected, value), do: {:error, "expected #{expected}, got #{inspect(value)}"}

  defp enum_error(allowed, value) do
    {:error,
     "expected one of #{Enum.map_join(allowed, ", ", &inspect(Atom.to_string(&1)))}, got #{inspect(value)}"}
  end
end
