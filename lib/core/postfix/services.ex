defmodule Sovite.Core.Postfix.Services do
  @moduledoc false
  # master.cf: [[listener]] tables from smtpd and postscreen services,
  # [pipe.NAME] sections from pipe services, and the Sovite form of
  # Postfix transports (which can name master.cf client services).

  alias Sovite.Core.Postfix.{Convert, MainCf, MasterCf, State}
  alias Sovite.Core.Transport

  # Postfix daemons that need nothing in Sovite, or are handled where a
  # transport names them.
  @internal ~w(pickup cleanup qmgr oqmgr tlsmgr trivial-rewrite bounce flush proxymap verify
               showq error discard retry local virtual lmtp smtp anvil scache postlogd dnsblog
               tlsproxy pipe spawn smtpd postscreen)

  # -o options of smtpd services that need nothing in Sovite.
  @quiet_options ~w(syslog_name smtpd_tls_auth_only smtpd_reject_unlisted_recipient
                    smtpd_reject_unlisted_sender milter_macro_daemon_name smtpd_helo_required
                    smtpd_delay_reject smtpd_tls_received_header smtpd_sasl_security_options
                    smtpd_sasl_tls_security_options smtpd_sasl_local_domain broken_sasl_auth_clients
                    smtpd_tls_ciphers smtpd_tls_mandatory_ciphers smtpd_tls_exclude_ciphers
                    smtpd_tls_mandatory_exclude_ciphers smtpd_sasl_type smtpd_sasl_path
                    smtpd_tls_loglevel)

  # -o options this module turns into listener keys.
  @listener_options ~w(smtpd_tls_wrappermode smtpd_sasl_auth_enable smtpd_tls_security_level
                       smtpd_upstream_proxy_protocol postscreen_upstream_proxy_protocol
                       smtpd_milters content_filter receive_override_options
                       smtpd_tls_protocols smtpd_tls_mandatory_protocols
                       smtpd_authorized_xforward_hosts smtpd_authorized_xclient_hosts
                       smtpd_enforce_tls smtpd_use_tls)

  @restriction_options ~w(smtpd_client_restrictions smtpd_helo_restrictions
                          smtpd_sender_restrictions smtpd_relay_restrictions
                          smtpd_recipient_restrictions smtpd_data_restrictions
                          smtpd_end_of_data_restrictions)

  # -o options of client services (content filters) that need nothing.
  @quiet_client_options ~w(syslog_name smtp_send_xforward_command lmtp_send_xforward_command
                           smtp_data_done_timeout lmtp_data_done_timeout disable_dns_lookups
                           max_use smtp_discard_ehlo_keywords lmtp_discard_lhlo_keywords
                           smtp_tls_security_level smtp_tls_note_starttls_offer)

  # Pipe macros (pipe(8)) and their Sovite placeholders.
  @macros %{
    "sender" => "{sender}",
    "recipient" => "{recipient}",
    "original_recipient" => "{recipient}",
    "user" => "{user}",
    "extension" => "{extension}",
    "domain" => "{domain}",
    "nexthop" => "{domain}",
    "queue_id" => "{queue_id}"
  }

  ## Listeners

  @doc "Adds a [[listener]] for each address of each smtpd and postscreen service."
  def listeners(state) do
    pass = Enum.find(state.services, &(&1.type == "pass" and &1.command == "smtpd"))
    Enum.reduce(state.services, state, &service(&2, &1, pass))
  end

  defp service(state, %{type: "inet", command: "smtpd"} = service, _pass),
    do: listener(state, service, service.options, :smtpd)

  defp service(state, %{type: "inet", command: "postscreen"} = service, pass),
    do: listener(state, service, service.options ++ ((pass && pass.options) || []), :postscreen)

  defp service(state, %{type: "inet"} = service, _pass) do
    State.report(
      state,
      :attention,
      "master.cf: #{service.name}",
      "#{service.type} #{service.command}",
      "This service runs #{service.command}(8), which Sovite has no equivalent for. Not migrated."
    )
  end

  defp service(state, %{command: command}, _pass) when command in @internal, do: state

  defp service(state, service, _pass) do
    State.report(
      state,
      :attention,
      "master.cf: #{service.name}",
      "#{service.type} #{service.command}",
      "Unknown service, not migrated. If something uses it, set that up for Sovite by hand."
    )
  end

  defp listener(state, service, options, kind) do
    case MasterCf.inet_address(service.name) do
      {:ok, host, port} ->
        context = %{
          state: state,
          service: service,
          options: options,
          kind: kind,
          port: port,
          entries: []
        }

        context
        |> mode()
        |> listener_keys()
        |> service_options()
        |> add_listeners(host)

      :error ->
        State.report(
          state,
          :attention,
          "master.cf: #{service.name}",
          "inet #{service.command}",
          "Unknown service name or port. Not migrated: add a [[listener]] with the address and port."
        )
    end
  end

  # The value of a parameter for the service: its -o override, or main.cf.
  defp option(%{options: options, state: state}, name) do
    case options |> Enum.filter(&(elem(&1, 0) == name)) |> List.last() do
      {_name, value} -> State.expand(state, value)
      nil -> State.value(state, name)
    end
  end

  defp override?(%{options: options}, name), do: List.keymember?(options, name, 0)

  defp mode(context) do
    wrapper = Convert.yes?(option(context, "smtpd_tls_wrappermode"))

    mode =
      cond do
        wrapper or context.service.name in ["smtps", "submissions"] or context.port == 465 ->
          :submissions

        context.service.name == "submission" or context.port == 587 ->
          :submission

        true ->
          :smtp
      end

    reinjection = reinjection?(context)
    context = Map.merge(context, %{mode: mode, reinjection: reinjection})
    if mode == :smtp, do: context, else: entry(context, "mode", Atom.to_string(mode))
  end

  # "-o content_filter=" on a service: where an after-queue filter sends
  # mail back. Only meaningful when some filter is set.
  defp reinjection?(context) do
    override?(context, "content_filter") and option(context, "content_filter") == "" and
      filter_configured?(context.state)
  end

  defp filter_configured?(state) do
    State.value(state, "content_filter") != "" or
      Enum.any?(state.services, fn service ->
        value = MasterCf.option(service, "content_filter")
        value != nil and State.expand(state, value) != ""
      end)
  end

  defp entry(context, key, value, comment \\ nil),
    do: %{context | entries: context.entries ++ [{key, value, comment}]}

  defp listener_keys(%{reinjection: true} = context) do
    context
    |> entry("content_filter", "")
    |> entry("reinjection", true)
    |> proxy_protocol()
  end

  defp listener_keys(context) do
    context
    |> auth()
    |> tls_version()
    |> proxy_protocol()
    |> milters()
    |> content_filter()
  end

  defp auth(%{mode: :smtp} = context) do
    tls = State.flag(context.state, :tls)
    plaintext = State.flag(context.state, :plaintext)
    require_auth = require_auth?(context)
    sasl = Convert.yes?(option(context, "smtpd_sasl_auth_enable")) or require_auth
    encrypt = tls_level(context) == "encrypt"

    context
    |> auth_key(sasl, tls or plaintext, require_auth)
    |> require_tls_key(encrypt, tls)
  end

  defp auth(context) do
    context
    |> submission_note(
      not Convert.yes?(option(context, "smtpd_sasl_auth_enable")),
      "Postfix did not offer AUTH on this service. Sovite offers it on #{context.mode} listeners (auth defaults to true)."
    )
    |> submission_note(
      not require_auth?(context),
      "Postfix accepted mail here without AUTH (at least for its own domains or mynetworks). Sovite refuses MAIL before AUTH on #{context.mode} listeners (require_auth defaults to true); clients in smtp.trusted_networks must log in too."
    )
  end

  defp submission_note(context, false, _message), do: context

  defp submission_note(context, true, message) do
    state =
      State.report(
        context.state,
        :attention,
        "master.cf: #{context.service.name}",
        service_line(context.service),
        message
      )

    %{context | state: state}
  end

  defp auth_key(context, false, _possible, _require), do: context

  defp auth_key(context, true, false, _require) do
    note(
      context,
      "AUTH is only offered over TLS, and there is no certificate (smtpd_tls_cert_file): auth was left off for this listener. Add a [[tls.certificate]] and set auth = true."
    )
  end

  defp auth_key(context, true, true, require) do
    context = entry(context, "auth", true)
    if require, do: entry(context, "require_auth", true), else: context
  end

  defp require_tls_key(context, false, _tls), do: context

  defp require_tls_key(context, true, false),
    do:
      note(
        context,
        "smtpd_tls_security_level = encrypt needs a certificate: require_tls was left off."
      )

  defp require_tls_key(context, true, true) do
    comment =
      if context.port == 25,
        do:
          "Postfix required TLS here; servers on the internet may not support it, so this is not recommended on port 25"

    entry(context, "require_tls", true, comment)
  end

  defp note(context, message) do
    %{
      context
      | state:
          State.report(
            context.state,
            :attention,
            "master.cf: #{context.service.name}",
            service_line(context.service),
            message
          )
    }
  end

  defp tls_level(context) do
    case option(context, "smtpd_tls_security_level") do
      "" -> if Convert.yes?(option(context, "smtpd_enforce_tls")), do: "encrypt", else: ""
      level -> level
    end
  end

  # "permit_sasl_authenticated, reject" in one of the lists that apply to
  # every recipient: only clients that logged in may send.
  defp require_auth?(context) do
    Enum.any?(
      ~w(smtpd_client_restrictions smtpd_helo_restrictions smtpd_sender_restrictions smtpd_relay_restrictions smtpd_recipient_restrictions),
      &auth_pattern?(MainCf.split(option(context, &1)))
    )
  end

  @doc false
  def auth_pattern?(checks) do
    checks = Enum.map(checks, &String.downcase/1)

    List.last(checks) == "reject" and "permit_sasl_authenticated" in checks and
      Enum.all?(
        Enum.drop(checks, -1),
        &(&1 in ["permit_sasl_authenticated", "permit_mynetworks"])
      )
  end

  # A listener's own minimum TLS version, when it differs from tls.min_version.
  defp tls_version(context) do
    global = State.get(context.state, "tls", "min_version") || "1.2"
    requires_tls = context.mode != :smtp or tls_level(context) == "encrypt"

    name =
      cond do
        override?(context, "smtpd_tls_protocols") and not requires_tls ->
          "smtpd_tls_protocols"

        override?(context, "smtpd_tls_mandatory_protocols") ->
          "smtpd_tls_mandatory_protocols"

        requires_tls and State.set?(context.state, "smtpd_tls_mandatory_protocols") ->
          "smtpd_tls_mandatory_protocols"

        true ->
          nil
      end

    with name when name != nil <- name,
         {:ok, "TLSv1.3"} when global != "1.3" <- Convert.min_tls(option(context, name)) do
      entry(context, "tls_min_version", "1.3")
    else
      _ -> context
    end
  end

  defp proxy_protocol(context) do
    name =
      if context.kind == :postscreen,
        do: "postscreen_upstream_proxy_protocol",
        else: "smtpd_upstream_proxy_protocol"

    case option(context, name) do
      "" ->
        context

      "haproxy" ->
        entry(context, "proxy_protocol", true)

      other ->
        note(
          context,
          "#{name} = #{other} is not supported: Sovite speaks the haproxy PROXY protocol (v1 and v2)."
        )
    end
  end

  defp milters(context) do
    overrides = String.split(option(context, "receive_override_options"), ~r/[\s,]+/, trim: true)

    cond do
      "no_milters" in overrides ->
        entry(context, "milters", [])

      override?(context, "smtpd_milters") ->
        names = milter_names(context.state, option(context, "smtpd_milters"))
        global = milter_names(context.state, State.value(context.state, "smtpd_milters"))
        if names == global, do: context, else: entry(context, "milters", names)

      true ->
        context
    end
  end

  defp milter_names(state, value) do
    for item <- MainCf.split(value),
        {:ok, milter} <- [milter_address(state, item)],
        uniq: true,
        do: milter
  end

  @doc """
  The Sovite address of a Postfix milter (`inet:host:port`,
  `unix:/path`, `unix:relative`, `local:path`, or the address of a
  `{ ... }` group), which is also the milter's name.
  """
  def milter_address(state, item) do
    address = item |> MainCf.ungroup() |> MainCf.split() |> List.first("")

    address =
      case String.split(address, ":", parts: 2) do
        [type, path] when type in ["unix", "local"] -> "unix:" <> State.queue_path(state, path)
        _ -> address
      end

    case Sovite.Milter.parse_address(address) do
      {:ok, _} -> {:ok, address}
      {:error, _} -> {:error, address}
    end
  end

  defp content_filter(context) do
    if override?(context, "content_filter") and option(context, "content_filter") != "" do
      case content_filter_spec(context.state, option(context, "content_filter")) do
        {:ok, spec, state} ->
          entry(%{context | state: state}, "content_filter", spec)

        {:error, message, state} ->
          note(%{context | state: state}, message)
      end
    else
      context
    end
  end

  # Reports the -o options that have no listener key.
  defp service_options(%{reinjection: true} = context), do: context

  defp service_options(context) do
    Enum.reduce(context.options, context, fn {name, value}, context ->
      cond do
        name in @quiet_options or name in @listener_options ->
          context

        name in @restriction_options ->
          restriction_option(context, name, State.expand(context.state, value))

        true ->
          note(
            context,
            "-o #{name}=#{value}: per-service settings are not migrated; Sovite's [smtp] settings apply to every listener."
          )
      end
    end)
  end

  defp restriction_option(context, name, value) do
    checks = MainCf.split(value)

    if checks == [] or auth_pattern?(checks) do
      context
    else
      note(
        context,
        "-o #{name}=#{value}: Sovite's [restrictions] apply to every listener, so this per-service list was not migrated. The main.cf lists were."
      )
    end
  end

  defp add_listeners(context, host) do
    {addresses, state} =
      case host do
        nil -> {interface_addresses(context.state), context.state}
        host -> listen_address(context.state, host, context.service)
      end

    if context.mode in [:submission, :submissions] and not State.flag(state, :tls) do
      State.report(
        state,
        :attention,
        "master.cf: #{context.service.name}",
        service_line(context.service),
        "A #{context.mode} listener needs a TLS certificate, and there is none (smtpd_tls_cert_file). Not migrated: add a [[tls.certificate]] or [tls.acme], then a [[listener]] with mode = \"#{context.mode}\"."
      )
    else
      Enum.reduce(addresses, state, fn address, state ->
        entries = [{"address", address, nil}, {"port", context.port, nil} | context.entries]

        State.add_table(
          state,
          "listener",
          entries,
          "master.cf: " <> service_line(context.service)
        )
      end)
    end
  end

  defp listen_address(state, host, service) do
    case Sovite.Net.parse_ip(host |> String.trim_leading("[") |> String.trim_trailing("]")) do
      {:ok, ip} ->
        {[ip |> :inet.ntoa() |> to_string()], state}

      {:error, _} when host == "localhost" ->
        {["127.0.0.1"], state}

      {:error, _} ->
        {[],
         State.report(
           state,
           :attention,
           "master.cf: #{service.name}",
           service_line(service),
           "Listeners need an IP address, not a host name. Not migrated: add a [[listener]] with the address."
         )}
    end
  end

  @doc "The addresses of inet_interfaces, for the IP versions of inet_protocols."
  def interface_addresses(state) do
    versions = ip_versions(state)
    ipv4 = :ipv4 in versions
    ipv6 = :ipv6 in versions

    state
    |> State.list("inet_interfaces")
    |> Enum.flat_map(fn
      "all" -> pick([{ipv4, "0.0.0.0"}, {ipv6, "::"}])
      "loopback-only" -> pick([{ipv4, "127.0.0.1"}, {ipv6, "::1"}])
      "localhost" -> pick([{ipv4, "127.0.0.1"}, {ipv6, "::1"}])
      address -> interface_address(address, ipv4, ipv6)
    end)
    |> Enum.uniq()
  end

  defp interface_address(address, ipv4, ipv6) do
    case Sovite.Net.parse_ip(address |> String.trim_leading("[") |> String.trim_trailing("]")) do
      {:ok, ip} when tuple_size(ip) == 4 -> pick([{ipv4, to_string(:inet.ntoa(ip))}])
      {:ok, ip} -> pick([{ipv6, to_string(:inet.ntoa(ip))}])
      {:error, _} -> []
    end
  end

  defp pick(choices), do: for({true, address} <- choices, do: address)

  @doc "The IP versions inet_protocols enables."
  def ip_versions(state) do
    case State.list(state, "inet_protocols") do
      ["all"] -> [:ipv4, :ipv6]
      items -> Enum.flat_map(items, &ip_version/1)
    end
  end

  defp ip_version("ipv4"), do: [:ipv4]
  defp ip_version("ipv6"), do: [:ipv6]
  defp ip_version("all"), do: [:ipv4, :ipv6]
  defp ip_version(_other), do: []

  @doc "A master.cf service as one line, for comments and the report."
  def service_line(service) do
    Enum.join(
      [
        service.name,
        service.type,
        service.private,
        service.unpriv,
        service.chroot,
        service.wakeup,
        service.maxproc,
        service.command
      ],
      " "
    )
  end

  ## Transports

  @doc """
  The Sovite form of a Postfix transport (`name:nexthop`), resolving
  master.cf client and pipe services. Adds [pipe.NAME] sections as
  needed. `setting` names where the transport came from, for the report.
  """
  def transport(state, spec, setting) do
    {name, nexthop} =
      case String.split(String.trim(spec), ":", parts: 2) do
        [name, nexthop] -> {name, String.trim(nexthop)}
        [name] -> {name, ""}
      end

    with {:ok, sovite, state} <- convert(state, kind(state, name), name, nexthop, setting) do
      case Transport.parse(sovite) do
        {:ok, _} ->
          {:ok, sovite, state}

        :error ->
          {:error, "#{spec} cannot be converted (#{sovite} is not a valid Sovite transport)",
           state}
      end
    end
  end

  defp kind(_state, ""), do: {:keep, nil}

  defp kind(state, name) do
    case State.service(state, name, ["unix"]) do
      nil -> builtin(name, nil)
      service -> builtin(service.command, service)
    end
  end

  # Fixed table: never create atoms from the files.
  defp builtin("smtp", service), do: {:smtp, service}
  defp builtin("relay", nil), do: {:smtp, nil}
  defp builtin("lmtp", service), do: {:lmtp, service}
  defp builtin("pipe", service) when service != nil, do: {:pipe, service}
  defp builtin("local", service), do: {:local, service}
  defp builtin("virtual", service), do: {:virtual, service}
  defp builtin("error", service), do: {:error, service}
  defp builtin("retry", service), do: {:retry, service}
  defp builtin("discard", service), do: {:discard, service}
  defp builtin(_command, _service), do: :unknown

  defp convert(state, :unknown, name, _nexthop, _setting),
    do:
      {:error,
       "#{name} is not a transport Sovite knows, nor a pipe, smtp, or lmtp service in master.cf",
       state}

  defp convert(state, {:keep, nil}, _name, nexthop, _setting), do: {:ok, ":" <> nexthop, state}

  defp convert(state, {:smtp, service}, _name, nexthop, setting) do
    state = client_options(state, service, setting)
    {:ok, if(nexthop == "", do: "smtp", else: "smtp:" <> nexthop), state}
  end

  defp convert(state, {:lmtp, service}, _name, nexthop, setting) do
    state = client_options(state, service, setting)

    case nexthop do
      "unix:" <> path ->
        absolute = State.queue_path(state, path)
        state = if absolute == path, do: state, else: queue_socket_note(state, setting, absolute)
        {:ok, "lmtp:unix:" <> absolute, state}

      "" ->
        {:ok, "lmtp", state}

      "inet:" <> address ->
        {:ok, "lmtp:" <> bracket_ip(address), state}

      nexthop ->
        {:ok, "lmtp:" <> nexthop, state}
    end
  end

  defp convert(state, {:local, _service}, _name, _nexthop, _setting), do: {:ok, "local", state}

  defp convert(state, {:virtual, _service}, _name, _nexthop, _setting),
    do: {:ok, "mailbox", state}

  defp convert(state, {:pipe, service}, _name, _nexthop, setting) do
    if Transport.pipe_name?(service.name) do
      with {:ok, state} <- pipe(state, service, setting),
           do: {:ok, "pipe:" <> service.name, state}
    else
      {:error, "the pipe service name #{service.name} is not a valid Sovite pipe name", state}
    end
  end

  defp convert(state, {kind, _service}, _name, nexthop, _setting) do
    name = Atom.to_string(kind)
    {:ok, if(nexthop == "", do: name, else: name <> ":" <> nexthop), state}
  end

  # Postfix's lmtp:inet:192.0.2.1:24; Sovite writes IP addresses in brackets.
  defp bracket_ip(address) do
    case MasterCf.inet_address(address) do
      {:ok, host, port} when is_binary(host) ->
        case Sovite.Net.parse_ip(host) do
          {:ok, _ip} -> "[#{host}]:#{port}"
          {:error, _} -> "inet:" <> address
        end

      _ ->
        "inet:" <> address
    end
  end

  defp queue_socket_note(state, setting, path) do
    if State.flag(state, {:socket_note, path}) do
      state
    else
      state
      |> State.flag({:socket_note, path}, true)
      |> State.report(
        :attention,
        setting,
        State.explicit(state, setting),
        "The socket #{path} is inside Postfix's queue directory, which goes away with Postfix. Move it, for Dovecot's LMTP socket in /etc/dovecot/conf.d/10-master.conf (service lmtp { unix_listener lmtp { ... } }) to e.g. /run/dovecot/lmtp with access for the Sovite user, and change the transport to lmtp:unix:/run/dovecot/lmtp."
      )
    end
  end

  # Options of a client service a transport uses, other than the usual
  # ones of a content filter, are reported once.
  defp client_options(state, nil, _setting), do: state

  defp client_options(state, service, _setting) do
    options = Enum.reject(service.options, fn {name, _} -> name in @quiet_client_options end)

    if options == [] or State.flag(state, {:client_options, service.name}) do
      state
    else
      text = Enum.map_join(options, " ", fn {name, value} -> "-o #{name}=#{value}" end)

      state
      |> State.flag({:client_options, service.name}, true)
      |> State.report(
        :attention,
        "master.cf: #{service.name}",
        service_line(service),
        "Per-service options are not migrated: #{text}. Set the [delivery] equivalents if they matter."
      )
    end
  end

  defp pipe(state, service, setting) do
    section = "pipe." <> service.name

    if Map.has_key?(state.config, section) do
      {:ok, state}
    else
      attributes = MasterCf.attributes(service.args)
      argv = Map.get(attributes, "argv", [])
      {command, unknown} = Enum.map_reduce(argv, [], &pipe_arg/2)

      if command != [] and Path.type(hd(command)) == :absolute do
        {:ok, add_pipe(state, service, section, command, attributes, Enum.uniq(unknown))}
      else
        {:error,
         "#{setting}: the command of pipe service #{service.name} (argv=#{Enum.join(argv, " ")}) is not an absolute path",
         state}
      end
    end
  end

  defp add_pipe(state, service, section, command, attributes, unknown) do
    flags = Map.get(attributes, "flags", "")
    trace = String.contains?(flags, "D") or String.contains?(flags, "R")

    state
    |> State.put(section, "command", command)
    |> then(&if(trace, do: &1, else: State.put(&1, section, "trace_headers", false)))
    |> pipe_notes(service, attributes, unknown)
  end

  defp pipe_notes(state, service, attributes, unknown) do
    notes =
      [
        attributes["user"] &&
          "user=#{attributes["user"]}: Sovite cannot switch users, so the command runs as the Sovite user. Set sandbox (for example systemd-run with User=#{attributes["user"] |> String.split(":") |> hd()}) in [pipe.#{service.name}] if it must run as another user.",
        unsupported_flags(attributes["flags"]),
        unknown != [] &&
          "Macros Sovite does not have were left as they are: #{Enum.join(unknown, ", ")}. Placeholders: {sender}, {recipient}, {user}, {extension}, {domain}, {queue_id}.",
        Map.has_key?(attributes, "size") &&
          "size= is not supported: smtp.max_message_size applies."
      ]
      |> Enum.filter(&is_binary/1)

    if notes == [] do
      state
    else
      State.report(
        state,
        :attention,
        "master.cf: #{service.name}",
        service_line(service),
        Enum.join(notes, " ")
      )
    end
  end

  defp unsupported_flags(nil), do: nil

  defp unsupported_flags(flags) do
    other = flags |> String.graphemes() |> Enum.reject(&(&1 in ["D", "R", "h", "u", "q"]))

    if other != [],
      do:
        "flags=#{flags}: only D and R (trace_headers) have an equivalent; #{Enum.join(other)} were dropped."
  end

  defp pipe_arg(arg, unknown) do
    Regex.scan(~r/\$\{(\w+)\}|\$\((\w+)\)|\$(\w+)/, arg)
    |> Enum.reduce({arg, unknown}, fn [macro | names], {arg, unknown} ->
      name = Enum.find(names, &(&1 != ""))

      case Map.fetch(@macros, String.downcase(name)) do
        {:ok, placeholder} -> {String.replace(arg, macro, placeholder), unknown}
        :error -> {arg, [macro | unknown]}
      end
    end)
  end

  @doc """
  The Sovite form of a content filter transport: smtp or lmtp with a
  next hop.
  """
  def content_filter_spec(state, value) do
    case transport(state, value, "content_filter") do
      {:ok, "smtp:" <> _ = spec, state} ->
        {:ok, spec, state}

      {:ok, "lmtp:" <> _ = spec, state} ->
        {:ok, spec, state}

      {:ok, spec, state} ->
        {:error,
         "content_filter = #{value} (#{spec}): Sovite's content filters are SMTP or LMTP servers with a next hop, such as smtp:[127.0.0.1]:10024. Not migrated.",
         state}

      {:error, message, state} ->
        {:error, "content_filter = #{value}: #{message}. Not migrated.", state}
    end
  end
end
