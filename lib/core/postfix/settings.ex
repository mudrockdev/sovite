defmodule Sovite.Core.Postfix.Settings do
  @moduledoc false
  # main.cf: limits and timers -> [queue], [smtp], [delivery], and
  # [rate_limit]; transports -> [routing]; milters -> [[milter]]; the
  # content filter, XCLIENT, XFORWARD, and PROXY settings -> [smtp]; the
  # policy server defaults -> [policy]; and the parameters left over.

  alias Sovite.Core.Postfix.{Convert, MainCf, MasterCf, Services, State}

  ## Scalars

  # {parameter, section, key, kind}: kinds are {:duration, unit},
  # {:integer, min, max}, :size, :rate, and :boolean_not (disable_vrfy).
  @scalars [
    {"maximal_queue_lifetime", "queue", "max_lifetime", {:duration, "d"}},
    {"minimal_backoff_time", "queue", "min_backoff", {:duration, "s"}},
    {"maximal_backoff_time", "queue", "max_backoff", {:duration, "s"}},
    {"delay_warning_time", "queue", "delay_warning", {:duration, "h"}},
    {"message_size_limit", "smtp", "max_message_size", :size},
    {"smtpd_recipient_limit", "smtp", "max_recipients", {:integer, 1, 100_000}},
    {"smtpd_client_connection_count_limit", "smtp", "max_connections_per_ip",
     {:integer, 1, 1_000_000}},
    {"smtpd_soft_error_limit", "smtp", "tarpit_after", {:integer, 1, 1000}},
    {"smtpd_hard_error_limit", "smtp", "max_errors", {:integer, 1, 1000}},
    {"smtpd_error_sleep_time", "smtp", "tarpit_delay", {:duration, "s"}},
    {"smtpd_timeout", "smtp", "command_timeout", {:duration, "s"}},
    {"smtpd_upstream_proxy_timeout", "smtp", "proxy_timeout", {:duration, "s"}},
    {"disable_vrfy_command", "smtp", "vrfy", :boolean_not},
    {"smtpd_client_connection_rate_limit", "rate_limit", "client_connections", :rate},
    {"smtpd_client_message_rate_limit", "rate_limit", "client_messages", :rate},
    {"smtpd_client_recipient_rate_limit", "rate_limit", "client_recipients", :rate},
    {"default_process_limit", "delivery", "max_deliveries", {:integer, 1, 100_000}},
    {"default_destination_concurrency_limit", "delivery", "destination_concurrency",
     {:integer, 1, 100_000}},
    {"smtp_destination_concurrency_limit", "delivery", "destination_concurrency",
     {:integer, 1, 100_000}},
    {"default_destination_recipient_limit", "delivery", "max_recipients", {:integer, 1, 100_000}},
    {"smtp_destination_recipient_limit", "delivery", "max_recipients", {:integer, 1, 100_000}},
    {"default_destination_rate_delay", "delivery", "destination_rate_delay", {:duration, "s"}},
    {"smtp_destination_rate_delay", "delivery", "destination_rate_delay", {:duration, "s"}},
    {"smtp_connect_timeout", "delivery", "connect_timeout", {:duration, "s"}},
    {"smtpd_policy_service_timeout", "policy", "timeout", {:duration, "s"}}
  ]

  @notes %{
    "default_process_limit" =>
      " Postfix limited each kind of process; Sovite limits deliveries in progress.",
    "smtpd_timeout" => " Sovite also has smtp.data_timeout (default 5m) for the message data.",
    "smtpd_hard_error_limit" => " Postfix counted errors, Sovite counts error replies."
  }

  @doc "The limits and timers of main.cf."
  def scalars(state) do
    Enum.reduce(@scalars, state, fn {name, section, key, kind}, state ->
      case State.explicit(state, name) do
        nil ->
          state

        value ->
          scalar(State.handle(state, name), name, section, key, convert(kind, value, state, name))
      end
    end)
  end

  defp scalar(state, name, section, key, {:ok, value}) do
    state
    |> State.put(section, key, value)
    |> State.report_param(:migrated, name, "#{section}.#{key}." <> Map.get(@notes, name, ""))
  end

  defp scalar(state, name, _section, _key, {:off, message}),
    do: State.report_param(state, :ignored, name, message)

  defp scalar(state, name, _section, _key, {:attention, message}),
    do: State.report_param(state, :attention, name, message)

  defp scalar(state, name, section, key, :error),
    do:
      State.report_param(
        state,
        :attention,
        name,
        "Not a value Sovite accepts for #{section}.#{key}. Not migrated."
      )

  # Durations that are off when unset in Sovite.
  @optional ~w(delay_warning_time default_destination_rate_delay smtp_destination_rate_delay)

  defp convert({:duration, unit}, value, _state, name) do
    case Convert.duration(value, unit) do
      {:ok, duration} -> {:ok, duration}
      :zero when name in @optional -> {:off, "0 turns it off, as Sovite's default does."}
      :zero -> {:attention, "0 is not a time Sovite accepts: its default applies."}
      :error -> :error
    end
  end

  defp convert({:integer, min, max}, value, _state, _name) do
    case Convert.integer(value) do
      {:ok, 0} ->
        {:attention, "0 means no limit, which Sovite does not have: its default applies."}

      {:ok, number} when number >= min and number <= max ->
        {:ok, number}

      _ ->
        :error
    end
  end

  defp convert(:size, value, _state, _name) do
    case Convert.integer(value) do
      {:ok, 0} ->
        {:attention, "0 means no limit, which Sovite does not have: its default (25M) applies."}

      {:ok, bytes} ->
        {:ok, bytes}

      :error ->
        :error
    end
  end

  defp convert(:rate, value, state, _name) do
    with {:ok, count} when count > 0 <- Convert.integer(value),
         {:ok, unit} <- Convert.duration(State.value(state, "anvil_rate_time_unit"), "s") do
      {:ok, "#{count}/#{unit}"}
    else
      {:ok, 0} -> {:off, "0 means no limit, as Sovite's default does."}
      _ -> :error
    end
  end

  defp convert(:boolean_not, value, _state, _name) do
    cond do
      Convert.yes?(value) ->
        {:off, "Sovite answers VRFY with 252 by default (smtp.vrfy = false)."}

      Convert.no?(value) ->
        {:ok, true}

      true ->
        :error
    end
  end

  ## Routing

  @doc "Transports, the extension delimiter, masquerading, and always_bcc -> [routing]."
  def routing(state) do
    state
    |> mailbox_transport()
    |> local_transport()
    |> transport("relay_transport", "relay_transport")
    |> transport("default_transport", "remote_transport")
    |> delimiter()
    |> masquerade()
    |> always_bcc()
  end

  defp mailbox_transport(state) do
    state = State.handle(state, ["virtual_transport", "virtual_mailbox_base"])

    case State.explicit(state, "virtual_transport") do
      nil ->
        if State.set?(state, "virtual_mailbox_maps"), do: virtual_maildir(state), else: state

      value ->
        case Services.transport(state, value, "virtual_transport") do
          {:ok, "mailbox", state} ->
            virtual_maildir(state)

          {:ok, spec, state} ->
            state
            |> State.put("routing", "mailbox_transport", spec, queue_comment(state, spec))
            |> State.report_param(
              :migrated,
              "virtual_transport",
              "routing.mailbox_transport = #{inspect(spec)}."
            )

          {:error, message, state} ->
            State.report_param(
              state,
              :attention,
              "virtual_transport",
              message <> ". Not migrated."
            )
        end
    end
  end

  defp queue_comment(state, spec) do
    if String.contains?(spec, state.queue_directory <> "/"),
      do: "the socket is inside Postfix's queue directory: move it, see report.txt"
  end

  # Postfix's virtual(8): Maildirs under virtual_mailbox_base, at the
  # paths the virtual_mailbox_maps values give.
  defp virtual_maildir(state) do
    case State.value(state, "virtual_mailbox_base") do
      "" ->
        State.report(
          state,
          :attention,
          "virtual_transport",
          "virtual",
          "Postfix's virtual(8) delivered to the paths in virtual_mailbox_maps, and virtual_mailbox_base is not set. Set maildir.mailbox by hand."
        )

      base ->
        template = Path.join(base, "{domain}/{user}") <> "/"

        state
        |> State.put(
          "maildir",
          "mailbox",
          template,
          "Postfix took the folder of each mailbox from virtual_mailbox_maps: make sure they follow this pattern"
        )
        |> State.report(
          :attention,
          "virtual_mailbox_base",
          base,
          "maildir.mailbox = #{inspect(template)}. Postfix's virtual(8) took each folder from virtual_mailbox_maps; Sovite uses one template, so check that the existing Maildirs match it, and that the Sovite user may write them."
        )
    end
  end

  # Postfix's local(8) handles aliases, then hands mailboxes to
  # mailbox_transport, mailbox_command, or the mail spool.
  defp local_transport(state) do
    state =
      State.handle(state, [
        "local_transport",
        "mailbox_transport",
        "mailbox_command",
        "home_mailbox",
        "mail_spool_directory"
      ])

    local = State.value(state, "local_transport")

    cond do
      not String.starts_with?(local, "local") ->
        transport(state, "local_transport", "local_transport")

      State.explicit(state, "mailbox_transport") not in [nil, ""] ->
        case Services.transport(
               state,
               State.value(state, "mailbox_transport"),
               "mailbox_transport"
             ) do
          {:ok, spec, state} ->
            state
            |> State.put("routing", "local_transport", spec, queue_comment(state, spec))
            |> State.report_param(
              :migrated,
              "mailbox_transport",
              "routing.local_transport = #{inspect(spec)} (Sovite resolves aliases before the transport)."
            )

          {:error, message, state} ->
            State.report_param(
              state,
              :attention,
              "mailbox_transport",
              message <> ". Not migrated."
            )
        end

      State.explicit(state, "mailbox_command") not in [nil, ""] ->
        State.report_param(
          state,
          :attention,
          "mailbox_command",
          "Commands are run by [pipe.NAME] transports in Sovite, without a shell: add one (placeholders {sender}, {recipient}, {user}, {extension}), such as command = [\"/usr/lib/dovecot/dovecot-lda\", \"-f\", \"{sender}\", \"-a\", \"{recipient}\", \"-d\", \"{user}\"], and set routing.local_transport = \"pipe:NAME\"."
        )

      State.explicit(state, "home_mailbox") not in [nil, ""] ->
        home_mailbox(state, State.value(state, "home_mailbox"))

      State.get(state, "domains", "local") == [] ->
        state

      true ->
        State.report(
          state,
          :attention,
          "local delivery",
          nil,
          "Postfix delivered mail for local users to mbox files in the mail spool (mail_spool_directory). Sovite delivers to Maildirs: set maildir.local, such as \"/var/mail/{user}/\", or route local mail elsewhere (routing.local_transport)."
        )
    end
  end

  defp home_mailbox(state, value) do
    if String.ends_with?(value, "/") do
      template = "/home/{user}/" <> value

      state
      |> State.put(
        "maildir",
        "local",
        template,
        "Postfix used each user's home directory; Sovite does not look them up"
      )
      |> State.report_param(
        :attention,
        "home_mailbox",
        "maildir.local = #{inspect(template)}. Sovite does not look up home directories: check the path, and that the Sovite user may write there."
      )
    else
      State.report_param(
        state,
        :attention,
        "home_mailbox",
        "mbox files are not supported: Sovite delivers to Maildirs (maildir.local)."
      )
    end
  end

  defp transport(state, name, key) do
    state = State.handle(state, name)

    with value when value != nil <- State.explicit(state, name),
         {:ok, spec, state} <- Services.transport(state, value, name) do
      sovite_default = if key == "local_transport", do: "local", else: "smtp"

      if spec == sovite_default,
        do:
          State.report_param(
            state,
            :ignored,
            name,
            "The same as Sovite's default routing.#{key}."
          ),
        else:
          state
          |> State.put("routing", key, spec)
          |> State.report_param(:migrated, name, "routing.#{key} = #{inspect(spec)}.")
    else
      nil ->
        state

      {:error, message, state} ->
        State.report_param(state, :attention, name, message <> ". Not migrated.")
    end
  end

  defp delimiter(state) do
    case State.explicit(state, "recipient_delimiter") do
      nil ->
        state

      value ->
        if String.length(value) <= 8 and not String.match?(value, ~r/[[:alnum:]@\s"<>.]/u),
          do:
            state
            |> State.put("routing", "extension_delimiter", value)
            |> State.report_param(:migrated, "recipient_delimiter", "routing.extension_delimiter"),
          else:
            State.report_param(
              state,
              :attention,
              "recipient_delimiter",
              "Not a delimiter Sovite accepts. Not migrated."
            )
    end
  end

  defp masquerade(state) do
    state =
      State.handle(state, ["masquerade_domains", "masquerade_exceptions", "masquerade_classes"])

    state =
      case State.list(state, "masquerade_domains") do
        [] ->
          state

        items ->
          {good, bad} = Enum.split_with(items, &Convert.domain?(String.trim_leading(&1, "!")))

          state
          |> State.put("routing", "hide_subdomains", Enum.map(good, &String.downcase/1))
          |> State.report_param(
            if(bad == [], do: :migrated, else: :attention),
            "masquerade_domains",
            "routing.hide_subdomains." <>
              if(bad == [], do: "", else: " Not migrated: #{Enum.join(bad, ", ")}.")
          )
      end

    state =
      case State.list(state, "masquerade_exceptions") do
        [] ->
          state

        users ->
          state
          |> State.put("routing", "hide_subdomains_exceptions", users)
          |> State.report_param(
            :migrated,
            "masquerade_exceptions",
            "routing.hide_subdomains_exceptions"
          )
      end

    if State.set?(state, "masquerade_classes"),
      do:
        State.report_param(
          state,
          :attention,
          "masquerade_classes",
          "Sovite masquerades sender addresses in the envelope and headers; this is not configurable."
        ),
      else: state
  end

  defp always_bcc(state) do
    case State.explicit(state, "always_bcc") do
      nil ->
        state

      "" ->
        State.handle(state, "always_bcc")

      value ->
        address = qualify(state, value)

        if Convert.address?(address),
          do:
            state
            |> State.put("routing", "always_bcc", address)
            |> State.report_param(:migrated, "always_bcc", "routing.always_bcc"),
          else:
            State.report_param(state, :attention, "always_bcc", "Not an address. Not migrated.")
    end
  end

  defp qualify(state, address) do
    if String.contains?(address, "@") or state.origin == nil,
      do: address,
      else: address <> "@" <> state.origin
  end

  ## Milters

  @milter_defaults %{
    "connect_timeout" => "30s",
    "command_timeout" => "30s",
    "content_timeout" => "5m"
  }

  @doc """
  smtpd_milters, and those in -o smtpd_milters overrides -> [[milter]].
  Listeners run all milters by default, so when a service lists milters
  main.cf does not, the other listeners get main.cf's list.
  """
  def milters(state) do
    state = State.handle(state, ~w(smtpd_milters milter_default_action milter_connect_timeout
                                   milter_command_timeout milter_content_timeout))

    main = MainCf.split(State.value(state, "smtpd_milters"))

    overrides =
      for service <- state.services,
          service.command in ["smtpd", "postscreen"],
          value = MasterCf.option(service, "smtpd_milters"),
          value != nil,
          item <- MainCf.split(State.expand(state, value)),
          do: item

    {state, names} =
      Enum.reduce(main ++ overrides, {state, []}, fn item, {state, names} ->
        milter(state, item, names)
      end)

    global =
      for item <- main,
          {:ok, address} <- [Services.milter_address(state, item)],
          uniq: true,
          do: address

    state
    |> report_milters(main, names)
    |> listener_milters(names, global)
    |> milter_notes()
  end

  defp milter(state, item, names) do
    case Services.milter_address(state, item) do
      {:ok, address} ->
        if address in names,
          do: {state, names},
          else: {add_milter(state, item, address), names ++ [address]}

      {:error, address} ->
        {State.report(
           state,
           :attention,
           "smtpd_milters",
           item,
           "#{address} is not a milter address Sovite accepts. Not migrated."
         ), names}
    end
  end

  defp add_milter(state, item, address) do
    [_address | attributes] = item |> MainCf.ungroup() |> MainCf.split()

    attributes =
      for attribute <- attributes,
          [key, value] <- [String.split(attribute, "=", parts: 2)],
          into: %{},
          do: {String.trim(key), String.trim(value)}

    {entries, state} =
      Enum.flat_map_reduce(
        ["default_action", "connect_timeout", "command_timeout", "content_timeout"],
        state,
        fn key, state ->
          value = Map.get(attributes, key) || State.value(state, "milter_" <> key)
          milter_setting(state, address, key, value)
        end
      )

    state = queue_socket(state, address)
    State.add_table(state, "milter", [{"address", address, nil} | entries])
  end

  defp milter_setting(state, _address, _key, ""), do: {[], state}

  defp milter_setting(state, _address, "default_action", "tempfail"), do: {[], state}

  defp milter_setting(state, _address, "default_action", value)
       when value in ["accept", "reject"],
       do: {[{"default_action", value, nil}], state}

  defp milter_setting(state, address, "default_action", value),
    do:
      {[],
       State.report(
         state,
         :attention,
         "milter_default_action",
         value,
         "#{address}: Sovite's default_action is tempfail, accept, or reject; tempfail is used."
       )}

  defp milter_setting(state, address, key, value) do
    case Convert.duration(value, "s") do
      {:ok, duration} ->
        if Convert.milliseconds(duration) == Convert.milliseconds(@milter_defaults[key]),
          do: {[], state},
          else: {[{key, duration, nil}], state}

      _ ->
        {[],
         State.report(
           state,
           :attention,
           "milter_" <> key,
           value,
           "#{address}: not a time Sovite accepts; the default is used."
         )}
    end
  end

  defp queue_socket(state, "unix:" <> path) do
    if String.starts_with?(path, state.queue_directory <> "/"),
      do:
        State.report(
          state,
          :attention,
          "smtpd_milters",
          "unix:" <> path,
          "The milter's socket is inside Postfix's queue directory, which goes away with Postfix. Move it (for OpenDKIM, Socket in opendkim.conf) to a place the Sovite user can reach, and change the [[milter]] address."
        ),
      else: state
  end

  defp queue_socket(state, _address), do: state

  defp report_milters(state, [], []), do: state

  defp report_milters(state, _main, names),
    do:
      State.report(
        state,
        :migrated,
        "smtpd_milters",
        State.explicit(state, "smtpd_milters"),
        "[[milter]] #{Enum.join(names, ", ")}."
      )

  defp listener_milters(state, names, global) do
    if Enum.sort(names) == Enum.sort(global) do
      state
    else
      tables = for table <- State.tables(state, "listener"), do: default_milters(table, global)
      State.put_tables(state, "listener", tables)
    end
  end

  defp default_milters({entries, comment}, global) do
    if List.keymember?(entries, "milters", 0) or List.keymember?(entries, "reinjection", 0),
      do: {entries, comment},
      else: {entries ++ [{"milters", global, nil}], comment}
  end

  defp milter_notes(state) do
    smtpd = MainCf.split(State.value(state, "smtpd_milters"))

    state
    |> note("non_smtpd_milters", fn value ->
      if value == "" or MainCf.split(value) == smtpd,
        do:
          {:ignored,
           "Sovite's sendmail submits mail over SMTP to a listener, whose milters apply."},
        else:
          {:attention,
           "Sovite's sendmail submits mail over SMTP to a listener, whose milters apply; these milters were not migrated."}
    end)
    |> note("milter_protocol", fn _ -> {:ignored, "Sovite speaks milter protocol version 6."} end)
    |> notes(
      ~w(milter_connect_macros milter_helo_macros milter_mail_macros milter_rcpt_macros
                milter_data_macros milter_unknown_command_macros milter_end_of_header_macros
                milter_end_of_data_macros milter_macro_daemon_name milter_macro_v),
      {:ignored,
       "Sovite sends the macros Postfix sends by default (i, j, {daemon_name}, {client_addr}, {client_name}, {auth_authen}, {mail_addr}, {rcpt_addr}, ...)."}
    )
    |> notes(
      ~w(milter_header_checks smtpd_milter_maps),
      {:attention, "Not supported. Not migrated."}
    )
  end

  defp note(state, name, fun) do
    case State.explicit(state, name) do
      nil ->
        state

      value ->
        {level, message} = fun.(value)
        State.report_param(state, level, name, message)
    end
  end

  defp notes(state, names, {level, message}),
    do: Enum.reduce(names, state, &note(&2, &1, fn _ -> {level, message} end))

  ## Content filters and proxies

  @doc "content_filter, XFORWARD and XCLIENT hosts, and the PROXY protocol -> [smtp]."
  def filters(state) do
    state
    |> content_filter()
    |> networks("smtpd_authorized_xforward_hosts", "xforward_networks")
    |> networks("smtpd_authorized_xclient_hosts", "xclient_networks")
    |> proxy_protocol()
    |> note("receive_override_options", fn _ ->
      {:attention,
       "Sovite has no such options for every listener: a reinjection listener skips the filter, milters, screen, and email authentication."}
    end)
  end

  defp content_filter(state) do
    state = State.handle(state, "content_filter")

    case State.explicit(state, "content_filter") do
      value when value in [nil, ""] ->
        state

      value ->
        case Services.content_filter_spec(state, value) do
          {:ok, spec, state} ->
            state
            |> State.put("smtp", "content_filter", spec)
            |> State.report_param(
              :migrated,
              "content_filter",
              "smtp.content_filter = #{inspect(spec)}. The filter must send mail back to the reinjection listener."
            )

          {:error, message, state} ->
            State.report_param(state, :attention, "content_filter", message)
        end
    end
  end

  # From main.cf and the -o overrides of smtpd services: Sovite's
  # setting is the same for every listener.
  defp networks(state, name, key) do
    items =
      State.list(state, name) ++
        for service <- state.services,
            service.command == "smtpd",
            value = MasterCf.option(service, name),
            value != nil,
            item <- MainCf.split(State.expand(state, value)),
            do: item

    state = State.handle(state, name)

    if items == [] do
      state
    else
      {networks, problems} = Convert.networks(Enum.uniq(items))

      state
      |> State.put("smtp", key, networks)
      |> State.report(
        State.level(problems),
        name,
        Enum.join(Enum.uniq(items), ", "),
        "smtp.#{key} (for every listener)." <> State.not_migrated(problems)
      )
    end
  end

  defp proxy_protocol(state) do
    case State.explicit(state, "smtpd_upstream_proxy_protocol") do
      nil ->
        state

      "" ->
        State.handle(state, "smtpd_upstream_proxy_protocol")

      _value ->
        State.report_param(
          state,
          :migrated,
          "smtpd_upstream_proxy_protocol",
          "proxy_protocol = true on the smtpd listeners."
        )
    end
  end

  ## Policy servers

  @doc "smtpd_policy_service_default_action -> policy.default_action."
  def policy(state) do
    state =
      Enum.reduce(
        ~w(smtpd_policy_service_max_idle smtpd_policy_service_max_ttl smtpd_policy_service_try_limit
                     smtpd_policy_service_retry_delay smtpd_policy_service_request_limit smtpd_policy_service_policy_context),
        state,
        fn name, state ->
          if State.set?(state, name),
            do:
              State.report_param(state, :ignored, name, "Sovite opens a connection per request."),
            else: state
        end
      )

    case State.explicit(state, "smtpd_policy_service_default_action") do
      nil ->
        state

      value ->
        case Sovite.Policy.parse_action(value) do
          {:ok, _} ->
            state
            |> State.put("policy", "default_action", value)
            |> State.report_param(
              :migrated,
              "smtpd_policy_service_default_action",
              "policy.default_action"
            )

          {:error, _} ->
            State.report_param(
              state,
              :attention,
              "smtpd_policy_service_default_action",
              "Not an action Sovite accepts. Not migrated."
            )
        end
    end
  end

  ## Delivery

  @doc "inet_protocols and smtp_address_preference -> delivery.ip_versions; bind addresses -> delivery.source_address."
  def delivery(state) do
    state
    |> ip_versions()
    |> source_address()
  end

  defp ip_versions(state) do
    state = State.handle(state, ["inet_protocols", "smtp_address_preference"])
    versions = Services.ip_versions(state)
    preference = State.value(state, "smtp_address_preference")

    ordered =
      case {Enum.uniq(versions), preference} do
        {[_, _], "ipv4"} -> ["ipv4", "ipv6"]
        {[_, _], _} -> nil
        {[version], _} -> [Atom.to_string(version)]
        {[], _} -> :error
      end

    case ordered do
      nil ->
        state

      :error ->
        State.report_param(
          state,
          :attention,
          "inet_protocols",
          "No IP version Sovite knows. Not migrated."
        )

      ordered ->
        state
        |> State.put("delivery", "ip_versions", ordered)
        |> State.report(
          :migrated,
          "inet_protocols",
          State.value(state, "inet_protocols"),
          "delivery.ip_versions = #{inspect(ordered)}, and the listener addresses."
        )
    end
  end

  defp source_address(state) do
    names = ["smtp_bind_address", "smtp_bind_address6"]
    state = State.handle(state, names)

    addresses =
      for name <- names,
          value = State.explicit(state, name),
          value not in [nil, ""],
          do: {name, value}

    Enum.reduce(addresses, state, fn {name, value}, state ->
      case Sovite.Net.parse_ip(value) do
        {:ok, ip} ->
          existing = State.get(state, "delivery", "source_address") || []

          state
          |> State.put("delivery", "source_address", existing ++ [to_string(:inet.ntoa(ip))])
          |> State.report_param(:migrated, name, "delivery.source_address")

        {:error, _} ->
          State.report_param(state, :attention, name, "Not an IP address. Not migrated.")
      end
    end)
  end

  ## Left over

  # Parameters that do nothing in Sovite, or say where Postfix keeps
  # its own files.
  @silent ~w(compatibility_level readme_directory html_directory manpage_directory sample_directory
             command_directory daemon_directory data_directory meta_directory shlib_directory
             queue_directory config_directory mail_owner setgid_group sendmail_path newaliases_path
             mailq_path biff append_dot_mydomain alias_database smtpd_tls_session_cache_database
             smtp_tls_session_cache_database smtpd_tls_session_cache_timeout
             smtp_tls_session_cache_timeout smtpd_tls_loglevel smtp_tls_loglevel tls_random_source
             maillog_file postlog_service_name syslog_name syslog_facility debug_peer_level
             debug_peer_list debugger_command mail_name inet_interfaces smtpd_tls_received_header
             smtp_tls_note_starttls_offer smtpd_sasl_local_domain broken_sasl_auth_clients
             smtpd_sasl_security_options smtpd_sasl_tls_security_options smtp_sasl_security_options
             smtp_sasl_tls_security_options smtp_sasl_mechanism_filter anvil_rate_time_unit
             smtpd_client_event_limit_exceptions smtpd_restriction_classes header_size_limit
             recipient_delimiter_extension smtp_tls_wrappermode tlsproxy_enforce_tls
             smtp_dns_support_level)

  @ignored %{
    "smtpd_banner" => "Sovite's greeting is fixed: 220 <server.hostname> ESMTP.",
    "smtpd_helo_required" => "Built in: Sovite always requires EHLO or HELO.",
    "smtpd_delay_reject" =>
      "Sovite refuses at the stage a check runs; see the [restrictions] notes.",
    "strict_rfc821_envelopes" => "Built in: Sovite only accepts addresses in angle brackets.",
    "smtpd_forbid_bare_newline" => "Built in: smtp.bare_line_endings = \"reject\".",
    "smtpd_forbid_unauth_pipelining" => "Built in: smtp.forbid_unauth_pipelining.",
    "smtpd_discard_ehlo_keywords" => "Sovite offers a fixed set of extensions.",
    "mailbox_size_limit" =>
      "Sovite does not limit Maildir sizes: use the mailbox server's quotas.",
    "unknown_local_recipient_reject_code" => "Sovite refuses unknown recipients with 550.",
    "unknown_virtual_mailbox_reject_code" => "Sovite refuses unknown recipients with 550.",
    "unknown_address_reject_code" => "Sovite refuses unknown recipients with 550.",
    "smtpd_reject_unlisted_recipient" => "Built in: unknown recipients are refused.",
    "local_recipient_maps" =>
      "Sovite accepts local recipients that have an alias, a mailbox, or are in domains.local_recipients.",
    "bounce_queue_lifetime" => "Sovite bounces bounces after queue.max_lifetime too.",
    "queue_run_delay" => "Sovite schedules each message's next attempt.",
    "notify_classes" =>
      "Sovite reports double bounces to bounce.double_bounce_recipient, if set.",
    "smtputf8_enable" => "Sovite supports SMTPUTF8.",
    "smtpd_sasl_authenticated_header" =>
      "Sovite's Received: field shows ESMTPSA, not the login name.",
    "disable_dns_lookups" => "Sovite always uses DNS.",
    "smtp_host_lookup" => "Sovite always uses DNS.",
    "lmtp_destination_recipient_limit" =>
      "Sovite sends each LMTP message once with all its recipients.",
    "virtual_destination_recipient_limit" => "Not needed in Sovite.",
    "local_destination_recipient_limit" => "Not needed in Sovite.",
    "virtual_minimum_uid" => "Sovite writes Maildirs as its own user.",
    "virtual_uid_maps" => "Sovite writes Maildirs as its own user.",
    "virtual_gid_maps" => "Sovite writes Maildirs as its own user."
  }

  @attention %{
    "header_checks" =>
      "Sovite has no header checks, so mail they refused now gets through: use a milter, such as Rspamd. Not migrated.",
    "body_checks" =>
      "Sovite has no body checks, so mail they refused now gets through: use a milter, such as Rspamd. Not migrated.",
    "smtpd_proxy_filter" =>
      "Before-queue content filters are not supported: use a milter, or an after-queue content filter (smtp.content_filter). Not migrated.",
    "fallback_transport" =>
      "Sovite has no fallback transport: unknown local users are refused. Not migrated.",
    "luser_relay" =>
      "Sovite has no catch-all for unknown local users: use a catch-all alias (@domain). Not migrated."
  }

  # master.cf services named after Postfix's own: their parameters are
  # not per-service settings.
  @standard_services ~w(smtp relay lmtp local virtual smtpd)

  @doc "The main.cf parameters nothing dealt with: reported, unless silent."
  def leftover(state) do
    service_names =
      for service <- state.services,
          service.type == "unix",
          service.command in ["smtp", "lmtp", "pipe"],
          service.name not in @standard_services,
          do: service.name

    state.main
    |> MainCf.names()
    |> Enum.reject(&MapSet.member?(state.handled, &1))
    |> Enum.reduce(state, fn name, state ->
      cond do
        name in @silent ->
          State.handle(state, name)

        Map.has_key?(@ignored, name) ->
          State.report_param(state, :ignored, name, Map.fetch!(@ignored, name))

        Map.has_key?(@attention, name) ->
          State.report_param(state, :attention, name, Map.fetch!(@attention, name))

        service = Enum.find(service_names, &String.starts_with?(name, &1 <> "_")) ->
          State.report_param(
            state,
            :ignored,
            name,
            "A setting of the master.cf service #{service}: Sovite's [delivery] settings apply to every destination."
          )

        true ->
          State.report_param(state, :attention, name, "Not migrated: Sovite has no equivalent.")
      end
    end)
  end
end
