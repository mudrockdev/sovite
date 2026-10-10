defmodule Sovite.Core.Postfix.Checks do
  @moduledoc false
  # smtpd_*_restrictions -> [restrictions], postscreen and the DNS lists
  # of reject_rbl_client & co. -> [screen], check_policy_service ->
  # policy checks, and check_*_access tables -> access rules in import.sh.

  alias Sovite.Abuse.DNSBL
  alias Sovite.Core.{PolicyService, Restrictions}
  alias Sovite.Core.Postfix.{Convert, MainCf, MasterCf, State, Table}

  # Postfix lists and Sovite stages, in evaluation order.
  @lists [
    {"smtpd_client_restrictions", :connect},
    {"smtpd_helo_restrictions", :helo},
    {"smtpd_sender_restrictions", :mail},
    {"smtpd_relay_restrictions", :rcpt},
    {"smtpd_recipient_restrictions", :rcpt},
    {"smtpd_data_restrictions", :data},
    {"smtpd_end_of_data_restrictions", :end_of_data}
  ]

  @renamed %{
    "permit_mynetworks" => "permit_trusted",
    "permit_sasl_authenticated" => "permit_authenticated",
    "permit" => "permit",
    "reject" => "reject",
    "defer" => "defer",
    "reject_unknown_recipient_domain" => "require_known_recipient_domain",
    "reject_unknown_sender_domain" => "require_known_sender_domain",
    "reject_non_fqdn_helo_hostname" => "require_fqdn_helo",
    "reject_non_fqdn_hostname" => "require_fqdn_helo",
    "reject_non_fqdn_sender" => "require_fqdn_sender",
    "reject_non_fqdn_recipient" => "require_fqdn_recipient",
    "reject_unknown_helo_hostname" => "require_known_helo",
    "reject_unknown_hostname" => "require_known_helo",
    "reject_unknown_reverse_client_hostname" => "require_reverse_hostname",
    "reject_unknown_client_hostname" => "require_fcrdns",
    "reject_unknown_client" => "require_fcrdns"
  }

  @built_in %{
    "reject_unauth_destination" =>
      "Built in: Sovite never relays for clients that are neither in smtp.trusted_networks nor authenticated.",
    "defer_unauth_destination" =>
      "Built in: Sovite never relays for clients that are neither in smtp.trusted_networks nor authenticated.",
    "reject_unlisted_recipient" =>
      "Built in: Sovite refuses unknown recipients of its domains at RCPT (aliases, mailboxes, domains.local_recipients).",
    "reject_invalid_helo_hostname" => "Built in: Sovite refuses EHLO names that are not valid.",
    "reject_invalid_hostname" => "Built in: Sovite refuses EHLO names that are not valid.",
    "reject_unauth_pipelining" => "Built in: smtp.forbid_unauth_pipelining (on by default).",
    "reject_sender_login_mismatch" => "Built in: auth.sender_check (on by default).",
    "reject_authenticated_sender_login_mismatch" =>
      "Built in: auth.sender_check (on by default).",
    "reject_known_sender_login_mismatch" => "Built in: auth.sender_check (on by default)."
  }

  @access %{
    "check_client_access" => {"client_access", "client"},
    "check_helo_access" => {"helo_access", "helo"},
    "check_sender_access" => {"sender_access", "sender"},
    "check_recipient_access" => {"recipient_access", "recipient"}
  }

  @with_argument ~w(check_reverse_client_hostname_access check_reverse_client_hostname_mx_access
                    check_reverse_client_hostname_ns_access check_reverse_client_hostname_a_access
                    check_client_mx_access check_client_ns_access check_client_a_access
                    check_helo_mx_access check_helo_ns_access check_helo_a_access
                    check_sender_mx_access check_sender_ns_access check_sender_a_access
                    check_recipient_mx_access check_recipient_ns_access check_recipient_a_access
                    check_ccert_access check_sasl_access check_etrn_access sleep
                    reject_rhsbl_client reject_rhsbl_reverse_client reject_rhsbl_recipient
                    permit_rhswl_client)

  @dns_checks ~w(reject_rbl_client reject_rhsbl_helo reject_rhsbl_sender permit_dnswl_client)

  ## Screen

  @doc "postscreen settings -> [screen], when master.cf runs postscreen."
  def screen(state) do
    names = Enum.filter(MainCf.names(state.main), &String.starts_with?(&1, "postscreen_"))
    postscreen = Enum.any?(state.services, &(&1.type == "inet" and &1.command == "postscreen"))

    state =
      state
      |> threshold()
      |> State.flag(:postscreen, postscreen)

    if postscreen do
      state
      |> dnsbl_sites()
      |> allow_threshold()
      |> greet()
      |> postscreen_rest(names)
    else
      names
      |> Enum.reject(&MapSet.member?(state.handled, &1))
      |> Enum.reduce(state, fn name, state ->
        State.report_param(
          state,
          :ignored,
          name,
          "master.cf does not run postscreen, so Postfix did not use this."
        )
      end)
    end
  end

  defp threshold(state) do
    with value when value != nil <- State.explicit(state, "postscreen_dnsbl_threshold"),
         {:ok, threshold} when threshold in 1..1000 <- Convert.integer(value) do
      state
      |> State.flag(:threshold, threshold)
      |> then(&if(threshold == 1, do: &1, else: State.put(&1, "screen", "threshold", threshold)))
      |> State.report_param(:migrated, "postscreen_dnsbl_threshold", "screen.threshold")
    else
      nil ->
        State.flag(state, :threshold, 1)

      _ ->
        state
        |> State.flag(:threshold, 1)
        |> State.report_param(
          :attention,
          "postscreen_dnsbl_threshold",
          "Not a threshold Sovite accepts (1 to 1000); not migrated."
        )
    end
  end

  defp dnsbl_sites(state) do
    case State.explicit(state, "postscreen_dnsbl_sites") do
      nil ->
        state

      value ->
        {state, problems} = Enum.reduce(MainCf.split(value), {state, []}, &add_site/2)

        message =
          Enum.join(
            ["[[screen.dnsbl]] lists."] ++
              Enum.reverse(problems) ++ dnsbl_action_note(state),
            " "
          )

        level =
          if problems == [] and dnsbl_action_note(state) == [], do: :migrated, else: :attention

        state
        |> State.handle("postscreen_dnsbl_action")
        |> State.report_param(level, "postscreen_dnsbl_sites", message)
    end
  end

  defp add_site(site, {state, problems}) do
    case dnsbl_site(site) do
      {:ok, list} -> {add_list(state, "screen.dnsbl", list), problems}
      {:error, message} -> {state, [message | problems]}
    end
  end

  defp dnsbl_action_note(state) do
    if State.value(state, "postscreen_dnsbl_action") == "ignore",
      do: [
        "postscreen_dnsbl_action is ignore, so Postfix only logged DNSBL results; Sovite refuses clients that reach screen.threshold. Remove the lists if that is not wanted."
      ],
      else: []
  end

  @doc """
  Parses a postscreen_dnsbl_sites entry: `zone`, `zone*weight`,
  `zone=127.0.0.2`, `zone=127.0.0.[2..11]*3`.
  """
  def dnsbl_site(site) do
    case Regex.run(~r/\A([^=*]+)(?:=([^*]+))?(?:\*(-?\d+))?\z/, site) do
      [_ | parts] ->
        [zone, codes, weight] = parts ++ List.duplicate("", 3 - length(parts))
        dns_list(zone, codes, if(weight == "", do: 1, else: String.to_integer(weight)), site)

      nil ->
        {:error, "#{site} is not a DNS list entry."}
    end
  end

  defp dns_list(zone, codes, weight, site) do
    codes = String.split(codes, ";", trim: true) |> rejoin_codes()

    cond do
      not Convert.domain?(zone) ->
        {:error, "#{site}: #{zone} is not a DNS zone."}

      weight not in -1000..1000 ->
        {:error, "#{site}: the weight must be from -1000 to 1000."}

      bad = Enum.find(codes, &match?({:error, _}, DNSBL.parse_code(&1))) ->
        {:error, "#{site}: #{bad} is not a reply code Sovite accepts."}

      true ->
        {:ok, %{zone: String.downcase(zone), codes: codes, weight: weight}}
    end
  end

  # "127.0.0.[2;3]" was split on ";" too: put octet lists back together.
  defp rejoin_codes(parts) do
    parts
    |> Enum.reduce([], fn
      part, [last | rest] ->
        if(open_bracket?(last), do: [last <> ";" <> part | rest], else: [part, last | rest])

      part, [] ->
        [part]
    end)
    |> Enum.reverse()
  end

  defp open_bracket?(text), do: length(String.split(text, "[")) > length(String.split(text, "]"))

  defp add_list(state, array, list) do
    exists =
      state
      |> State.tables(array)
      |> Enum.any?(fn {entries, _comment} ->
        List.keyfind(entries, "zone", 0) == {"zone", list.zone, nil} and
          (List.keyfind(entries, "codes", 0) || {"codes", [], nil}) == {"codes", list.codes, nil}
      end)

    entries =
      [{"zone", list.zone, nil}] ++
        if(list.weight == 1, do: [], else: [{"weight", list.weight, nil}]) ++
        if(list.codes == [], do: [], else: [{"codes", list.codes, nil}]) ++
        if(Map.has_key?(list, :check), do: [{"check", list.check, nil}], else: [])

    if exists, do: state, else: State.add_table(state, array, entries)
  end

  defp allow_threshold(state) do
    name =
      Enum.find(
        ["postscreen_dnsbl_allowlist_threshold", "postscreen_dnsbl_whitelist_threshold"],
        &State.set?(state, &1)
      )

    with name when name != nil <- name,
         value = State.value(state, name),
         {number, ""} <- Integer.parse(String.trim(value)) do
      cond do
        number == 0 ->
          State.report_param(
            state,
            :ignored,
            name,
            "0 turns allow-listing off; Sovite's screen.allow_threshold (default -1) only matters for lists with negative weights."
          )

        number in -1000..-1 ->
          state
          |> State.put("screen", "allow_threshold", number)
          |> State.report_param(:migrated, name, "screen.allow_threshold")

        true ->
          State.report_param(
            state,
            :attention,
            name,
            "Not a threshold Sovite accepts (-1000 to 0); not migrated."
          )
      end
    else
      nil -> state
      _ -> State.report_param(state, :attention, name, "Not a number; not migrated.")
    end
  end

  defp greet(state) do
    action = State.value(state, "postscreen_greet_action")
    state = State.handle(state, ["postscreen_greet_action", "postscreen_greet_wait"])

    cond do
      action in ["enforce", "drop"] ->
        case Convert.duration(State.value(state, "postscreen_greet_wait"), "s") do
          {:ok, delay} ->
            state
            |> State.put("screen", "greet_delay", delay)
            |> State.report(
              :migrated,
              "postscreen_greet_action",
              action,
              "screen.greet_delay = #{inspect(delay)} (postscreen_greet_wait): early talkers are refused."
            )

          _ ->
            State.report(
              state,
              :attention,
              "postscreen_greet_wait",
              State.value(state, "postscreen_greet_wait"),
              "Not a time Sovite accepts; set screen.greet_delay by hand."
            )
        end

      State.set?(state, "postscreen_greet_action") ->
        State.report(
          state,
          :ignored,
          "postscreen_greet_action",
          action,
          "Postfix did not act on early talkers; screen.greet_delay is left unset."
        )

      true ->
        state
    end
  end

  @postscreen_ignored ~w(postscreen_cache_map postscreen_cache_retention_time postscreen_cache_cleanup_interval
                         postscreen_dnsbl_ttl postscreen_dnsbl_min_ttl postscreen_dnsbl_max_ttl
                         postscreen_dnsbl_timeout postscreen_greet_banner postscreen_greet_ttl
                         postscreen_blacklist_action postscreen_denylist_action postscreen_watchdog_timeout
                         postscreen_post_queue_limit postscreen_pre_queue_limit postscreen_command_time_limit
                         postscreen_upstream_proxy_protocol postscreen_upstream_proxy_timeout
                         postscreen_use_tls postscreen_tls_security_level postscreen_enforce_tls
                         postscreen_expansion_filter postscreen_client_connection_count_limit)

  @postscreen_tests ~w(postscreen_bare_newline_enable postscreen_bare_newline_action postscreen_bare_newline_ttl
                       postscreen_non_smtp_command_enable postscreen_non_smtp_command_action
                       postscreen_non_smtp_command_ttl postscreen_pipelining_enable
                       postscreen_pipelining_action postscreen_pipelining_ttl postscreen_forbidden_commands
                       postscreen_disable_vrfy_command postscreen_discard_ehlo_keywords
                       postscreen_discard_ehlo_keyword_address_maps postscreen_command_count_limit
                       postscreen_command_filter)

  defp postscreen_rest(state, names) do
    Enum.reduce(names, state, fn name, state ->
      cond do
        MapSet.member?(state.handled, name) ->
          state

        name in @postscreen_ignored ->
          State.report_param(
            state,
            :ignored,
            name,
            "Not needed: Sovite's screen keeps its own cache, timeouts, and limits."
          )

        name in @postscreen_tests ->
          State.report_param(
            state,
            :ignored,
            name,
            "Sovite has no deep protocol tests after the greeting, but always refuses bare line endings (smtp.bare_line_endings), unauthorized pipelining, and HTTP or other non-SMTP commands."
          )

        name == "postscreen_access_list" ->
          postscreen_access(state)

        true ->
          State.report_param(
            state,
            :attention,
            name,
            "Not migrated: Sovite's screen has no equivalent."
          )
      end
    end)
  end

  defp postscreen_access(state) do
    other = Enum.reject(State.list(state, "postscreen_access_list"), &(&1 == "permit_mynetworks"))

    if other == [],
      do:
        State.report_param(
          state,
          :ignored,
          "postscreen_access_list",
          "Sovite's screen skips smtp.trusted_networks anyway."
        ),
      else:
        State.report_param(
          state,
          :attention,
          "postscreen_access_list",
          "Only permit_mynetworks has an equivalent (the screen skips smtp.trusted_networks). Not migrated: #{Enum.join(other, ", ")}."
        )
  end

  ## Restrictions

  @doc "The smtpd_*_restrictions lists -> [restrictions]."
  def restrictions(state) do
    delayed = Convert.yes?(State.value(state, "smtpd_delay_reject"))

    {lists, state} =
      Enum.map_reduce(@lists, state, fn {name, stage}, state ->
        if State.set?(state, name) do
          {checks, state} = translate(state, name, stage, State.list(state, name))
          checks = trim_permits(checks)
          {{name, target_stage(stage, checks, delayed), checks}, State.handle(state, name)}
        else
          {nil, state}
        end
      end)

    lists = Enum.reject(lists, &is_nil/1)

    state =
      Enum.reduce(lists, state, fn {name, stage, _checks}, state ->
        State.report_param(state, :migrated, name, "restrictions.#{stage}")
      end)

    Enum.reduce(Restrictions.stages(), state, fn stage, state ->
      parts = for {name, ^stage, checks} <- lists, checks != [], do: {name, checks}
      put_stage(state, stage, parts)
    end)
  end

  # Sovite runs connect and helo checks before AUTH. Postfix, with
  # smtpd_delay_reject = yes, ran them at RCPT, where
  # permit_sasl_authenticated works: such lists move to the mail stage.
  defp target_stage(stage, checks, true) when stage in [:connect, :helo] do
    if "permit_authenticated" in checks, do: :mail, else: stage
  end

  defp target_stage(stage, _checks, _delayed), do: stage

  defp put_stage(state, _stage, []), do: state

  defp put_stage(state, stage, parts) do
    names = Enum.map(parts, &elem(&1, 0))
    checks = parts |> Enum.flat_map(&elem(&1, 1)) |> Enum.uniq()

    comment =
      cond do
        stage == :mail and
            Enum.any?(names, &(&1 in ["smtpd_client_restrictions", "smtpd_helo_restrictions"])) ->
          "from #{Enum.join(names, ", ")}: Sovite runs connect and helo checks before AUTH, where permit_authenticated cannot work, so they run at MAIL, as Postfix ran them at RCPT (smtpd_delay_reject). Check the order"

        length(names) > 1 ->
          "#{Enum.join(names, " and ")} merged into one list (relay control is built in). Check the order"

        true ->
          nil
      end

    state = State.put(state, "restrictions", Atom.to_string(stage), checks, comment)

    if comment,
      do:
        State.report(
          state,
          :attention,
          Enum.join(names, " + "),
          nil,
          "restrictions.#{stage}: " <> comment <> "."
        ),
      else: state
  end

  # Translates one Postfix list. Returns Sovite checks.
  defp translate(state, name, stage, tokens) do
    {checks, state} = walk(tokens, %{state: state, name: name, stage: stage, checks: []})
    {Enum.reverse(checks), state}
  end

  defp walk([], context), do: {context.checks, context.state}

  defp walk(["warn_if_reject", next | rest], context) do
    rest = if takes_argument?(next), do: Enum.drop(rest, 1), else: rest
    message = "warn_if_reject is not supported; the check after it was dropped too."
    walk(rest, problem(context, "warn_if_reject #{next}", message))
  end

  defp walk([token, argument | rest], context) when token in @with_argument,
    do: walk(rest, problem(context, "#{token} #{argument}", "Sovite has no equivalent; dropped."))

  defp walk(["check_policy_service", argument | rest], context) do
    case policy(context.state, argument, context.name) do
      {:ok, check, state} ->
        walk(rest, add(%{context | state: state}, check))

      {:error, message, state} ->
        walk(
          rest,
          problem(%{context | state: state}, "check_policy_service #{argument}", message)
        )
    end
  end

  defp walk([token, argument | rest], context) when token in @dns_checks,
    do: walk(rest, dns_check(context, token, argument))

  defp walk([token, argument | rest], context) when is_map_key(@access, token) do
    {check, kind} = Map.fetch!(@access, token)
    state = access_table(context.state, kind, argument, context.name)
    walk(rest, add(%{context | state: state}, check))
  end

  defp walk([token | rest], context) do
    lower = String.downcase(token)

    cond do
      Map.has_key?(@renamed, lower) ->
        walk(rest, add(context, Map.fetch!(@renamed, lower)))

      Map.has_key?(@built_in, lower) ->
        walk(rest, built_in(context, lower))

      true ->
        walk(rest, problem(context, token, unsupported_message(context.state, lower)))
    end
  end

  defp takes_argument?(token),
    do:
      token in @with_argument or token in @dns_checks or Map.has_key?(@access, token) or
        token == "check_policy_service"

  defp unsupported_message(state, token) do
    cond do
      token in State.list(state, "smtpd_restriction_classes") ->
        "Restriction classes are not supported; dropped."

      token == "reject_unlisted_sender" ->
        "Sovite does not refuse unknown senders in its own domains; dropped. SPF and DMARC catch forged senders, and auth.sender_check covers authenticated clients."

      token == "permit_mx_backup" ->
        "Not supported: list backup MX domains in domains.relay. Dropped."

      token == "reject_plaintext_session" ->
        "Use require_tls on the listener instead. Dropped."

      String.starts_with?(token, "reject_unverified_") ->
        "Address verification is not supported; dropped."

      true ->
        "Sovite has no equivalent; dropped."
    end
  end

  defp add(context, check) do
    if Restrictions.allowed?(check, context.stage) do
      %{context | checks: [check | context.checks]}
    else
      problem(context, check, "#{check} cannot run at Sovite's #{context.stage} stage; dropped.")
    end
  end

  defp built_in(context, token) do
    key = {:built_in, token}

    state =
      if State.flag(context.state, key),
        do: context.state,
        else:
          context.state
          |> State.flag(key, true)
          |> State.report(:ignored, token, nil, Map.fetch!(@built_in, token))

    %{context | state: state}
  end

  defp problem(context, item, message) do
    %{context | state: State.report(context.state, :attention, context.name, item, message)}
  end

  defp dns_check(context, token, argument) do
    threshold = State.flag(context.state, :threshold) || 1

    case dnsbl_site(argument) do
      {:ok, list} ->
        {array, list} = dns_list_for(token, list, threshold)
        state = add_list(context.state, array, list)

        message =
          "-> [[#{array}]] #{list.zone} with weight #{list.weight}. The screen runs on listeners with screen = true (smtp ones) for clients outside smtp.trusted_networks: DNSBLs at connect, RHSBLs at EHLO and MAIL." <>
            if(token == "permit_dnswl_client",
              do: " A listed client skips the RHSBLs and greylisting, not the restrictions.",
              else: ""
            )

        %{
          context
          | state: State.report(state, :migrated, context.name, "#{token} #{argument}", message)
        }

      {:error, message} ->
        problem(context, "#{token} #{argument}", message <> " Dropped.")
    end
  end

  # A DNS list check of the restrictions as a screen list: DNSBLs refuse
  # at the threshold, DNSWLs allow-list.
  defp dns_list_for("reject_rbl_client", list, threshold),
    do: {"screen.dnsbl", %{list | weight: threshold}}

  defp dns_list_for("permit_dnswl_client", list, threshold),
    do: {"screen.dnsbl", %{list | weight: -threshold}}

  defp dns_list_for("reject_rhsbl_helo", list, threshold),
    do: {"screen.rhsbl", Map.merge(list, %{weight: threshold, check: ["helo"]})}

  defp dns_list_for(_reject_rhsbl_sender, list, threshold),
    do: {"screen.rhsbl", Map.merge(list, %{weight: threshold, check: ["sender"]})}

  # Trailing permits only end their own list in Postfix: they do nothing.
  defp trim_permits(checks) do
    checks
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 in ["permit", "permit_trusted", "permit_authenticated"]))
    |> Enum.reverse()
  end

  ## Policy servers

  @doc """
  The Sovite check for `check_policy_service ADDRESS`: unix sockets of
  master.cf spawn services become `spawn:` commands.
  """
  def policy(state, argument, setting) do
    [address | attributes] = argument |> MainCf.ungroup() |> MainCf.split()
    state = policy_attributes(state, attributes, setting)

    {address, state} =
      case String.split(address, ":", parts: 2) do
        ["unix", path] -> unix_policy(state, path, setting)
        ["inet", rest] -> {"inet:" <> rest, state}
        [path] -> unix_policy(state, path, setting)
        [_host, _port] -> {"inet:" <> address, state}
      end

    if PolicyService.valid_address?(address),
      do: {:ok, "check_policy_service " <> address, state},
      else: {:error, "#{address} is not a policy server address Sovite accepts; dropped.", state}
  end

  defp unix_policy(state, path, setting) do
    service = State.service(state, Path.basename(path), ["unix"])

    cond do
      service != nil and service.command == "spawn" and Path.type(path) != :absolute ->
        spawn_policy(state, service, setting)

      Path.type(path) == :absolute ->
        {"unix:" <> path, state}

      true ->
        absolute = State.queue_path(state, path)

        {"unix:" <> absolute,
         State.report(
           state,
           :attention,
           setting,
           "check_policy_service unix:#{path}",
           "The policy server's socket #{absolute} is inside Postfix's queue directory, which goes away with Postfix. Move it, give the Sovite user access, and change the address in [restrictions]."
         )}
    end
  end

  defp spawn_policy(state, service, setting) do
    attributes = MasterCf.attributes(service.args)
    argv = Map.get(attributes, "argv", [])
    program = List.first(argv, "")

    notes =
      [
        attributes["user"] &&
          "user=#{attributes["user"]} is not supported: Sovite runs the program as the Sovite user.",
        Enum.any?(argv, &String.match?(&1, ~r/\s/)) &&
          "An argument contains whitespace, which spawn: addresses cannot express.",
        String.contains?(Path.basename(program), "spf") &&
          "Sovite checks SPF itself ([spf], on by default, with the result in Authentication-Results). To refuse SPF failures as policyd-spf did, set [spf] reject_fail = true and drop this check."
      ]
      |> Enum.filter(&is_binary/1)

    state =
      state
      |> State.handle(
        Enum.filter(MainCf.names(state.main), &String.starts_with?(&1, service.name <> "_"))
      )
      |> State.report(
        :attention,
        setting,
        "check_policy_service unix:private/#{service.name}",
        "-> check_policy_service spawn:#{Enum.join(argv, " ")} (the master.cf spawn service #{service.name}: Sovite starts the program for each check). " <>
          Enum.join(notes, " ")
      )

    {"spawn:" <> Enum.join(argv, " "), state}
  end

  defp policy_attributes(state, attributes, setting) do
    Enum.reduce(attributes, state, fn attribute, state ->
      case String.split(attribute, "=", parts: 2) do
        ["timeout", value] ->
          policy_setting(state, "timeout", Convert.duration(value, "s"), attribute, setting)

        ["default_action", value] ->
          policy_setting(state, "default_action", default_action(value), attribute, setting)

        _ ->
          State.report(
            state,
            :attention,
            setting,
            attribute,
            "Not supported for policy servers; dropped."
          )
      end
    end)
  end

  defp default_action(value) do
    case Sovite.Policy.parse_action(value) do
      {:ok, _} -> {:ok, value}
      {:error, _} -> :error
    end
  end

  defp policy_setting(state, key, {:ok, value}, attribute, setting) do
    state
    |> State.put("policy", key, value)
    |> State.report(
      :migrated,
      setting,
      attribute,
      "policy.#{key} (it applies to every policy server in Sovite)"
    )
  end

  defp policy_setting(state, _key, _error, attribute, setting),
    do:
      State.report(state, :attention, setting, attribute, "Not a value Sovite accepts; dropped.")

  ## Access tables

  defp access_table(state, kind, table, setting) do
    case Table.read(table, state.read) do
      {:ok, entries} ->
        {commands, problems} =
          access_commands(kind, entries, State.flag(state, {:access, kind}) || MapSet.new())

        seen = MapSet.new(commands, fn [_, _, _, key | _] -> key end)

        state
        |> State.flag(
          {:access, kind},
          MapSet.union(State.flag(state, {:access, kind}) || MapSet.new(), seen)
        )
        |> State.commands("#{setting}: check_#{kind}_access #{table}", commands)
        |> State.table_report(
          setting,
          "check_#{kind}_access #{table}",
          length(commands),
          problems,
          "access rules (#{kind})"
        )

      {:error, reason} ->
        State.report(
          state,
          :attention,
          setting,
          "check_#{kind}_access #{table}",
          Table.describe_error(reason) <>
            ". The #{kind}_access check is in place; add the rules with sovitectl access set."
        )
    end
  end

  defp access_commands(kind, entries, seen) do
    {commands, problems, _seen} =
      Enum.reduce(entries, {[], [], seen}, &access_entry(kind, &1, &2))

    {Enum.reverse(commands), Enum.reverse(problems)}
  end

  defp access_entry(kind, {key, value}, {commands, problems, seen}) do
    with {:ok, pattern} <- access_key(kind, key),
         :ok <- unseen(seen, pattern),
         {:ok, action, text} <- access_action(value) do
      command =
        ["access", "set", kind, pattern, action] ++ if(text in [nil, ""], do: [], else: [text])

      {[command | commands], problems, MapSet.put(seen, pattern)}
    else
      {:error, message} -> {commands, [{key, message} | problems], seen}
    end
  end

  defp unseen(seen, pattern) do
    if MapSet.member?(seen, pattern),
      do: {:error, "an earlier table has this key already"},
      else: :ok
  end

  @doc "Checks an access table key of `kind`, as Sovite matches it."
  def access_key("client", key) do
    cond do
      key =~ ~r/\A\d{1,3}(\.\d{1,3}){0,2}\z/ and octets?(key) ->
        {:ok, key}

      match?({:ok, _}, Sovite.Net.parse_ip(key)) ->
        {:ok, ip} = Sovite.Net.parse_ip(key)
        {:ok, ip |> Sovite.Net.normalize() |> :inet.ntoa() |> to_string()}

      true ->
        {:error,
         "Sovite matches client addresses and IPv4 networks (192.0.2, 192.0), not host names or IPv6 prefixes"}
    end
  end

  def access_key("helo", key) do
    if Convert.domain?(String.trim_leading(key, ".")) or Sovite.Validators.address_literal?(key),
      do: {:ok, key},
      else: {:error, "not a host name, .domain, or address literal"}
  end

  def access_key(kind, "<>") when kind == "sender", do: {:ok, "<>"}

  def access_key(_kind, key) do
    local = String.trim_trailing(key, "@")

    cond do
      Convert.form?(key, [:address, :domain, :subdomains]) -> {:ok, key}
      String.ends_with?(key, "@") and Sovite.Validators.local_part?(local) -> {:ok, key}
      true -> {:error, "not an address, domain, .domain, or user@"}
    end
  end

  defp octets?(key), do: key |> String.split(".") |> Enum.all?(&(String.to_integer(&1) <= 255))

  @doc "Translates a Postfix access(5) action."
  def access_action(value) do
    {word, text} =
      case String.split(String.trim(value), ~r/\s+/, parts: 2) do
        [word, text] -> {word, text}
        [word] -> {word, nil}
      end

    case String.upcase(word) do
      ok when ok in ["OK", "PERMIT"] -> {:ok, "ACCEPT", nil}
      "DUNNO" -> {:ok, "CONTINUE", nil}
      "REJECT" -> {:ok, "REJECT", text}
      "DEFER" -> {:ok, "DEFER", text}
      action when action in ["HOLD", "DISCARD", "WARN"] -> {:ok, action, text}
      code -> code_action(code, text, value)
    end
  end

  defp code_action(code, text, value) do
    if code =~ ~r/\A[45]\d\d\z/,
      do: {:ok, code, text},
      else:
        {:error,
         "#{String.split(value) |> hd()} is not an action Sovite has (ACCEPT, CONTINUE, REJECT, DEFER, DISCARD, HOLD, WARN, or a 4NN/5NN reply)"}
  end
end
