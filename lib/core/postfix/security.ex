defmodule Sovite.Core.Postfix.Security do
  @moduledoc false
  # main.cf: server TLS -> [tls], SASL -> [auth], client TLS and the
  # relay host -> [delivery].

  alias Sovite.Core.Postfix.{Convert, Imports, MasterCf, State, Table}
  alias Sovite.Core.Transport

  ## Server TLS

  # Settings Sovite fixes to BCP 195 (RFC 9325).
  @fixed_tls ~w(smtpd_tls_ciphers smtpd_tls_mandatory_ciphers smtpd_tls_exclude_ciphers
                smtpd_tls_mandatory_exclude_ciphers smtpd_tls_dh1024_param_file
                smtpd_tls_dh512_param_file smtpd_tls_eecdh_grade tls_preempt_cipherlist
                tls_ssl_options tls_high_cipherlist tls_medium_cipherlist tls_low_cipherlist
                tls_export_cipherlist tls_null_cipherlist tls_eecdh_auto_curves
                tls_eecdh_strong_curve tls_eecdh_ultra_curve tls_ffdhe_auto_groups
                smtp_tls_ciphers smtp_tls_mandatory_ciphers smtp_tls_exclude_ciphers
                smtp_tls_mandatory_exclude_ciphers smtp_tls_protocols smtp_tls_mandatory_protocols)

  @client_certificates ~w(smtpd_tls_ask_ccert smtpd_tls_req_ccert smtpd_tls_ccert_verifydepth
                          smtpd_tls_CAfile smtpd_tls_CApath relay_clientcerts
                          smtpd_tls_fingerprint_digest)

  @doc """
  The server certificates -> [[tls.certificate]], the TLS versions ->
  tls.min_version. Sets the :tls flag the listeners need.
  """
  def tls(state) do
    state
    |> certificates()
    |> min_version()
    |> security_level()
    |> auth_only()
    |> fixed(
      @fixed_tls,
      "Sovite's TLS settings are fixed to BCP 195: TLS 1.2 and 1.3, forward-secret AEAD cipher suites."
    )
    |> client_certificates()
  end

  defp certificates(state) do
    pairs =
      if State.set?(state, "smtpd_tls_chain_files"),
        do: chain_files(state),
        else: certificate_files(state)

    state =
      state
      |> State.handle(~w(smtpd_tls_chain_files smtpd_tls_cert_file smtpd_tls_key_file
                         smtpd_tls_eccert_file smtpd_tls_eckey_file smtpd_tls_dcert_file
                         smtpd_tls_dkey_file))
      |> State.flag(:plaintext, false)

    {state, added} =
      Enum.reduce(pairs, {state, 0}, fn
        {:ok, setting, cert, key}, {state, added} ->
          state =
            state
            |> State.add_table("tls.certificate", [
              {"cert_file", cert, nil},
              {"key_file", key, nil}
            ])
            |> State.report(
              :migrated,
              setting,
              State.explicit(state, setting),
              "[[tls.certificate]] cert_file = #{inspect(cert)}, key_file = #{inspect(key)}."
            )

          {state, added + 1}

        {:error, setting, message}, {state, added} ->
          {State.report(state, :attention, setting, State.explicit(state, setting), message),
           added}
      end)

    state = State.flag(state, :tls, added > 0)

    if added > 0,
      do:
        State.report(
          state,
          :attention,
          "TLS keys",
          nil,
          "Sovite reads the certificate and key files as its own user: give it read access to the keys (Postfix read them as root)."
        ),
      else: state
  end

  defp certificate_files(state) do
    [
      {"smtpd_tls_cert_file", "smtpd_tls_key_file"},
      {"smtpd_tls_eccert_file", "smtpd_tls_eckey_file"},
      {"smtpd_tls_dcert_file", "smtpd_tls_dkey_file"}
    ]
    |> Enum.flat_map(fn {cert_name, key_name} ->
      cert = State.value(state, cert_name)
      key = State.value(state, key_name)

      cond do
        cert in ["", "none"] ->
          []

        cert_name == "smtpd_tls_dcert_file" ->
          [{:error, cert_name, "DSA certificates are not supported. Not migrated."}]

        true ->
          [pair(cert_name, cert, if(key == "", do: cert, else: key))]
      end
    end)
  end

  defp pair(setting, cert, key) do
    if Path.type(cert) == :absolute and Path.type(key) == :absolute,
      do: {:ok, setting, cert, key},
      else:
        {:error, setting, "Sovite needs absolute paths. Not migrated: add a [[tls.certificate]]."}
  end

  # smtpd_tls_chain_files: files with a key and its certificates, or a
  # key file followed by its certificate files.
  defp chain_files(state) do
    {pairs, pending} =
      state
      |> State.list("smtpd_tls_chain_files")
      |> Enum.reduce({[], nil}, fn file, {pairs, pending} ->
        case pem_kinds(state, file) do
          {true, true} ->
            {[pair("smtpd_tls_chain_files", file, file) | flush(pairs, pending)], nil}

          {true, false} ->
            {flush(pairs, pending), file}

          {false, true} when pending != nil ->
            {[pair("smtpd_tls_chain_files", file, pending) | pairs], nil}

          _ ->
            {[
               {:error, "smtpd_tls_chain_files",
                "#{file}: cannot tell what it holds. Add a [[tls.certificate]] for it."}
               | pairs
             ], pending}
        end
      end)

    pairs |> flush(pending) |> Enum.reverse()
  end

  defp flush(pairs, nil), do: pairs

  defp flush(pairs, key),
    do: [
      {:error, "smtpd_tls_chain_files", "#{key}: a key without a certificate after it."} | pairs
    ]

  # Whether a PEM file holds a private key, and a certificate.
  defp pem_kinds(state, file) do
    case state.read.(file) do
      {:ok, pem} ->
        {String.contains?(pem, "PRIVATE KEY-----"), String.contains?(pem, "BEGIN CERTIFICATE")}

      {:error, _} ->
        :unreadable
    end
  end

  defp min_version(state) do
    state = State.handle(state, ["smtpd_tls_protocols", "smtpd_tls_mandatory_protocols"])

    case State.explicit(state, "smtpd_tls_protocols") do
      nil ->
        mandatory_note(state)

      value ->
        case Convert.min_tls(value) do
          {:ok, "TLSv1.3"} ->
            state
            |> State.put("tls", "min_version", "1.3")
            |> State.report_param(:migrated, "smtpd_tls_protocols", "tls.min_version = \"1.3\".")
            |> mandatory_note()

          {:ok, _} ->
            state
            |> State.report_param(
              :ignored,
              "smtpd_tls_protocols",
              "Sovite only enables TLS 1.2 and 1.3."
            )
            |> mandatory_note()

          :error ->
            State.report_param(
              state,
              :attention,
              "smtpd_tls_protocols",
              "Not a protocol list Sovite understands. Set tls.min_version by hand."
            )
        end
    end
  end

  defp mandatory_note(state) do
    if State.set?(state, "smtpd_tls_mandatory_protocols"),
      do:
        State.report_param(
          state,
          :migrated,
          "smtpd_tls_mandatory_protocols",
          "Listeners that require TLS get tls_min_version = \"1.3\" when this allows only TLS 1.3; Sovite never allows less than TLS 1.2."
        ),
      else: state
  end

  defp security_level(state) do
    level =
      cond do
        State.set?(state, "smtpd_tls_security_level") ->
          State.value(state, "smtpd_tls_security_level")

        Convert.yes?(State.explicit(state, "smtpd_enforce_tls")) ->
          "encrypt"

        Convert.yes?(State.explicit(state, "smtpd_use_tls")) ->
          "may"

        true ->
          nil
      end

    state =
      State.handle(state, ["smtpd_tls_security_level", "smtpd_enforce_tls", "smtpd_use_tls"])

    case {level, State.flag(state, :tls)} do
      {nil, _} ->
        state

      {"encrypt", _} ->
        State.report(
          state,
          :migrated,
          "smtpd_tls_security_level",
          level,
          "require_tls on the listeners."
        )

      {"none", true} ->
        State.report(
          state,
          :attention,
          "smtpd_tls_security_level",
          level,
          "Postfix did not offer STARTTLS. Sovite offers it whenever a certificate is configured."
        )

      {_level, _tls} ->
        State.report(
          state,
          :ignored,
          "smtpd_tls_security_level",
          level,
          "Sovite offers STARTTLS whenever a certificate is configured."
        )
    end
  end

  defp auth_only(state) do
    case State.explicit(state, "smtpd_tls_auth_only") do
      nil ->
        state

      value ->
        if Convert.no?(value),
          do:
            State.report_param(
              state,
              :attention,
              "smtpd_tls_auth_only",
              "Postfix offered AUTH without TLS. Sovite only offers it over TLS unless auth.plaintext = true, which sends passwords in the clear: not migrated."
            ),
          else:
            State.report_param(
              state,
              :ignored,
              "smtpd_tls_auth_only",
              "Sovite only offers AUTH over TLS anyway."
            )
    end
  end

  defp client_certificates(state) do
    Enum.reduce(@client_certificates, state, fn name, state ->
      cond do
        not State.set?(state, name) ->
          state

        name in ["smtpd_tls_ask_ccert", "smtpd_tls_req_ccert"] and
            Convert.yes?(State.value(state, name)) ->
          State.report_param(
            state,
            :attention,
            name,
            "Client certificates are not supported. Not migrated."
          )

        true ->
          State.report_param(state, :ignored, name, "Client certificates are not supported.")
      end
    end)
  end

  defp fixed(state, names, message) do
    Enum.reduce(names, state, fn name, state ->
      if State.set?(state, name),
        do: State.report_param(state, :ignored, name, message),
        else: state
    end)
  end

  ## SASL

  @doc "smtpd_sasl_* -> [auth]."
  def auth(state) do
    state = State.handle(state, ["smtpd_sasl_auth_enable", "smtpd_sasl_type", "smtpd_sasl_path"])

    cond do
      not sasl?(state) ->
        unused_sasl(state)

      State.value(state, "smtpd_sasl_type") == "dovecot" ->
        dovecot(state, State.value(state, "smtpd_sasl_path"))

      true ->
        State.report(
          state,
          :attention,
          "smtpd_sasl_type",
          State.value(state, "smtpd_sasl_type"),
          "Cyrus SASL is not supported, so auth.backend is Sovite's database: add the users with sovitectl user add, or use the file, ldap, or dovecot backend ([auth])."
        )
    end
  end

  defp unused_sasl(state) do
    Enum.reduce(["smtpd_sasl_type", "smtpd_sasl_path"], state, fn name, state ->
      if State.set?(state, name),
        do: State.report_param(state, :ignored, name, "No service offers AUTH."),
        else: state
    end)
  end

  # Whether any smtpd service offers AUTH: main.cf, -o overrides, or a
  # submission service (which always does in Sovite).
  defp sasl?(state) do
    main = Convert.yes?(State.value(state, "smtpd_sasl_auth_enable"))

    Enum.any?(state.services, fn service ->
      service.type == "inet" and service.command == "smtpd" and
        (service.name in ["submission", "submissions", "smtps"] or
           case MasterCf.option(service, "smtpd_sasl_auth_enable") do
             nil -> main
             value -> Convert.yes?(State.expand(state, value))
           end)
    end)
  end

  defp dovecot(state, path) do
    socket =
      case String.split(path, ":", parts: 2) do
        ["inet", address] -> address
        _ -> State.queue_path(state, path)
      end

    in_queue = String.starts_with?(socket, state.queue_directory <> "/")
    comment = if in_queue, do: "inside Postfix's queue directory: move it, see report.txt"

    state =
      state
      |> State.put("auth", "backend", "dovecot")
      |> State.put("auth.dovecot", "socket", socket, comment)

    if in_queue,
      do:
        State.report(
          state,
          :attention,
          "smtpd_sasl_path",
          path,
          "auth.dovecot.socket = #{inspect(socket)} is inside Postfix's queue directory, which goes away with Postfix. In Dovecot's 10-master.conf, give Sovite its own listener (service auth { unix_listener auth-client { mode = 0660, user = sovite } }) and set auth.dovecot.socket = \"/run/dovecot/auth-client\"."
        ),
      else:
        State.report(
          state,
          :migrated,
          "smtpd_sasl_path",
          path,
          "auth.backend = \"dovecot\", auth.dovecot.socket = #{inspect(socket)}. The Sovite user needs access to it."
        )
  end

  ## Client TLS

  @levels %{
    "none" => "none",
    "may" => "may",
    "encrypt" => "encrypt",
    "dane" => "dane",
    "dane-only" => "dane",
    "verify" => "verify",
    "secure" => "verify"
  }

  @doc "smtp_tls_* -> delivery.tls, delivery.tls_policy, delivery.tls_ca_file."
  def client_tls(state) do
    state
    |> client_level()
    |> tls_policy()
    |> ca_file()
  end

  defp client_level(state) do
    level = client_level_value(state)
    state = State.handle(state, ["smtp_tls_security_level", "smtp_enforce_tls", "smtp_use_tls"])
    client_level(state, level)
  end

  # smtp_tls_security_level, or the obsolete parameters before it.
  defp client_level_value(state) do
    cond do
      State.set?(state, "smtp_tls_security_level") ->
        State.value(state, "smtp_tls_security_level")

      Convert.yes?(State.explicit(state, "smtp_enforce_tls")) ->
        "encrypt"

      Convert.yes?(State.explicit(state, "smtp_use_tls")) ->
        "may"

      true ->
        nil
    end
  end

  defp client_level(state, level) do
    case level do
      nil ->
        State.report(
          state,
          :ignored,
          "smtp_tls_security_level",
          nil,
          "Postfix sent mail without TLS. Sovite's delivery.tls defaults to dane: opportunistic TLS, verified with DANE where DNSSEC allows."
        )

      level when level in ["may", "dane"] ->
        State.report(
          state,
          :migrated,
          "smtp_tls_security_level",
          level,
          "Sovite's default delivery.tls = \"dane\": opportunistic TLS, verified with DANE when a validating resolver is used ([dns])."
        )

      "dane-only" ->
        state
        |> State.put(
          "delivery",
          "tls",
          "dane",
          "Postfix used dane-only, which requires DANE; Sovite's dane falls back to opportunistic TLS"
        )
        |> State.report(
          :attention,
          "smtp_tls_security_level",
          level,
          "delivery.tls = \"dane\": Sovite has no dane-only, so hosts without TLSA records get opportunistic TLS."
        )

      level ->
        case Map.fetch(@levels, level) do
          {:ok, sovite} ->
            state
            |> State.put("delivery", "tls", sovite)
            |> State.report(
              :migrated,
              "smtp_tls_security_level",
              level,
              "delivery.tls = #{inspect(sovite)}."
            )

          :error ->
            State.report(
              state,
              :attention,
              "smtp_tls_security_level",
              level,
              "Sovite has no such level. Set delivery.tls by hand."
            )
        end
    end
  end

  defp tls_policy(state) do
    state = State.handle(state, "smtp_tls_policy_maps")

    {pairs, problems} =
      state
      |> State.list("smtp_tls_policy_maps")
      |> Enum.reduce({[], []}, fn table, {pairs, problems} ->
        case Table.read(table, state.read) do
          {:ok, entries} ->
            Enum.reduce(entries, {pairs, problems}, &policy_entry/2)

          {:error, reason} ->
            {pairs, [{table, Table.describe_error(reason)} | problems]}
        end
      end)

    pairs = pairs |> Enum.reverse() |> Enum.uniq_by(&elem(&1, 0))

    state =
      if pairs == [],
        do: state,
        else: State.put(state, "delivery", "tls_policy", {:inline, pairs})

    cond do
      not State.set?(state, "smtp_tls_policy_maps") ->
        state

      problems == [] ->
        State.report_param(
          state,
          :migrated,
          "smtp_tls_policy_maps",
          "delivery.tls_policy (#{length(pairs)} destinations)."
        )

      true ->
        State.report_param(
          state,
          :attention,
          "smtp_tls_policy_maps",
          "delivery.tls_policy (#{length(pairs)} destinations). Not migrated: " <>
            Enum.map_join(Enum.reverse(problems), "; ", fn {key, message} ->
              "#{key}: #{message}"
            end) <> "."
        )
    end
  end

  # Keys are domains, or "[host]" and "[host]:port" of next hops: Sovite
  # matches the host name, or an address literal.
  defp policy_entry({key, value}, {pairs, problems}) do
    [level | _attributes] = String.split(value)

    destination =
      case Transport.parse_host(key, 25) do
        {:ok, %{host: host}} -> {:ok, host}
        :error -> :error
      end

    case {destination, Map.fetch(@levels, String.downcase(level))} do
      {{:ok, host}, {:ok, sovite}} ->
        {[{host, sovite} | pairs], problems}

      {:error, _} ->
        {pairs, [{key, "not a domain or [host]"} | problems]}

      {_, :error} ->
        {pairs, [{key, "#{level} is not a level Sovite has"} | problems]}
    end
  end

  defp ca_file(state) do
    state = State.handle(state, ["smtp_tls_CAfile", "smtp_tls_CApath"])

    state =
      case State.explicit(state, "smtp_tls_CAfile") do
        nil ->
          state

        "" ->
          state

        path ->
          if Path.type(path) == :absolute,
            do:
              state
              |> State.put("delivery", "tls_ca_file", path)
              |> State.report_param(:migrated, "smtp_tls_CAfile", "delivery.tls_ca_file"),
            else:
              State.report_param(
                state,
                :attention,
                "smtp_tls_CAfile",
                "Not an absolute path. Not migrated."
              )
      end

    case State.explicit(state, "smtp_tls_CApath") do
      nil ->
        state

      path when path in ["", "/etc/ssl/certs", "/etc/pki/tls/certs"] ->
        State.report_param(state, :ignored, "smtp_tls_CApath", "Sovite uses the system's CAs.")

      _path ->
        State.report_param(
          state,
          :attention,
          "smtp_tls_CApath",
          "CA directories are not supported: put the CAs in one PEM file for delivery.tls_ca_file."
        )
    end
  end

  ## Relay host

  @doc """
  relayhost -> delivery.relayhost, with the login from
  smtp_sasl_password_maps.
  """
  def relayhost(state) do
    state = State.handle(state, ["relayhost", "smtp_sasl_auth_enable"])

    case State.list(state, "relayhost") do
      [] ->
        state

      [relayhost | others] ->
        relayhost(state, relayhost, others)
    end
  end

  defp relayhost(state, relayhost, others) do
    case Transport.parse_host(relayhost, 25) do
      {:ok, host} ->
        message =
          if others == [],
            do: "delivery.relayhost.",
            else:
              "delivery.relayhost. Sovite has one relay host: #{Enum.join(others, ", ")} were left out."

        state
        |> State.put("delivery", "relayhost", relayhost)
        |> State.report_param(State.level(others), "relayhost", message)
        |> relay_login(relayhost, host)

      :error ->
        State.report_param(
          state,
          :attention,
          "relayhost",
          "Not a relay host Sovite accepts. Not migrated."
        )
    end
  end

  # Postfix looks up the next hop as written, then the bare host name.
  defp relay_login(state, relayhost, host) do
    if Convert.yes?(State.value(state, "smtp_sasl_auth_enable")) do
      passwords = Imports.passwords(state)
      bare = host.host |> String.trim_leading("[") |> String.trim_trailing("]")
      key = Enum.find([relayhost, bare], &Map.has_key?(passwords, &1))

      case key && passwords[key] do
        {username, password} ->
          state
          |> State.flag({:password_used, key}, true)
          |> State.put("delivery", "relayhost_username", username)
          |> State.put("delivery", "relayhost_password", password)
          |> State.report(
            :attention,
            "smtp_sasl_password_maps",
            key,
            "delivery.relayhost_username and relayhost_password: the password is now in sovite.toml, so keep the file readable by root and the Sovite user only."
          )

        nil ->
          State.report(
            state,
            :attention,
            "smtp_sasl_auth_enable",
            "yes",
            "No login for #{relayhost} in smtp_sasl_password_maps. Set delivery.relayhost_username and relayhost_password by hand."
          )
      end
    else
      state
    end
  end
end
