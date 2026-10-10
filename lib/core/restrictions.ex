defmodule Sovite.Core.Restrictions do
  @moduledoc """
  Restriction chains (`[restrictions]`): lists of checks run at each
  stage of an SMTP session.

  Each stage's list runs in order until a check decides: `permit` ends
  the list, a rejection ends the session's request. Restrictions only add
  checks: relay control and recipient validation always apply, so no
  restriction can make Sovite an open relay.

  ## Checks

  | Check | Stages | Effect |
  |---|---|---|
  | `permit`, `reject`, `defer` | all | Accept, `554 5.7.1`, or `450 4.7.1`. |
  | `permit_trusted` | all | Accept clients in `smtp.trusted_networks`. |
  | `permit_authenticated` | all | Accept clients that logged in. |
  | `client_access` | all | The access rules for the client IP address. |
  | `helo_access` | from `helo` | The access rules for the `EHLO` name. |
  | `sender_access` | from `mail` | The access rules for the sender address. |
  | `recipient_access` | `rcpt` | The access rules for the recipient address. |
  | `require_fqdn_helo` | from `helo` | `504` unless the name has a dot or is an address literal. |
  | `require_fqdn_sender` / `require_fqdn_recipient` | from `mail` / `rcpt` | `504` unless the domain has a dot. |
  | `require_known_sender_domain` / `require_known_recipient_domain` | from `mail` / `rcpt` | `550` if the domain has no MX or address records, or a Null MX; `450` when DNS fails. |
  | `require_reverse_hostname` | all | `550 5.7.25` unless the client address has a reverse DNS (PTR) name. |
  | `require_fcrdns` | all | `550 5.7.25` unless that name also resolves back to the client address (forward-confirmed reverse DNS). Stricter. |
  | `reject_forged_helo` | from `helo` | `550` if the `EHLO` name is this server's host name or one of its local domains, `localhost`, or an address literal other than the client's address. |
  | `require_known_helo` | from `helo` | `550` unless the `EHLO` name has address or MX records. Address literals pass. |
  | `require_matching_helo` | from `helo` | `550` unless the `EHLO` name resolves to the client address, or is its address literal. Strictest. |
  | `check_policy_service ADDRESS` | all | Ask a Postfix policy server, see `Sovite.Core.PolicyService`. |

  The DNS checks reply `450` (`4.7.25` or `4.7.1`) when DNS fails, so a
  client is never refused for a temporary problem.

  Checks whose information is not known yet are skipped: a `helo_access`
  in the `mail` stage of a client that sent no `EHLO` does nothing.

  ## Access rules

  Access rules live in the database (`sovitectl access`). A rule matches
  a pattern and has an action:

    * `ACCEPT` - accept, ending the list.
    * `CONTINUE` - as if no rule matched: go on with the next check.
    * `REJECT [text]` - `554 5.7.1`.
    * `DEFER [text]` - `450 4.7.1`.
    * `4NN [x.y.z] text` / `5NN [x.y.z] text` - that reply.
    * `DISCARD [text]` - accept, then silently drop the message. Ends the
      list.
    * `HOLD [text]` - accept, and put the message in the hold queue.
    * `WARN text` - log, and go on.

  Patterns tried, in order:

    * client: the IP address, then for IPv4 the networks `192.0.2`,
      `192.0`, `192`.
    * `EHLO` names and domains: the name, then each parent domain as
      `.example.com` (subdomains only) and `example.com` (the domain and
      its subdomains).
    * addresses: the address, the address without its extension
      (`routing.extension_delimiter`), the domain patterns as above, then
      `user@` (any domain). The null sender is `<>`.
  """

  alias Sovite.Abuse.ReverseDNS
  alias Sovite.Core.{Lookup, PolicyService}
  alias Sovite.DNS.MX
  alias Sovite.{Net, Validators}
  alias Sovite.SMTP.Reply

  @stages [:connect, :helo, :mail, :rcpt, :data, :end_of_data]
  @from_mail [:mail, :rcpt, :data, :end_of_data]

  @checks %{
    "permit" => @stages,
    "reject" => @stages,
    "defer" => @stages,
    "permit_trusted" => @stages,
    "permit_authenticated" => @stages,
    "client_access" => @stages,
    "helo_access" => @stages -- [:connect],
    "sender_access" => @from_mail,
    "recipient_access" => [:rcpt],
    "require_fqdn_helo" => @stages -- [:connect],
    "require_fqdn_sender" => @from_mail,
    "require_fqdn_recipient" => [:rcpt],
    "require_known_sender_domain" => @from_mail,
    "require_known_recipient_domain" => [:rcpt],
    "require_reverse_hostname" => @stages,
    "require_fcrdns" => @stages,
    "reject_forged_helo" => @stages -- [:connect],
    "require_known_helo" => @stages -- [:connect],
    "require_matching_helo" => @stages -- [:connect]
  }

  @reverse_dns_checks ["require_reverse_hostname", "require_fcrdns"]

  @typedoc "The verdict of a chain."
  @type verdict ::
          :ok
          | {:reject, Reply.t()}
          | {:discard, String.t()}
          | {:hold, String.t()}

  @typedoc "What policy servers added to the message, see `Sovite.Core.PolicyService`."
  @type effect :: PolicyService.effect()

  @doc "The stages, in session order."
  @spec stages() :: [atom()]
  def stages, do: @stages

  @doc "Checks a restriction name. Returns it, or an error message."
  @spec parse(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def parse("check_policy_service" <> address = name) do
    if String.starts_with?(address, " ") and PolicyService.valid_address?(String.trim(address)),
      do: {:ok, "check_policy_service " <> String.trim(address)},
      else:
        {:error,
         "#{inspect(name)}: expected check_policy_service inet:host:port, unix:/path, or spawn:/path"}
  end

  def parse(name) do
    if Map.has_key?(@checks, name),
      do: {:ok, name},
      else: {:error, "unknown restriction #{inspect(name)}"}
  end

  @doc "Whether check `name` can run at `stage`."
  @spec allowed?(String.t(), atom()) :: boolean()
  def allowed?("check_policy_service " <> _address, stage), do: stage in @stages
  def allowed?(name, stage), do: stage in Map.fetch!(@checks, name)

  @doc """
  Whether any of the chains (a map of stage to checks) looks at the
  client's reverse DNS, so it is worth looking up once per session.
  """
  @spec reverse_dns?(%{atom() => [String.t()]}) :: boolean()
  def reverse_dns?(chains),
    do:
      Enum.any?(chains, fn {_stage, checks} -> Enum.any?(checks, &(&1 in @reverse_dns_checks)) end)

  @typedoc """
  What a chain looks at:

    * `:client_ip`, `:helo`, `:sender`, `:recipient` - `nil` when not
      known yet.
    * `:trusted`, `:authenticated` - booleans.
    * `:access` - the access rule tables (`Sovite.Core.Lookup.tables()`)
      by kind: `:client`, `:helo`, `:sender`, `:recipient`.
    * `:resolver` - for the DNS checks.
    * `:delimiter` - the extension delimiter characters.
    * `:own_names` - this server's host name and local domains, lower-cased,
      for `reject_forged_helo`.
    * `:client_dns` - the result of `Sovite.Abuse.ReverseDNS.check/2` for
      the client, if already known. Looked up when needed otherwise.
    * `:policy`, `:policy_request`, `:esmtp` - for
      `check_policy_service`, see `Sovite.Core.PolicyService.check/3`.
  """
  @type context :: map()

  @doc """
  Runs `checks` for `stage`. `WARN` results are reported with telemetry
  `[:sovite, :restrictions, :warn]` (`%{stage, check, text}`).
  """
  @spec run([String.t()], atom(), context()) :: verdict()
  def run(checks, stage, context), do: checks |> check(stage, context) |> elem(0)

  @doc """
  Like `run/3`, and also returns what policy servers added to the
  message, in order.
  """
  @spec check([String.t()], atom(), context()) :: {verdict(), [effect()]}
  def check(checks, stage, context) do
    {verdict, effects} =
      Enum.reduce_while(checks, {:ok, []}, fn check, {verdict, effects} ->
        case evaluate(check, stage, context) do
          :continue -> {:cont, {verdict, effects}}
          :permit -> {:halt, {verdict, effects}}
          {:effect, effect} -> {:cont, {verdict, [effect | effects]}}
          {:hold, _text} = hold -> {:cont, {hold, effects}}
          {:discard, _text} = discard -> {:halt, {discard, effects}}
          {:reject, _reply} = reject -> {:halt, {reject, effects}}
        end
      end)

    {verdict, Enum.reverse(effects)}
  end

  defp evaluate("permit", _stage, _context), do: :permit

  defp evaluate("reject", _stage, _context),
    do: {:reject, Reply.new(554, "5.7.1", "Access denied")}

  defp evaluate("defer", _stage, _context),
    do: {:reject, Reply.new(450, "4.7.1", "Try again later")}

  defp evaluate("permit_trusted", _stage, context), do: permit_if(context.trusted)
  defp evaluate("permit_authenticated", _stage, context), do: permit_if(context.authenticated)

  defp evaluate("client_access", stage, context) do
    ip = context.client_ip |> Sovite.Net.normalize() |> :inet.ntoa() |> to_string()
    access(:client, client_keys(ip), stage, context, "Client host [#{ip}] rejected")
  end

  defp evaluate("helo_access", stage, %{helo: helo} = context) when helo != nil do
    keys = domain_keys(String.downcase(helo))
    access(:helo, keys, stage, context, "<#{helo}>: Helo command rejected")
  end

  defp evaluate("sender_access", stage, %{sender: sender} = context) when sender != nil do
    keys = address_keys(sender, context.delimiter)
    access(:sender, keys, stage, context, "<#{sender}>: Sender address rejected")
  end

  defp evaluate("recipient_access", stage, %{recipient: rcpt} = context) when rcpt != nil do
    keys = address_keys(rcpt, context.delimiter)
    access(:recipient, keys, stage, context, "<#{rcpt}>: Recipient address rejected")
  end

  defp evaluate("require_fqdn_helo", _stage, %{helo: helo}) when helo != nil do
    if fqdn?(helo),
      do: :continue,
      else:
        {:reject,
         Reply.new(
           504,
           "5.5.2",
           "<#{helo}>: Helo command rejected: need fully-qualified hostname"
         )}
  end

  defp evaluate("require_fqdn_sender", _stage, %{sender: sender}) when sender not in [nil, ""],
    do: non_fqdn_address(sender, "Sender address rejected")

  defp evaluate("require_fqdn_recipient", _stage, %{recipient: rcpt}) when rcpt != nil,
    do: non_fqdn_address(rcpt, "Recipient address rejected")

  defp evaluate("require_known_sender_domain", _stage, %{sender: sender} = context)
       when sender not in [nil, ""],
       do: unknown_domain(sender, context, "Sender address rejected", "1.8")

  defp evaluate("require_known_recipient_domain", _stage, %{recipient: rcpt} = context)
       when rcpt != nil,
       do: unknown_domain(rcpt, context, "Recipient address rejected", "1.2")

  defp evaluate("require_reverse_hostname", _stage, context) do
    case client_dns(context) do
      {:error, :temporary} -> reverse_dns_reject(context, 450, "reverse hostname")
      :none -> reverse_dns_reject(context, 550, "reverse hostname")
      _name -> :continue
    end
  end

  defp evaluate("require_fcrdns", _stage, context) do
    case client_dns(context) do
      {:ok, _name} -> :continue
      {:error, :temporary} -> reverse_dns_reject(context, 450, "hostname")
      _ -> reverse_dns_reject(context, 550, "hostname")
    end
  end

  defp evaluate("reject_forged_helo", _stage, %{helo: helo} = context) when helo != nil do
    name = helo |> String.downcase(:ascii) |> String.trim_trailing(".")

    forged =
      case Validators.parse_address_literal(helo) do
        {:ok, ip} ->
          Net.normalize(ip) != Net.normalize(context.client_ip)

        {:error, _} ->
          name in ["localhost", "localhost.localdomain"] or name in own_names(context)
      end

    if forged,
      do: {:reject, Reply.new(550, "5.7.1", "<#{helo}>: Helo command rejected: forged hostname")},
      else: :continue
  end

  defp evaluate("require_known_helo", _stage, %{helo: helo} = context) when helo != nil do
    if Validators.address_literal?(helo) do
      :continue
    else
      case MX.hosts(context.resolver, helo) do
        {:ok, _hosts} -> :continue
        {:error, {:temporary, _}} -> helo_reject(helo, 450, "Host not found")
        {:error, _} -> helo_reject(helo, 550, "Host not found")
      end
    end
  end

  defp evaluate("require_matching_helo", _stage, %{helo: helo} = context) when helo != nil do
    ip = Net.normalize(context.client_ip)

    case helo_addresses(helo, ip, context.resolver) do
      {:ok, addresses} ->
        if ip in Enum.map(addresses, &Net.normalize/1),
          do: :continue,
          else: helo_reject(helo, 550, "does not match your address")

      {:error, :nxdomain} ->
        helo_reject(helo, 550, "Host not found")

      {:error, _} ->
        helo_reject(helo, 450, "Host not found")
    end
  end

  defp evaluate("check_policy_service " <> address, stage, context),
    do: PolicyService.check(address, stage, context)

  defp evaluate(_check, _stage, _context), do: :continue

  # The address of a literal, or those the name resolves to.
  defp helo_addresses(helo, ip, resolver) do
    case Validators.parse_address_literal(helo) do
      {:ok, literal} ->
        {:ok, [literal]}

      {:error, _} ->
        Sovite.DNS.lookup(resolver, helo, if(tuple_size(ip) == 4, do: :a, else: :aaaa))
    end
  end

  defp client_dns(%{client_dns: result}) when result != nil, do: result
  defp client_dns(context), do: ReverseDNS.check(context.resolver, context.client_ip)

  # RFC 7372 §3.3: X.7.25, reverse DNS validation failed.
  defp reverse_dns_reject(context, code, what) do
    ip = context.client_ip |> Net.normalize() |> :inet.ntoa()
    status = if code == 450, do: "4.7.25", else: "5.7.25"
    {:reject, Reply.new(code, status, "Client host rejected: cannot find your #{what}, [#{ip}]")}
  end

  defp helo_reject(helo, code, text) do
    status = if code == 450, do: "4.7.1", else: "5.7.1"
    {:reject, Reply.new(code, status, "<#{helo}>: Helo command rejected: #{text}")}
  end

  defp own_names(context), do: Map.get(context, :own_names, [])

  defp permit_if(true), do: :permit
  defp permit_if(_), do: :continue

  defp access(kind, keys, stage, context, prefix) do
    case Lookup.lookup(Map.get(context.access, kind, []), keys) do
      {:ok, value, _key} -> action(value, stage, "#{kind}_access", prefix)
      :error -> :continue
      {:error, _table} -> {:reject, Reply.new(451, "4.3.0", "Temporary lookup failure")}
    end
  end

  @doc false
  # Turns an access rule's action into a decision.
  def action(value, stage, check, prefix) do
    {word, text} =
      case String.split(String.trim(value), ~r/\s+/, parts: 2) do
        [word, text] -> {String.upcase(word), text}
        [word] -> {String.upcase(word), nil}
      end

    decide(word, text, {stage, check, prefix})
  end

  defp decide("ACCEPT", _text, _where), do: :permit
  defp decide("CONTINUE", _text, _where), do: :continue

  defp decide("REJECT", text, {_stage, _check, prefix}),
    do: {:reject, Reply.new(554, "5.7.1", "#{prefix}: #{text || "Access denied"}")}

  defp decide("DEFER", text, {_stage, _check, prefix}),
    do: {:reject, Reply.new(450, "4.7.1", "#{prefix}: #{text || "Try again later"}")}

  defp decide("DISCARD", text, _where), do: {:discard, text || "discarded"}
  defp decide("HOLD", text, _where), do: {:hold, text || "held"}
  defp decide("WARN", text, {stage, check, _prefix}), do: warn(stage, check, text)
  defp decide(word, text, {_stage, _check, prefix}), do: code_action(word, text, prefix)

  defp warn(stage, check, text) do
    :telemetry.execute([:sovite, :restrictions, :warn], %{}, %{
      stage: stage,
      check: check,
      text: text || ""
    })

    :continue
  end

  defp code_action(word, text, prefix) do
    case Integer.parse(word) do
      {code, ""} when code in 400..599 ->
        {status, text} = status_text(code, text)
        {:reject, Reply.new(code, status, "#{prefix}: #{text}")}

      _ ->
        {:reject, Reply.new(451, "4.3.5", "Server configuration error")}
    end
  end

  defp status_text(code, text) do
    case Regex.run(~r/\A([45]\.\d{1,3}\.\d{1,3})(?:\s+(.*))?\z/s, text || "") do
      [_, status | rest] -> {status, List.first(rest) || "Access denied"}
      nil -> {if(code >= 500, do: "5.7.1", else: "4.7.1"), text || "Access denied"}
    end
  end

  defp non_fqdn_address(address, prefix) do
    domain = domain(address)

    if domain == nil or fqdn?(domain),
      do: :continue,
      else:
        {:reject,
         Reply.new(504, "5.5.2", "<#{address}>: #{prefix}: need fully-qualified address")}
  end

  defp unknown_domain(address, context, prefix, detail) do
    with domain when is_binary(domain) <- domain(address),
         false <- String.starts_with?(domain, "[") do
      case MX.hosts(context.resolver, domain) do
        {:ok, _hosts} ->
          :continue

        {:error, {:temporary, _}} ->
          {:reject, Reply.new(450, "4.#{detail}", "<#{address}>: #{prefix}: Domain not found")}

        {:error, _} ->
          {:reject, Reply.new(550, "5.#{detail}", "<#{address}>: #{prefix}: Domain not found")}
      end
    else
      _ -> :continue
    end
  end

  defp fqdn?("[" <> _), do: true
  defp fqdn?(name), do: name |> String.trim_trailing(".") |> String.contains?(".")

  defp domain(address) do
    case String.split(address, "@") do
      [_no_domain] -> nil
      parts -> String.downcase(List.last(parts), :ascii)
    end
  end

  @doc false
  def client_keys(ip) do
    case String.split(ip, ".") do
      [a, b, c, _d] -> [ip, "#{a}.#{b}.#{c}", "#{a}.#{b}", a]
      _ -> [ip]
    end
  end

  @doc false
  # "host.example.com" -> host.example.com, .example.com, example.com, .com, com
  def domain_keys(name) do
    labels = String.split(name, ".")

    parents =
      for n <- 1..(length(labels) - 1)//1,
          parent = labels |> Enum.drop(n) |> Enum.join("."),
          key <- ["." <> parent, parent],
          do: key

    [name | parents]
  end

  @doc false
  def address_keys("", _delimiter), do: ["<>"]

  def address_keys(address, delimiter) do
    address = String.downcase(address)

    case String.split(address, "@") do
      [_no_domain] ->
        [address]

      parts ->
        domain = List.last(parts)
        local = parts |> Enum.drop(-1) |> Enum.join("@")
        base = strip_extension(local, delimiter)

        Enum.uniq(
          [address, "#{base}@#{domain}"] ++ domain_keys(domain) ++ ["#{local}@", "#{base}@"]
        )
    end
  end

  # "alice+lists" -> "alice" with delimiter "+". Kept here rather than
  # using Sovite.Core.Routing, which depends on the config.
  defp strip_extension(local, delimiter) when delimiter in [nil, ""], do: local

  defp strip_extension(local, delimiter) do
    case :binary.match(local, String.graphemes(delimiter)) do
      {at, _} when at > 0 -> binary_part(local, 0, at)
      _ -> local
    end
  end
end
