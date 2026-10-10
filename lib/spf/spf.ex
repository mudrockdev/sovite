defmodule Sovite.SPF do
  @moduledoc """
  SPF verification (RFC 7208).

      Sovite.SPF.check_mail_from(resolver, {192, 0, 2, 3}, "alice@example.com", "mx.example.com")
      #=> %Sovite.SPF.Result{result: :pass, domain: "example.com", mechanism: "ip4:192.0.2.0/24"}

  `check_host/5` is the `check_host()` function of RFC 7208 §4.
  `check_mail_from/5` and `check_helo/4` pick the identity to check from
  the SMTP session (§2.3, §2.4).

  DNS errors give `:temperror`. Records that cannot be parsed, too many
  DNS lookups, and includes or redirects to domains without an SPF
  record give `:permerror`. The lookup limits span the whole check,
  including nested `include:` and `redirect=` records.

  ## Options

    * `:helo` - the HELO/EHLO name, for the `h` macro. `check_mail_from/5`
      and `check_helo/4` set it.
    * `:receiver` - this host's name, for the `r` macro in explanations.
      Defaults to `"unknown"`.
    * `:max_lookups` - terms that query DNS (`include`, `a`, `mx`, `ptr`,
      `exists`, `redirect`, and the `p` macro). Defaults to 10.
    * `:max_void_lookups` - lookups by those terms that find no records.
      Defaults to 2.
    * `:timeout` - milliseconds for the whole check, after which the
      result is `:temperror`. Defaults to 20 seconds.
    * `:now` - Unix seconds for the `t` macro. Defaults to the current
      time.

  ## Telemetry

    * `[:sovite, :spf, :check, :start]` - `%{system_time}`, `%{domain, ip}`
    * `[:sovite, :spf, :check, :stop]` - `%{duration}`, `%{domain, ip,
      result}`
    * `[:sovite, :spf, :check, :exception]` - the usual `:telemetry.span/3`
      measurements and metadata
  """

  alias Sovite.SPF.{Eval, Result}

  @typedoc "An SPF result (RFC 7208 §2.6)."
  @type result :: :pass | :fail | :softfail | :neutral | :none | :temperror | :permerror

  @defaults [
    helo: nil,
    receiver: "unknown",
    max_lookups: 10,
    max_void_lookups: 2,
    timeout: 20_000,
    now: nil
  ]

  @doc """
  Checks whether `ip` may send mail for `domain`, with `sender` as the
  `MAIL FROM` address (RFC 7208 §4). A `sender` without a local part
  gets `"postmaster"`.

  A malformed `domain` gives `:none` without any lookups. See the module
  documentation for options.
  """
  @spec check_host(Sovite.DNS.resolver(), :inet.ip_address(), String.t(), String.t(), keyword()) ::
          Result.t()
  def check_host(resolver, ip, domain, sender, opts \\ []) do
    opts = Keyword.validate!(opts, @defaults)
    metadata = %{domain: domain, ip: ip}

    :telemetry.span([:sovite, :spf, :check], metadata, fn ->
      result = run(opts[:timeout], fn -> Eval.check(resolver, ip, domain, sender, opts) end)
      {%{result | domain: domain}, Map.put(metadata, :result, result.result)}
    end)
  end

  # A separate process, so a resolver that hangs cannot hold the check
  # past its budget. It is monitored, not linked: callers that trap exits
  # (such as SMTP sessions) must not get an exit signal from it.
  defp run(timeout, fun) do
    caller = self()
    ref = make_ref()
    {pid, monitor} = spawn_monitor(fn -> send(caller, {ref, fun.()}) end)

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^pid, reason} ->
        exit(reason)
    after
      timeout ->
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])

        receive do
          {^ref, _late} -> :ok
        after
          0 -> :ok
        end

        %Result{result: :temperror, reason: "timed out after #{timeout} ms"}
    end
  end

  @doc """
  Checks the `MAIL FROM` identity (RFC 7208 §2.4).

  The domain checked is the domain of `sender`. For the null reverse-path
  (`sender` is `""`), it is `helo`, with `postmaster@<helo>` as the
  sender.
  """
  @spec check_mail_from(
          Sovite.DNS.resolver(),
          :inet.ip_address(),
          String.t(),
          String.t() | nil,
          keyword()
        ) :: Result.t()
  def check_mail_from(resolver, ip, sender, helo, opts \\ []) do
    opts = Keyword.put(opts, :helo, helo)

    case sender do
      "" ->
        helo = helo || ""
        check_host(resolver, ip, helo, "postmaster@" <> helo, opts)

      sender ->
        check_host(resolver, ip, Eval.sender_domain(sender), sender, opts)
    end
  end

  @doc """
  Checks the HELO identity (RFC 7208 §2.3), with `postmaster@<helo>` as
  the sender.

  An address literal or a name that is not a fully qualified domain name
  gives `:none` without any lookups.
  """
  @spec check_helo(Sovite.DNS.resolver(), :inet.ip_address(), String.t() | nil, keyword()) ::
          Result.t()
  def check_helo(resolver, ip, helo, opts \\ []) do
    name = if is_binary(helo), do: String.replace_suffix(helo, ".", ""), else: ""

    if Sovite.Validators.hostname?(name) and String.contains?(name, ".") do
      check_host(resolver, ip, helo, "postmaster@" <> helo, Keyword.put(opts, :helo, helo))
    else
      %Result{result: :none, domain: helo, reason: "HELO name is not a domain name"}
    end
  end
end
