defmodule Sovite.HeaderChecks do
  @moduledoc """
  Checks of a message's header fields that tell spam and forgeries from
  mail written by mail programs: missing or malformed `Date:`,
  `Message-ID:`, and `From:`, display names that show another address,
  `Reply-To:` to another domain, fields that may appear once appearing
  again, and `Received:` chains that do not add up.

      iex> fields = Sovite.Message.Headers.parse("From: \\"support@bank.example\\" <x@evil.example>\\r\\nTo: you@example.com\\r\\n")
      iex> Sovite.HeaderChecks.check(fields, now: ~U[2026-10-27 12:00:00Z])
      [{"MISSING_DATE", []}, {"MISSING_MID", []}, {"SPOOF_DISPLAY_NAME", ["support@bank.example"]},
       {"MISSING_SUBJECT", []}, {"RCVD_COUNT_ZERO", []}]

  Each finding is a symbol for `Sovite.Rules.scan/3`, with options that
  say what was found:

    * `MISSING_DATE`, `INVALID_DATE`, `DATE_IN_FUTURE` (more than
      `:future` ahead), `DATE_IN_PAST` (more than `:past` ago).
    * `MISSING_MID`, `INVALID_MSGID`, `MID_RHS_NOT_FQDN` (the part after
      `@` is not a domain with a dot).
    * `MISSING_FROM`, `MULTIPLE_FROM` (several fields, or several
      addresses), `INVALID_FROM`, `FROM_NO_DN` (no display name),
      `SPOOF_DISPLAY_NAME` (the display name shows an address at another
      domain), `FROM_NEQ_ENVFROM` (not the `:envelope_from`).
    * `REPLYTO_UNPARSABLE`, `REPLYTO_DOM_NEQ_FROM_DOM`.
    * `MISSING_TO`, `MISSING_SUBJECT`.
    * `MULTIPLE_UNIQUE_HEADERS`: fields RFC 5322 allows once, more than
      once (`From:` is `MULTIPLE_FROM`).
    * `RCVD_COUNT_ZERO`, `RCVD_UNPARSABLE` (a `Received:` field without
      a readable date or host), `RCVD_DATES_UNORDERED` (an earlier hop
      dated more than an hour after a later one), `FORGED_RCVD_HOSTNAME`
      (one of `:hostnames` received the message before another host did:
      claimed by the sender, or a loop).

  ## Options

    * `:now` - the time to compare dates with. Defaults to now.
    * `:future`, `:past` - seconds. Default to 2 hours and 7 days.
    * `:hostnames` - this server's names, lower-cased.
    * `:envelope_from` - the `MAIL FROM` address.
  """

  alias Sovite.Message.{AddressList, Date, Headers, MessageID, Received}
  alias Sovite.MIME.EncodedWord

  @type symbol :: {String.t(), [String.t()]}

  # Fields RFC 5322 §3.6 allows at most once.
  @unique ~w(date sender reply-to to cc bcc message-id in-reply-to references subject)

  @address ~r/[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)/

  @doc "Checks the header fields of a message (`Sovite.Message.Headers.parse/1`)."
  @spec check([Headers.field()], keyword()) :: [symbol()]
  def check(fields, opts \\ []) do
    from = from_mailbox(values(fields, "from"))

    List.flatten([
      date(values(fields, "date"), opts),
      message_id(values(fields, "message-id")),
      from(from, opts),
      reply_to(values(fields, "reply-to"), from),
      if(values(fields, "to") == [], do: {"MISSING_TO", []}, else: []),
      if(values(fields, "subject") == [], do: {"MISSING_SUBJECT", []}, else: []),
      unique(fields),
      received(values(fields, "received"), Keyword.get(opts, :hostnames, []))
    ])
  end

  # Unfolded values, in order, in UTF-8.
  defp values(fields, name) do
    for {^name, raw} <- fields do
      [_name, value] = :binary.split(raw, ":")
      value |> String.replace_invalid() |> String.replace(~r/\r?\n(?=[ \t])/, "") |> String.trim()
    end
  end

  defp date([], _opts), do: {"MISSING_DATE", []}

  defp date([value | _], opts) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    case Date.parse(value) do
      {:ok, date} ->
        ahead = DateTime.diff(date, now)

        cond do
          ahead > Keyword.get(opts, :future, 2 * 3600) -> {"DATE_IN_FUTURE", [value]}
          -ahead > Keyword.get(opts, :past, 7 * 86_400) -> {"DATE_IN_PAST", [value]}
          true -> []
        end

      :error ->
        {"INVALID_DATE", [value]}
    end
  end

  defp message_id([]), do: {"MISSING_MID", []}

  defp message_id([value | _]) do
    case MessageID.parse(value) do
      {:ok, _left, "[" <> _ = right} ->
        {"MID_RHS_NOT_FQDN", [right]}

      {:ok, _left, right} ->
        if String.contains?(right, "."), do: [], else: {"MID_RHS_NOT_FQDN", [right]}

      :error ->
        {"INVALID_MSGID", [value]}
    end
  end

  # {:ok, display name, address}, or why there is none.
  defp from_mailbox([]), do: :missing
  defp from_mailbox([_, _ | _]), do: :multiple

  defp from_mailbox([value]) do
    case AddressList.mailboxes(value) do
      {:ok, [{name, address}]} -> {:ok, name && EncodedWord.decode(name), address}
      {:ok, [_, _ | _]} -> :multiple
      _ -> :invalid
    end
  end

  defp from(:missing, _opts), do: {"MISSING_FROM", []}
  defp from(:multiple, _opts), do: {"MULTIPLE_FROM", []}
  defp from(:invalid, _opts), do: {"INVALID_FROM", []}

  defp from({:ok, name, address}, opts) do
    envelope_from = Keyword.get(opts, :envelope_from)

    [
      display_name(name, address),
      if(
        envelope_from not in [nil, ""] and
          String.downcase(envelope_from) != String.downcase(address),
        do: {"FROM_NEQ_ENVFROM", [envelope_from]},
        else: []
      )
    ]
  end

  defp display_name(nil, _address), do: {"FROM_NO_DN", []}

  defp display_name(name, address) do
    domain = domain(address)

    case Regex.run(@address, name) do
      [shown, shown_domain] ->
        if String.downcase(shown_domain) != domain, do: {"SPOOF_DISPLAY_NAME", [shown]}, else: []

      nil ->
        []
    end
  end

  defp reply_to([], _from), do: []

  defp reply_to([value | _], from) do
    case {AddressList.mailboxes(value), from} do
      {{:ok, [{_name, address} | _]}, {:ok, _from_name, from_address}} ->
        if domain(address) != domain(from_address),
          do: {"REPLYTO_DOM_NEQ_FROM_DOM", [domain(address)]},
          else: []

      {{:ok, [_ | _]}, _from} ->
        []

      _ ->
        {"REPLYTO_UNPARSABLE", [value]}
    end
  end

  defp unique(fields) do
    repeated =
      fields
      |> Enum.map(&elem(&1, 0))
      |> Enum.filter(&(&1 in @unique))
      |> Enum.frequencies()
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))
      |> Enum.sort()

    if repeated == [], do: [], else: {"MULTIPLE_UNIQUE_HEADERS", repeated}
  end

  defp received([], _hostnames), do: {"RCVD_COUNT_ZERO", []}

  defp received(values, hostnames) do
    hops = Enum.map(values, &Received.parse/1)

    [
      unparsable(hops),
      unordered(hops),
      forged(hops, MapSet.new(hostnames, &String.downcase/1))
    ]
  end

  defp unparsable(hops) do
    if Enum.any?(hops, &(&1.date == nil or (&1.from == nil and &1.by == nil))),
      do: {"RCVD_UNPARSABLE", []},
      else: []
  end

  # Fields are added at the top: each is older than the one above it.
  # An hour allows for clocks that are off.
  defp unordered(hops) do
    dates = for %{date: %DateTime{} = date} <- hops, do: date

    dates
    |> Enum.zip(Enum.drop(dates, 1))
    |> Enum.any?(fn {newer, older} -> DateTime.diff(older, newer) > 3600 end)
    |> if(do: {"RCVD_DATES_UNORDERED", []}, else: [])
  end

  defp forged(hops, hostnames) do
    hops
    |> Enum.map(& &1.by)
    |> Enum.reject(&is_nil/1)
    |> Enum.drop_while(&MapSet.member?(hostnames, &1))
    |> Enum.find(&MapSet.member?(hostnames, &1))
    |> case do
      nil -> []
      host -> {"FORGED_RCVD_HOSTNAME", [host]}
    end
  end

  defp domain(address), do: address |> String.split("@") |> List.last() |> String.downcase()
end
