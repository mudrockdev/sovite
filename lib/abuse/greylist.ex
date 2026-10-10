defmodule Sovite.Abuse.Greylist do
  @moduledoc """
  Greylisting decisions, in the style of postgrey.

  Mail from an unknown triplet of client network, sender, and recipient
  is deferred the first time. Real servers retry after a while and are
  let through; much spam software never retries. Once a triplet has
  passed, it passes at once for as long as it keeps being used.

      triplet = Greylist.triplet(ip, sender, recipient)
      entry = MyApp.lookup(Greylist.key(triplet))

      case Greylist.check(entry, DateTime.utc_now()) do
        {:pass, entry} -> MyApp.store(entry) && accept()
        {{:defer, seconds}, entry} -> MyApp.store(entry) && defer(seconds)
      end

  Functions are pure: the caller stores entries under `key/1` wherever
  it likes, and can delete those past their `:expires_at`.

  The triplet is loosened so that retries still match: the client
  address is reduced to its /24 (IPv4) or /64 (IPv6) network, since big
  senders retry from other hosts, and the sender loses BATV tags and has
  the digits of its local part replaced, since bounce and VERP addresses
  change with every message.

  ## Options

    * `:delay` - milliseconds a new triplet is deferred for. Defaults to
      five minutes.
    * `:retry_window` - milliseconds a deferred triplet is remembered
      for; one that has not passed by then starts over. Defaults to two
      days.
    * `:max_age` - milliseconds a passed triplet is remembered for after
      it was last seen. Defaults to 35 days.
  """

  @type triplet :: {network :: String.t(), sender :: String.t(), recipient :: String.t()}
  @type entry :: %{
          first_seen: DateTime.t(),
          last_seen: DateTime.t(),
          passed_at: DateTime.t() | nil,
          expires_at: DateTime.t()
        }
  @type decision :: :pass | {:defer, pos_integer()}

  @defaults [delay: 300_000, retry_window: 2 * 86_400_000, max_age: 35 * 86_400_000]

  @doc """
  Returns the triplet for a client address, envelope sender, and
  recipient.

      iex> Sovite.Abuse.Greylist.triplet({192, 0, 2, 7}, "prvs=1234abcdef=Bounce-42@List.Example", "Bob@Example.com")
      {"192.0.2.0/24", "bounce-#@list.example", "bob@example.com"}
  """
  @spec triplet(:inet.ip_address(), String.t(), String.t()) :: triplet()
  def triplet(ip, sender, recipient),
    do: {network(Sovite.Net.normalize(ip)), sender(sender), String.downcase(recipient)}

  @doc "Returns a fixed-size key for storing a triplet: 64 hex characters."
  @spec key(triplet()) :: String.t()
  def key({network, sender, recipient}) do
    data =
      for field <- [network, sender, recipient],
          into: <<>>,
          do: <<byte_size(field)::32, field::binary>>

    Base.encode16(:crypto.hash(:sha256, data), case: :lower)
  end

  @doc """
  Decides on mail for a triplet whose stored entry is `entry`, or `nil`
  if there is none. Returns the decision and the entry to store.
  """
  @spec check(entry() | nil, DateTime.t(), keyword()) :: {decision(), entry()}
  def check(entry, now, opts \\ []) do
    opts = Keyword.validate!(opts, @defaults)
    now = DateTime.truncate(now, :second)
    entry = if expired?(entry, now, opts), do: nil, else: entry
    decide(entry, now, opts)
  end

  defp expired?(nil, _now, _opts), do: true

  defp expired?(%{passed_at: nil} = entry, now, opts),
    do: DateTime.diff(now, entry.first_seen, :millisecond) > opts[:retry_window]

  defp expired?(entry, now, opts),
    do: DateTime.diff(now, entry.last_seen, :millisecond) > opts[:max_age]

  defp decide(nil, now, opts) do
    entry = %{
      first_seen: now,
      last_seen: now,
      passed_at: nil,
      expires_at: add(now, opts[:retry_window])
    }

    {{:defer, seconds(opts[:delay])}, entry}
  end

  defp decide(%{passed_at: nil} = entry, now, opts) do
    remaining = opts[:delay] - DateTime.diff(now, entry.first_seen, :millisecond)

    if remaining > 0 do
      entry = %{entry | last_seen: now, expires_at: add(entry.first_seen, opts[:retry_window])}
      {{:defer, seconds(remaining)}, entry}
    else
      {:pass, %{entry | passed_at: now, last_seen: now, expires_at: add(now, opts[:max_age])}}
    end
  end

  defp decide(entry, now, opts),
    do: {:pass, %{entry | last_seen: now, expires_at: add(now, opts[:max_age])}}

  defp network({a, b, c, _d}), do: Sovite.Net.format_cidr({{a, b, c, 0}, 24})

  defp network({a, b, c, d, _e, _f, _g, _h}),
    do: Sovite.Net.format_cidr({{a, b, c, d, 0, 0, 0, 0}, 64})

  defp sender(""), do: ""

  defp sender(sender) do
    sender =
      String.replace(
        String.downcase(sender),
        ~r/\A(?:(?:prvs|msprvs1)=[^=@]+=|btv1==[^=@]+==)/,
        ""
      )

    case Regex.run(~r/\A(.*)(@[^@]*)\z/s, sender, capture: :all_but_first) do
      [local, domain] -> mask_digits(local) <> domain
      nil -> mask_digits(sender)
    end
  end

  defp mask_digits(local), do: String.replace(local, ~r/[0-9]+/, "#")

  defp seconds(milliseconds), do: max(div(milliseconds + 999, 1000), 1)

  defp add(datetime, milliseconds),
    do: datetime |> DateTime.add(milliseconds, :millisecond) |> DateTime.truncate(:second)
end
