defmodule Sovite.SRS do
  @moduledoc """
  The Sender Rewriting Scheme, so forwarded mail still passes SPF: the
  envelope sender is rewritten into an address at the forwarder's own
  domain, and bounces to that address are turned back into the original
  sender.

      {:ok, srs} = Sovite.SRS.forward("alice@example.com", "fwd.example.net", secrets: ["s3cret"])
      #=> "SRS0=HHHH=TT=example.com=alice@fwd.example.net"
      Sovite.SRS.reverse(srs, secrets: ["s3cret"])
      #=> {:ok, "alice@example.com"}

  This is the Shevek scheme as libsrs2 and postsrsd implement it, so
  addresses can be reversed by either side:

    * `SRS0=HHHH=TT=domain=local@srs-domain` for a plain address. `TT`
      is the day number (days since the Unix epoch, mod 1024) in two
      base32 characters. `HHHH` is the first four characters of the
      base64 HMAC-SHA1, keyed with the secret, of `TT <> domain <> local`
      lower-cased (ASCII only).
    * An address that is already `SRS0` at `hop1` becomes
      `SRS1=HHHH=hop1==HHHH=TT=domain=local@srs-domain`, so the bounce
      goes back to `hop1` rather than through every forwarder. The hash
      is over `hop1 <> "=HHHH=TT=domain=local"`, again lower-cased.
    * An `SRS1` address keeps its first hop; only the hash is replaced.

  Bounces may come back with the local part case-mangled, so hashes are
  compared without regard to case, like libsrs2 does.
  """

  @time_chars "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  @time_slots 1024
  @hash_length 4

  @doc """
  Rewrites `address` into an SRS address at `srs_domain`.

  An address already at `srs_domain` is returned unchanged.

  ## Options

    * `:secrets` - required, a non-empty list of secrets. The first one
      signs; the others are only for `reverse/2`, so a secret can be
      rotated without breaking bounces in flight.
    * `:now` - the `DateTime` for the timestamp. Defaults to now.
  """
  @spec forward(String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, :invalid_address}
  def forward(address, srs_domain, opts) do
    [secret | _] = Keyword.fetch!(opts, :secrets)

    with {:ok, local, domain} <- split(address) do
      if String.downcase(domain, :ascii) == String.downcase(srs_domain, :ascii),
        do: {:ok, address},
        else: {:ok, rewrite(local, domain, secret, opts) <> "@" <> srs_domain}
    end
  end

  defp split(address) do
    case String.split(address, "@") do
      [local, domain] when local != "" and domain != "" -> {:ok, local, domain}
      _ -> {:error, :invalid_address}
    end
  end

  defp rewrite(local, domain, secret, opts) do
    case tag(local) do
      {:srs0, separator, rest} ->
        guarded(secret, domain, <<separator, rest::binary>>)

      {:srs1, rest} ->
        case String.split(rest, "=", parts: 3) do
          [_hash, hop, user] when hop != "" and user != "" -> guarded(secret, hop, user)
          # Not one of ours to keep short, so wrap it like any address.
          _ -> shortcut(secret, local, domain, opts)
        end

      :none ->
        shortcut(secret, local, domain, opts)
    end
  end

  defp shortcut(secret, local, domain, opts) do
    stamp = opts |> Keyword.get_lazy(:now, &DateTime.utc_now/0) |> day() |> encode_stamp()
    "SRS0=#{hash(secret, [stamp, domain, local])}=#{stamp}=#{domain}=#{local}"
  end

  defp guarded(secret, hop, user), do: "SRS1=#{hash(secret, [hop, user])}=#{hop}=#{user}"

  @doc """
  Turns an SRS address back into the address it was made from: an
  `SRS0` address into the original sender, an `SRS1` address into the
  `SRS0` address at the first forwarder.

  The separator after `SRS0`/`SRS1` may be `=`, `+` or `-`.

  ## Options

    * `:secrets` - required. Every secret is tried.
    * `:max_age` - how many days an `SRS0` address stays valid.
      Defaults to 21.
    * `:now` - the `DateTime` to check the age against. Defaults to now.
  """
  @spec reverse(String.t(), keyword()) ::
          {:ok, String.t()} | {:error, :not_srs | :malformed | :bad_hash | :expired}
  def reverse(address, opts) do
    secrets = Keyword.fetch!(opts, :secrets)

    case String.split(address, "@") do
      [local, domain] when domain != "" -> reverse_local(tag(local), secrets, opts)
      [local | _] -> if tag(local) == :none, do: {:error, :not_srs}, else: {:error, :malformed}
    end
  end

  defp reverse_local(:none, _secrets, _opts), do: {:error, :not_srs}

  defp reverse_local({:srs0, _separator, rest}, secrets, opts) do
    with [hash, stamp, host, user] <- String.split(rest, "=", parts: 4),
         true <- Enum.all?([hash, host, user], &(&1 != "")),
         {:ok, then} <- decode_stamp(stamp),
         :ok <- check_hash(hash, secrets, [stamp, host, user]),
         :ok <- check_age(then, opts) do
      {:ok, user <> "@" <> host}
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed}
    end
  end

  defp reverse_local({:srs1, rest}, secrets, _opts) do
    with [hash, hop, user] when hash != "" and hop != "" and user != "" <-
           String.split(rest, "=", parts: 3),
         :ok <- check_hash(hash, secrets, [hop, user]) do
      {:ok, "SRS0" <> user <> "@" <> hop}
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed}
    end
  end

  @doc """
  Whether `address` (or a bare local part) is an SRS address.

      iex> Sovite.SRS.srs?("srs0+HHHH=TT=example.com=alice@fwd.example.net")
      true
      iex> Sovite.SRS.srs?("alice@example.com")
      false
  """
  @spec srs?(String.t()) :: boolean()
  def srs?(address) do
    [local | _] = :binary.split(address, "@")
    tag(local) != :none
  end

  defp tag(<<tag::binary-size(4), separator, rest::binary>>) when separator in ~c"=+-" do
    case String.upcase(tag, :ascii) do
      "SRS0" -> {:srs0, separator, rest}
      "SRS1" -> {:srs1, rest}
      _ -> :none
    end
  end

  defp tag(_local), do: :none

  defp hash(secret, parts) do
    data = parts |> IO.iodata_to_binary() |> String.downcase(:ascii)
    :hmac |> :crypto.mac(:sha, secret, data) |> Base.encode64() |> binary_part(0, @hash_length)
  end

  defp check_hash(given, secrets, parts) do
    given = String.downcase(given, :ascii)

    # Every secret is tried, so the time taken does not tell which one matched.
    matches =
      Enum.map(secrets, fn secret ->
        expected = secret |> hash(parts) |> String.downcase(:ascii)
        byte_size(given) == @hash_length and :crypto.hash_equals(given, expected)
      end)

    if Enum.any?(matches), do: :ok, else: {:error, :bad_hash}
  end

  # The day counter has only 10 bits, so it wraps every 1024 days: the
  # age is taken modulo that, as libsrs2 does.
  defp check_age(then, opts) do
    now = opts |> Keyword.get_lazy(:now, &DateTime.utc_now/0) |> day()

    if Integer.mod(now - then, @time_slots) > Keyword.get(opts, :max_age, 21),
      do: {:error, :expired},
      else: :ok
  end

  defp day(datetime),
    do: datetime |> DateTime.to_unix() |> Integer.floor_div(86_400) |> Integer.mod(@time_slots)

  defp encode_stamp(day),
    do: <<:binary.at(@time_chars, div(day, 32)), :binary.at(@time_chars, rem(day, 32))>>

  defp decode_stamp(<<high, low>>) do
    with {:ok, high} <- stamp_digit(high), {:ok, low} <- stamp_digit(low) do
      {:ok, high * 32 + low}
    end
  end

  defp decode_stamp(_stamp), do: :error

  defp stamp_digit(char) do
    case :binary.match(@time_chars, String.upcase(<<char>>, :ascii)) do
      {index, 1} -> {:ok, index}
      :nomatch -> :error
    end
  end
end
