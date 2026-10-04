defmodule Sovite.Core.Recipients do
  @moduledoc """
  Recipient expansion and validation.

  ## Expansion

  `expand/2` turns a recipient into the addresses the mail is queued
  for, using the aliases in the database (`sovitectl alias`). Keys tried,
  in order (see `Sovite.Core.Routing.lookup/4`): `user+ext@domain`,
  `user@domain`, the bare local part for local domains, then `@domain`.
  An extension the alias did not match is kept: with an alias for
  `alice@example.com`, mail for `alice+lists@example.com` goes to each
  destination with `+lists` added.

  Destinations are expanded again, up to 100 levels and 1000 addresses.
  An address that comes back to itself (`team -> team, alice`) is kept,
  not expanded again.

  `postmaster@` and `abuse@` an aliased or hosted domain without an alias
  or mailbox go to `postmaster@` the server's host name, so they always
  reach someone (RFC 5321 §4.5.1, RFC 2142).

  ## Validation

  `check/2` decides whether a single address (after expansion) is known,
  by its domain class (`Sovite.Core.Routing.class/2`):

    * `:local` - any address, unless `domains.local_recipients` is set:
      then only those (and `postmaster@`, `abuse@`).
    * `:aliased` - only aliases, so an address that reaches `check/2`
      unexpanded is unknown.
    * `:hosted` - mailboxes (`sovitectl mailbox`), or `@domain` for all.
    * `:relay` and `:remote` - any address.

  It also rejects users who moved (`sovitectl moved`) with `5.1.6` and
  their new location.

  ## BCC

  `bcc/3` adds `routing.always_bcc`, and the copies the BCC rules
  (`sovitectl bcc`) give for the sender and each recipient, by address,
  then `@domain`.
  """

  alias Sovite.Core.Routing

  @max_depth 100
  @max_recipients 1000

  @typedoc """
  Why expansion failed: a table could not be read, or the aliases are
  broken. The client should try again later. The text is for the log.
  """
  @type error :: {:error, :temporary, String.t()}

  @doc "Expands `address`. Returns the final addresses, without duplicates."
  @spec expand(Routing.t(), String.t()) :: {:ok, [String.t(), ...]} | error()
  def expand(routing, address) do
    with {:ok, addresses} <- expand(routing, address, [], 0) do
      addresses = Enum.uniq_by(addresses, &String.downcase/1)

      if length(addresses) > @max_recipients,
        do:
          {:error, :temporary, "<#{address}> expands to more than #{@max_recipients} addresses"},
        else: {:ok, addresses}
    end
  end

  defp expand(_routing, address, _ancestors, depth) when depth > @max_depth,
    do: {:error, :temporary, "aliases nested more than #{@max_depth} levels deep at <#{address}>"}

  defp expand(routing, address, ancestors, depth) do
    key = String.downcase(address)

    if key in ancestors do
      {:ok, [address]}
    else
      case aliases(routing, address) do
        {:ok, targets} -> expand_all(routing, targets, [key | ancestors], depth + 1)
        :none -> {:ok, [fallback(routing, address)]}
        {:error, _kind, _text} = error -> error
      end
    end
  end

  defp expand_all(routing, targets, ancestors, depth) do
    Enum.reduce_while(targets, {:ok, []}, fn target, {:ok, acc} ->
      case expand(routing, target, ancestors, depth) do
        {:ok, addresses} when length(acc) + length(addresses) > @max_recipients ->
          {:halt,
           {:error, :temporary, "alias expansion gives more than #{@max_recipients} addresses"}}

        {:ok, addresses} ->
          {:cont, {:ok, acc ++ addresses}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp aliases(routing, address) do
    {_local, domain} = Routing.split(address)
    class = if domain, do: Routing.class(routing, domain), else: :local

    case Routing.lookup(routing, routing.aliases, address,
           local_part: class == :local,
           catchall: true
         ) do
      {:ok, value, _kind, ext} ->
        targets =
          value
          |> Routing.addresses()
          |> Enum.map(&Routing.add_extension(routing, &1, ext))

        valid(targets, address)

      :error ->
        :none

      {:error, table} ->
        {:error, :temporary, "cannot read table #{table}"}
    end
  end

  defp valid(targets, address) do
    case Enum.reject(targets, &Routing.valid_address?/1) do
      [] when targets != [] ->
        {:ok, targets}

      [] ->
        {:error, :temporary, "empty alias for <#{address}>"}

      [bad | _] ->
        {:error, :temporary, "alias for <#{address}> has an invalid address #{inspect(bad)}"}
    end
  end

  defp fallback(routing, address) do
    {local, domain} = Routing.split(address)

    with true <- domain != nil,
         true <- String.downcase(local) in ["postmaster", "abuse"],
         class when class in [:aliased, :hosted] <- Routing.class(routing, domain),
         {:reject, _status, _text} <- check(routing, address) do
      "postmaster@" <> routing.hostname
    else
      _ -> address
    end
  end

  @doc """
  Checks a single address. Returns its class, a rejection (`550` with
  the status and text), or `{:error, text}` when a table cannot be read.
  """
  @spec check(Routing.t(), String.t()) ::
          {:ok, Routing.class()} | {:reject, String.t(), String.t()} | {:error, String.t()}
  def check(routing, address) do
    {local, domain} = Routing.split(address)
    class = if domain, do: Routing.class(routing, domain), else: :local

    case Routing.lookup(routing, routing.moved_users, address, catchall: true) do
      {:ok, value, _kind, _ext} ->
        {:reject, "5.1.6", "<#{address}>: Recipient address rejected: User has moved to #{value}"}

      :error ->
        check_class(routing, class, address, local)

      {:error, table} ->
        {:error, "cannot read table #{table}"}
    end
  end

  defp check_class(routing, :local, address, local) do
    cond do
      String.downcase(local) in ["postmaster", "abuse"] -> {:ok, :local}
      routing.local_recipients == nil -> {:ok, :local}
      listed?(routing, address) -> {:ok, :local}
      true -> unknown(address, "local recipient")
    end
  end

  defp check_class(_routing, :aliased, address, _local), do: unknown(address, "alias")

  defp check_class(routing, :hosted, address, _local) do
    case Routing.lookup(routing, routing.mailboxes, address, catchall: true) do
      {:ok, _value, _kind, _ext} -> {:ok, :hosted}
      :error -> unknown(address, "mailbox")
      {:error, table} -> {:error, "cannot read table #{table}"}
    end
  end

  defp check_class(_routing, class, _address, _local), do: {:ok, class}

  defp listed?(routing, address) do
    address = String.downcase(address)
    {local, domain} = Routing.split(address)
    {base, _ext} = Routing.extension(routing, local)

    MapSet.member?(routing.local_recipients, address) or
      MapSet.member?(routing.local_recipients, "#{base}@#{domain}")
  end

  defp unknown(address, kind),
    do:
      {:reject, "5.1.1",
       "<#{address}>: Recipient address rejected: User unknown in #{kind} table"}

  @doc "The BCC addresses for a message, see the module documentation."
  @spec bcc(Routing.t(), String.t(), [String.t()]) :: {:ok, [String.t()]} | {:error, String.t()}
  def bcc(routing, sender, recipients) do
    always = if routing.always_bcc, do: [routing.always_bcc], else: []
    senders = if sender == "", do: [], else: [{routing.sender_bcc, sender}]
    lookups = senders ++ Enum.map(recipients, &{routing.recipient_bcc, &1})

    lookups
    |> Enum.reduce_while({:ok, always}, fn {tables, address}, {:ok, acc} ->
      case Routing.lookup(routing, tables, address, catchall: true) do
        {:ok, value, _kind, _ext} -> {:cont, {:ok, acc ++ Routing.addresses(value)}}
        :error -> {:cont, {:ok, acc}}
        {:error, table} -> {:halt, {:error, "cannot read table #{table}"}}
      end
    end)
    |> case do
      {:ok, addresses} ->
        {:ok,
         addresses
         |> Enum.filter(&Routing.valid_address?/1)
         |> Enum.uniq_by(&String.downcase/1)}

      error ->
        error
    end
  end
end
