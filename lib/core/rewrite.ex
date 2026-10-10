defmodule Sovite.Core.Rewrite do
  @moduledoc """
  Address rewriting.

  ## Rewrites

  The address rewrites in the database (`sovitectl rewrite`) change
  sender addresses (kind `sender`), recipient addresses (`recipient`), or
  both. A rewrite for the specific kind wins over one for both; only one
  applies to an address. Keys tried (see `Sovite.Core.Routing.lookup/4`):
  `user+ext@domain`, `user@domain`, the bare local part for hosted
  domains, then `@domain`. Replacements:

    * `new@example.net` - replaces the address. An extension the pattern
      did not match is kept: with `alice@example.com -> new@example.net`,
      `alice+x@example.com` becomes `new+x@example.net`.
    * `@example.net` - replaces only the domain.
    * `new` - replaces only the local part.

  ## Hiding subdomains

  `routing.hide_subdomains` hides host names in sender addresses: with
  `["example.com"]`, `alice@host.example.com` becomes
  `alice@example.com`. An entry `!sub.example.com` keeps that domain and
  its subdomains as they are; entries are tried in order. Local parts in
  `routing.hide_subdomains_exceptions` (such as `root`) are never
  changed. This applies to the envelope sender and to the addresses in
  the header.

  ## Header addresses

  With `routing.rewrite_headers` (the default), the addresses in `From:`,
  `Sender:`, `Reply-To:`, `Resent-From:`, and `Resent-Sender:` are
  rewritten like the sender, and those in `To:`, `Cc:`, `Bcc:`,
  `Resent-To:`, `Resent-Cc:`, and `Resent-Bcc:` like recipients, but only
  in mail from trusted networks and authenticated clients: Sovite does
  not change the header of mail from the internet.
  """

  alias Sovite.Core.Routing
  alias Sovite.Message.AddressList
  alias Sovite.Validators

  @sender_headers ~w(from sender reply-to resent-from resent-sender)
  @recipient_headers ~w(to cc bcc resent-to resent-cc resent-bcc)

  @doc """
  Rewrites an envelope sender: the address rewrites, then hiding
  subdomains. The null sender stays null. Returns `{:error, table}` when
  a table cannot be read.
  """
  @spec sender(Routing.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def sender(_routing, ""), do: {:ok, ""}

  def sender(routing, address) do
    with {:ok, address} <- rewrite(routing, routing.sender_rewrites, address) do
      {:ok, hide_subdomains(routing, address)}
    end
  end

  @doc "Rewrites an envelope recipient with the address rewrites."
  @spec recipient(Routing.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def recipient(routing, address), do: rewrite(routing, routing.recipient_rewrites, address)

  defp rewrite(_routing, [], address), do: {:ok, address}

  defp rewrite(routing, tables, address) do
    {local, domain} = Routing.split(address)
    hosted = domain != nil and Routing.hosted?(routing, domain)

    case Routing.lookup(routing, tables, address, local_part: hosted, catchall: true) do
      {:ok, value, _kind, ext} -> {:ok, apply_value(routing, address, local, value, ext)}
      :error -> {:ok, address}
      {:error, _table} = error -> error
    end
  end

  defp apply_value(routing, address, local, value, ext) do
    {_old_local, domain} = Routing.split(address)

    new =
      case String.trim(value) do
        "@" <> new_domain -> "#{local}@#{new_domain}"
        new -> if String.contains?(new, "@"), do: new, else: "#{new}@#{domain}"
      end

    new = Routing.add_extension(routing, new, ext)
    # A value that is not an address is a table mistake: keep the original.
    if Routing.valid_address?(new), do: new, else: address
  end

  @doc "Hides the subdomain in `address`, see the module documentation."
  @spec hide_subdomains(Routing.t(), String.t()) :: String.t()
  def hide_subdomains(%{hide_subdomains: []}, address), do: address

  def hide_subdomains(routing, address) do
    {local, domain} = Routing.split(address)
    base = local |> String.downcase() |> then(&elem(Routing.extension(routing, &1), 0))

    if domain == nil or MapSet.member?(routing.hide_subdomains_exceptions, base) do
      address
    else
      case parent_domain(routing.hide_subdomains, domain) do
        nil -> address
        target -> "#{local}@#{target}"
      end
    end
  end

  defp parent_domain(entries, domain) do
    Enum.reduce_while(entries, nil, fn
      "!" <> keep, nil ->
        if within?(domain, keep), do: {:halt, nil}, else: {:cont, nil}

      target, nil ->
        cond do
          domain == target -> {:halt, nil}
          String.ends_with?(domain, "." <> target) -> {:halt, target}
          true -> {:cont, nil}
        end
    end)
  end

  defp within?(domain, parent), do: domain == parent or String.ends_with?(domain, "." <> parent)

  @doc """
  Rewrites the addresses in header fields (`Sovite.Message.Headers`
  fields). A table that cannot be read leaves the address as it was.
  """
  @spec header_fields(Routing.t(), [Sovite.Message.Headers.field()]) ::
          [Sovite.Message.Headers.field()]
  def header_fields(routing, fields) do
    if rewrites_headers?(routing) do
      Enum.map(fields, fn
        {name, raw} when name in @sender_headers ->
          {name, AddressList.rewrite_field(raw, &header_sender(routing, &1))}

        {name, raw} when name in @recipient_headers ->
          {name, AddressList.rewrite_field(raw, &header_recipient(routing, &1))}

        field ->
          field
      end)
    else
      fields
    end
  end

  @doc "Whether anything would change header addresses."
  @spec rewrites_headers?(Routing.t()) :: boolean()
  def rewrites_headers?(routing) do
    routing.rewrite_headers and
      (routing.sender_rewrites != [] or routing.recipient_rewrites != [] or
         routing.hide_subdomains != [])
  end

  defp header_sender(routing, address) do
    header_address(address, fn ascii ->
      case sender(routing, ascii) do
        {:ok, new} -> new
        {:error, _table} -> ascii
      end
    end)
  end

  defp header_recipient(routing, address) do
    header_address(address, fn ascii ->
      case recipient(routing, ascii) do
        {:ok, new} -> hide_subdomains(routing, new)
        {:error, _table} -> ascii
      end
    end)
  end

  # Header fields may have domains in U-labels (RFC 6532); the tables
  # have A-labels. An address nothing rewrites keeps the form it had.
  defp header_address(address, rewrite) do
    ascii =
      case Validators.ascii_domain(address) do
        {:ok, ascii} -> ascii
        {:error, _} -> address
      end

    case rewrite.(ascii) do
      ^ascii -> address
      new -> new
    end
  end
end
