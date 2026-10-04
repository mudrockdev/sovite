defmodule Sovite.Core.SenderCheck do
  @moduledoc """
  Sender login maps: which `MAIL FROM` addresses an authenticated user
  may use.

  A user may send as their login (when it is an address), and as any
  address matching a pattern for their login in `auth.senders` or in the
  database (`sovitectl user sender add`). A pattern is a full address,
  `@domain` for every address at the domain, or `*` for any address. The
  null sender (`MAIL FROM:<>`) is always allowed. Comparisons ignore
  case.
  """

  @doc "Returns whether `pattern` is a valid sender pattern."
  @spec valid_pattern?(String.t()) :: boolean()
  def valid_pattern?("*"), do: true
  def valid_pattern?("@" <> domain), do: Sovite.Validators.domain?(domain)
  def valid_pattern?(address), do: Sovite.Validators.mailbox?(address)

  @doc "Returns whether `login` may send as `sender`, given its `patterns`."
  @spec allowed?(String.t(), String.t(), [String.t()]) :: boolean()
  def allowed?(_login, "", _patterns), do: true

  def allowed?(login, sender, patterns) do
    sender = String.downcase(sender)
    domain = sender |> String.split("@") |> List.last()

    String.downcase(login) == sender or
      Enum.any?(patterns, fn
        "*" -> true
        "@" <> pattern_domain -> String.downcase(pattern_domain) == domain
        address -> String.downcase(address) == sender
      end)
  end
end
