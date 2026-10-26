defmodule Sovite.Core.Address do
  @moduledoc """
  Mail addresses as every part of the stack splits them: the local part
  and the domain, the extension (`alice+lists`), and the Maildir folder
  of a recipient.
  """

  @doc """
  Splits an address into its local part and lower-cased domain. A bare
  local part (`"postmaster"`) has domain `nil`.

      iex> Sovite.Core.Address.split("Alice@Example.COM")
      {"Alice", "example.com"}
  """
  @spec split(String.t()) :: {String.t(), String.t() | nil}
  def split(address) do
    case :binary.matches(address, "@") do
      [] ->
        {address, nil}

      matches ->
        {at, 1} = List.last(matches)
        local = binary_part(address, 0, at)
        domain = binary_part(address, at + 1, byte_size(address) - at - 1)
        {local, String.downcase(domain, :ascii)}
    end
  end

  @doc """
  Splits the extension off a local part: `"alice+lists"` is `{"alice",
  "+lists"}` with delimiter `"+"`. With several delimiter characters, the
  first one found counts. Returns `{local, nil}` without an extension.

      iex> Sovite.Core.Address.extension("+-", "alice-lists+x")
      {"alice", "-lists+x"}
  """
  @spec extension(String.t() | nil, String.t()) :: {String.t(), String.t() | nil}
  def extension(delimiter, local) when delimiter in [nil, ""], do: {local, nil}

  def extension(delimiter, local) do
    case :binary.match(local, String.graphemes(delimiter)) do
      {at, _} when at > 0 ->
        {binary_part(local, 0, at), binary_part(local, at, byte_size(local) - at)}

      _ ->
        {local, nil}
    end
  end

  @doc """
  The lower-cased user (the local part without its extension), the
  extension without its delimiter (`""` for none), and the domain of
  `address`.

      iex> Sovite.Core.Address.parts("Alice+Lists@Example.com", "+")
      {"alice", "lists", "example.com"}
  """
  @spec parts(String.t(), String.t() | nil) :: {String.t(), String.t(), String.t() | nil}
  def parts(address, delimiter) do
    {local, domain} = split(String.downcase(address))
    {user, extension} = extension(delimiter, local)
    extension = if extension, do: String.slice(extension, 1..-1//1), else: ""
    {user, extension, domain}
  end

  @doc """
  The Maildir folder for `recipient` from a `[maildir]` template:
  `{user}` is the lower-cased local part without its extension,
  `{domain}` the domain, `{address}` both. `:error` when a value cannot
  be part of a path (empty, `.`, `..`, or with `/`).

      iex> Sovite.Core.Address.maildir("/var/mail/{domain}/{user}", "A+x@example.com", "+")
      {:ok, "/var/mail/example.com/a"}
  """
  @spec maildir(String.t(), String.t(), String.t() | nil) :: {:ok, Path.t()} | :error
  def maildir(template, recipient, delimiter) do
    {user, _extension, domain} = parts(recipient, delimiter)
    values = %{"user" => user, "domain" => domain, "address" => "#{user}@#{domain}"}

    if Enum.all?(Map.values(values), &path_safe?/1),
      do:
        {:ok,
         Regex.replace(~r/\{(user|domain|address)\}/, template, fn _, key -> values[key] end)},
      else: :error
  end

  defp path_safe?(value),
    do:
      is_binary(value) and value not in ["", ".", ".."] and
        not String.contains?(value, ["/", <<0>>])
end
