defmodule Sovite.Validators do
  @moduledoc """
  Syntax validators for the identifiers that appear in SMTP envelopes.

  All functions are pure, never raise on bad input, and never create atoms.
  Any term that is not a binary is treated as invalid.

  The grammar follows RFC 5321 §4.1.2 and §4.1.3, with the length limits
  from RFC 5321 §4.5.3.1. Only ASCII is accepted for now. Internationalized
  addresses (SMTPUTF8, RFC 6531) come later.
  """

  import Bitwise, only: [band: 2]

  @max_domain 255
  @max_label 63
  @max_local_part 64
  # RFC 5321 §4.5.3.1.3: a path is at most 256 octets including "<" and ">".
  @max_mailbox 254

  @typedoc "Reasons returned by `split_mailbox/1`."
  @type mailbox_error ::
          :missing_at | :invalid_local_part | :local_part_too_long | :invalid_domain | :too_long

  defguardp is_alpha(c) when c in ?a..?z or c in ?A..?Z
  defguardp is_digit(c) when c in ?0..?9
  defguardp is_let_dig(c) when is_alpha(c) or is_digit(c)

  defguardp is_atext(c)
            when is_let_dig(c) or
                   c in [
                     ?!,
                     ?#,
                     ?$,
                     ?%,
                     ?&,
                     ?',
                     ?*,
                     ?+,
                     ?-,
                     ?/,
                     ?=,
                     ??,
                     ?^,
                     ?_,
                     ?`,
                     ?{,
                     ?|,
                     ?},
                     ?~
                   ]

  # qtextSMTP: %d32-33 / %d35-91 / %d93-126
  defguardp is_qtext(c) when c in 32..33 or c in 35..91 or c in 93..126

  @doc """
  Returns `true` if `domain` matches the RFC 5321 `Domain` production.

  Labels are 1-63 letters, digits, or hyphens, and cannot start or end with
  a hyphen. The whole domain is at most 255 octets. Trailing dots are not
  allowed.

      iex> Sovite.Validators.domain?("mail.example.com")
      true
      iex> Sovite.Validators.domain?("-bad.example")
      false
  """
  @spec domain?(term()) :: boolean()
  def domain?(domain) when is_binary(domain) and byte_size(domain) in 1..@max_domain do
    domain
    |> :binary.split(".", [:global])
    |> Enum.all?(&label?/1)
  end

  def domain?(_), do: false

  @doc """
  Returns `true` if `hostname` is a valid domain whose top-level label is
  not all digits (RFC 3696 §2). This rules out IPv4 addresses written as
  domains, such as `"192.0.2.1"`.

      iex> Sovite.Validators.hostname?("mx1.example.net")
      true
      iex> Sovite.Validators.hostname?("192.0.2.1")
      false
  """
  @spec hostname?(term()) :: boolean()
  def hostname?(hostname) do
    domain?(hostname) and not all_digits?(last_label(hostname))
  end

  @doc """
  Returns `true` if `literal` is an RFC 5321 address literal: `[IPv4]` or
  `[IPv6:addr]`.

  General address literals (`[tag:content]`) are rejected because IANA has
  registered no tags besides `IPv6`.

      iex> Sovite.Validators.address_literal?("[192.0.2.1]")
      true
      iex> Sovite.Validators.address_literal?("[IPv6:2001:db8::1]")
      true
  """
  @spec address_literal?(term()) :: boolean()
  def address_literal?(literal), do: match?({:ok, _}, parse_address_literal(literal))

  @doc """
  Parses an RFC 5321 address literal into an `:inet` IP address tuple.

      iex> Sovite.Validators.parse_address_literal("[192.0.2.1]")
      {:ok, {192, 0, 2, 1}}
      iex> Sovite.Validators.parse_address_literal("192.0.2.1")
      {:error, :invalid_address_literal}
  """
  @spec parse_address_literal(term()) ::
          {:ok, :inet.ip_address()} | {:error, :invalid_address_literal}
  def parse_address_literal(literal) when is_binary(literal) and byte_size(literal) > 2 do
    size = byte_size(literal) - 2

    with <<"[", inner::binary-size(^size), "]">> <- literal,
         {:ok, ip} <- parse_literal_body(inner) do
      {:ok, ip}
    else
      _ -> {:error, :invalid_address_literal}
    end
  end

  def parse_address_literal(_), do: {:error, :invalid_address_literal}

  @doc """
  Returns `true` if `helo` is a valid `EHLO`/`HELO` argument: a domain or
  an address literal (RFC 5321 §4.1.1.1).

  This only checks syntax. Whether the name resolves, or matches the
  client's IP, is a policy decision.
  """
  @spec helo?(term()) :: boolean()
  def helo?(helo), do: domain?(helo) or address_literal?(helo)

  @doc """
  Returns `true` if `local_part` is a valid RFC 5321 `Local-part`: a
  dot-string or a quoted string, at most 64 octets.

      iex> Sovite.Validators.local_part?("first.last+tag")
      true
      iex> Sovite.Validators.local_part?(~s("john doe"))
      true
      iex> Sovite.Validators.local_part?("a..b")
      false
  """
  @spec local_part?(term()) :: boolean()
  def local_part?(local_part)
      when is_binary(local_part) and byte_size(local_part) in 1..@max_local_part do
    case local_part do
      <<?", rest::binary>> -> match?({:ok, ""}, scan_quoted(rest))
      _ -> dot_string?(local_part)
    end
  end

  def local_part?(_), do: false

  @doc """
  Returns `true` if `mailbox` is a valid RFC 5321 `Mailbox`
  (`Local-part "@" ( Domain / address-literal )`).

  The angle brackets of a reverse-path or forward-path are not part of the
  mailbox and must be removed before calling this.
  """
  @spec mailbox?(term()) :: boolean()
  def mailbox?(mailbox), do: match?({:ok, _}, split_mailbox(mailbox))

  @doc """
  Validates `mailbox` and splits it into its local part and domain.

  The local part is returned exactly as written. Quoted local parts keep
  their quotes and escapes. The domain is not case-folded.

      iex> Sovite.Validators.split_mailbox("user@example.com")
      {:ok, {"user", "example.com"}}
      iex> Sovite.Validators.split_mailbox(~s("a@b"@example.com))
      {:ok, {~s("a@b"), "example.com"}}
      iex> Sovite.Validators.split_mailbox("user@-example.com")
      {:error, :invalid_domain}
  """
  @spec split_mailbox(term()) :: {:ok, {String.t(), String.t()}} | {:error, mailbox_error()}
  def split_mailbox(mailbox) when is_binary(mailbox) and byte_size(mailbox) > @max_mailbox,
    do: {:error, :too_long}

  def split_mailbox(mailbox) when is_binary(mailbox) do
    with {:ok, local, domain} <- split_at(mailbox),
         :ok <- check_local_part(local),
         :ok <- check_domain(domain) do
      {:ok, {local, domain}}
    end
  end

  def split_mailbox(_), do: {:error, :missing_at}

  ## Domains

  defp label?(<<first, _::binary>> = label)
       when byte_size(label) <= @max_label and is_let_dig(first) do
    last = :binary.last(label)
    is_let_dig(last) and ldh?(label)
  end

  defp label?(_), do: false

  defp ldh?(<<>>), do: true
  defp ldh?(<<c, rest::binary>>) when is_let_dig(c) or c == ?-, do: ldh?(rest)
  defp ldh?(_), do: false

  defp last_label(domain), do: domain |> :binary.split(".", [:global]) |> List.last()

  defp all_digits?(<<>>), do: false

  defp all_digits?(binary),
    do: for(<<c <- binary>>, reduce: true, do: (acc -> acc and is_digit(c)))

  ## Address literals

  # ABNF string literals are case-insensitive, so "ipv6:" is valid too.
  defp parse_literal_body(<<tag::binary-size(5), addr::binary>> = body) do
    if String.downcase(tag, :ascii) == "ipv6:", do: parse_ipv6(addr), else: parse_ipv4(body)
  end

  defp parse_literal_body(body), do: parse_ipv4(body)

  defp parse_ipv4(body) do
    with [_, _, _, _] = parts <- :binary.split(body, ".", [:global]),
         octets = Enum.map(parts, &snum/1),
         false <- :error in octets do
      {:ok, List.to_tuple(octets)}
    else
      _ -> :error
    end
  end

  # Snum = 1*3DIGIT, value 0-255
  defp snum(part) when byte_size(part) in 1..3 do
    with true <- all_digits?(part),
         n when n <= 255 <- String.to_integer(part) do
      n
    else
      _ -> :error
    end
  end

  defp snum(_), do: :error

  # :inet's strict IPv6 parser also accepts zone IDs ("fe80::1%eth0") and
  # needs a charlist, so check the characters first.
  defp parse_ipv6(addr) when byte_size(addr) in 2..45 do
    if ipv6_chars?(addr) do
      case :inet.parse_ipv6strict_address(String.to_charlist(addr)) do
        {:ok, ip} -> {:ok, ip}
        {:error, _} -> :error
      end
    else
      :error
    end
  end

  defp parse_ipv6(_), do: :error

  defp ipv6_chars?(addr) do
    for <<c <- addr>>, reduce: true do
      acc -> acc and (is_digit(c) or band(c, 0xDF) in ?A..?F or c in [?:, ?.])
    end
  end

  ## Local parts

  defp dot_string?(string), do: string |> :binary.split(".", [:global]) |> Enum.all?(&atom?/1)

  defp atom?(<<>>), do: false
  defp atom?(atom), do: for(<<c <- atom>>, reduce: true, do: (acc -> acc and is_atext(c)))

  # Scans the rest of a quoted string after the opening quote. Returns what
  # follows the closing quote.
  defp scan_quoted(<<?", rest::binary>>), do: {:ok, rest}
  defp scan_quoted(<<?\\, c, rest::binary>>) when c in 32..126, do: scan_quoted(rest)
  defp scan_quoted(<<c, rest::binary>>) when is_qtext(c), do: scan_quoted(rest)
  defp scan_quoted(_), do: :error

  ## Mailboxes

  defp split_at(<<?", rest::binary>> = mailbox) do
    case scan_quoted(rest) do
      {:ok, <<?@, domain::binary>>} ->
        local_size = byte_size(mailbox) - byte_size(domain) - 1
        {:ok, binary_part(mailbox, 0, local_size), domain}

      {:ok, _} ->
        {:error, :invalid_local_part}

      :error ->
        {:error, :invalid_local_part}
    end
  end

  defp split_at(mailbox) do
    case :binary.split(mailbox, "@") do
      [local, domain] -> {:ok, local, domain}
      [_] -> {:error, :missing_at}
    end
  end

  defp check_local_part(local) when byte_size(local) > @max_local_part,
    do: {:error, :local_part_too_long}

  defp check_local_part(local),
    do: if(local_part?(local), do: :ok, else: {:error, :invalid_local_part})

  defp check_domain(domain) do
    if domain?(domain) or address_literal?(domain), do: :ok, else: {:error, :invalid_domain}
  end
end
