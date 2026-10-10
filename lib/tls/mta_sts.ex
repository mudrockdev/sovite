defmodule Sovite.TLS.MTASTS do
  @moduledoc """
  SMTP MTA Strict Transport Security (MTA-STS, RFC 8461).

  A domain announces a policy with a TXT record at `_mta-sts.<domain>`
  and serves the policy itself over HTTPS:

      _mta-sts.example.com. IN TXT "v=STSv1; id=20260101T000000"

      # https://mta-sts.example.com/.well-known/mta-sts.txt
      version: STSv1
      mode: enforce
      mx: mx1.example.com
      mx: *.backup.example.com
      max_age: 604800

  A sender that finds the record fetches the policy, caches it for
  `max_age` seconds, and from then on delivers to the domain only over
  TLS with a certificate valid for an MX host that `match?/2` accepts.
  The `id` tells it when to fetch again: it changes whenever the policy
  does.

      {:ok, id} = Sovite.TLS.MTASTS.discover(resolver, "example.com")
      {:ok, policy} = Sovite.TLS.MTASTS.fetch("example.com")
      Sovite.TLS.MTASTS.match?(policy, "mx1.example.com")  #=> true

  Caching, refreshing, and the TLS checks on the MX connection are left
  to the caller. For receiving domains, `policy_text/3` and `policy_id/1`
  build the policy and its id, and `Sovite.TLS.MTASTS.Server` serves it.
  """

  import Kernel, except: [match?: 2]

  alias Sovite.TLS.MTASTS.{Fetch, Policy}

  # RFC 8461 §3.2: max_age is at most 31557600 seconds.
  @max_age 31_557_600

  @modes %{"enforce" => :enforce, "testing" => :testing, "none" => :none}

  @fetch_defaults [timeout: 60_000, max_size: 65_536, cacerts: nil, port: 443, connect_to: nil]

  @typedoc "Why `parse_record/1` or `discover/2` found no usable record."
  @type record_error :: :no_record | :multiple_records | :invalid_record

  @typedoc """
  Why `parse_policy/1` rejected a policy:

    * `:invalid_encoding` - the body is not UTF-8.
    * `{:invalid_line, n}` - line `n` (from 1) is not `key: value`.
    * `:missing_version`, `{:invalid_version, value}` - `version` is
      missing or not `STSv1`.
    * `:missing_mode`, `{:invalid_mode, value}` - `mode` is missing or
      not `enforce`, `testing`, or `none`.
    * `:missing_max_age`, `{:invalid_max_age, value}` - `max_age` is
      missing or not a number of at most 10 digits.
    * `:missing_mx` - no `mx` line, with a mode other than `none`.
    * `{:invalid_mx, value}` - an `mx` value is neither a host name nor
      `*.` and a host name.
  """
  @type policy_error ::
          :invalid_encoding
          | {:invalid_line, pos_integer()}
          | :missing_version
          | {:invalid_version, String.t()}
          | :missing_mode
          | {:invalid_mode, String.t()}
          | :missing_max_age
          | {:invalid_max_age, String.t()}
          | :missing_mx
          | {:invalid_mx, String.t()}

  @typedoc """
  Why `fetch/2` got no policy:

    * `:invalid_domain` - the domain is not a valid domain name.
    * `{:connect, reason}` - the TCP connection failed (`:inet` reasons
      such as `:econnrefused` or `:nxdomain`).
    * `{:tls, reason}` - the TLS handshake failed, including a
      certificate that is not valid for `mta-sts.<domain>` (`:ssl`
      reasons). TLS-RPT (RFC 8460 §4.3.2.2) reports this as
      `sts-webpki-invalid`.
    * `{:http_status, code}` - the status was not 200. Redirects are not
      followed (RFC 8461 §3.3).
    * `:invalid_content_type` - the Content-Type was not `text/plain`.
    * `:too_large` - the body was larger than `:max_size`.
    * `:timeout` - the whole fetch took longer than `:timeout`.
    * `{:invalid_response, detail}` - the HTTP response was malformed:
      `:status_line`, `:header`, `:headers_too_large`,
      `:content_length`, `:transfer_encoding`, `:chunk`, or `:truncated`.
    * `{:invalid_policy, reason}` - the body is not a valid policy, see
      `t:policy_error/0`.
  """
  @type fetch_error ::
          :invalid_domain
          | {:connect, term()}
          | {:tls, term()}
          | {:http_status, 100..999}
          | :invalid_content_type
          | :too_large
          | :timeout
          | {:invalid_response, atom()}
          | {:invalid_policy, policy_error()}

  ## DNS record (RFC 8461 §3.1)

  @doc """
  Finds the policy id in the TXT records at `_mta-sts.<domain>`.

  Records that do not start with `v=STSv1` are ignored. Exactly one must
  be left, and it must be valid (RFC 8461 §3.1):

    * fields are `key=value`, separated by `;` with optional whitespace,
      and a trailing `;` is allowed;
    * `v=STSv1` comes first;
    * `id` is 1 to 32 letters and digits;
    * other fields are ignored, but no key may appear twice.

  Otherwise the domain has no usable policy.

      iex> Sovite.TLS.MTASTS.parse_record(["v=spf1 -all", "v=STSv1; id=20260101"])
      {:ok, "20260101"}
      iex> Sovite.TLS.MTASTS.parse_record(["v=STSv1; id=a", "v=STSv1; id=b"])
      {:error, :multiple_records}
  """
  @spec parse_record([String.t()]) :: {:ok, id :: String.t()} | {:error, record_error()}
  def parse_record(txts) when is_list(txts) do
    case Enum.filter(txts, &sts_record?/1) do
      [] -> {:error, :no_record}
      [record] -> record_id(record)
      [_ | _] -> {:error, :multiple_records}
    end
  end

  defp sts_record?(txt), do: is_binary(txt) and String.starts_with?(txt, "v=STSv1")

  defp record_id(record) do
    fields =
      record
      |> String.replace(~r/[ \t]+\z/, "")
      |> String.split(~r/[ \t]*;[ \t]*/)
      |> drop_trailing_empty()

    with ["v=STSv1" | rest] <- fields,
         {:ok, pairs} <- record_fields(rest, %{}),
         {:ok, id} <- Map.fetch(pairs, "id"),
         true <- Regex.match?(~r/\A[A-Za-z0-9]{1,32}\z/, id) do
      {:ok, id}
    else
      _ -> {:error, :invalid_record}
    end
  end

  defp drop_trailing_empty(fields) do
    case List.last(fields) do
      "" -> Enum.drop(fields, -1)
      _ -> fields
    end
  end

  # sts-extension: a name of up to 32 characters, and a value of
  # printable characters other than "=" and ";".
  defp record_fields([], pairs), do: {:ok, pairs}

  defp record_fields([field | rest], pairs) do
    case Regex.run(~r/\A([A-Za-z0-9][A-Za-z0-9_.-]{0,31})=([\x21-\x3a\x3c\x3e-\x7e]+)\z/, field) do
      [_, name, value] when not is_map_key(pairs, name) and name != "v" ->
        record_fields(rest, Map.put(pairs, name, value))

      _ ->
        :error
    end
  end

  @doc """
  Looks up the TXT records at `_mta-sts.<domain>` and returns the policy
  id, as `parse_record/1` does.

  A name that does not exist and a name without TXT records both give
  `{:error, :no_record}`. Other DNS errors give `{:error, {:dns,
  reason}}`: a sender then keeps using any cached policy (RFC 8461
  §5.1).
  """
  @spec discover(Sovite.DNS.resolver(), String.t()) ::
          {:ok, id :: String.t()}
          | {:error, record_error() | {:dns, Sovite.DNS.Resolver.error()}}
  def discover(resolver, domain) when is_binary(domain) do
    case Sovite.DNS.lookup(resolver, "_mta-sts." <> String.trim_trailing(domain, "."), :txt) do
      {:ok, txts} -> txts |> Enum.filter(&is_binary/1) |> parse_record()
      {:error, :nxdomain} -> {:error, :no_record}
      {:error, reason} -> {:error, {:dns, reason}}
    end
  end

  ## Policy (RFC 8461 §3.2)

  @doc """
  Parses a policy body (RFC 8461 §3.2).

  Lines end with LF or CRLF, and are `key: value` with optional
  whitespace around the colon and at the ends. Blank lines and unknown
  keys are ignored. Keys and the `version` and `mode` values are
  case-sensitive.

    * `version` must be `STSv1`.
    * `mode` must be `enforce`, `testing`, or `none`.
    * `max_age` must be a number of seconds; values above 31557600 are
      lowered to it.
    * `mx` may appear several times, and at least once unless the mode
      is `none`. Each is a host name, or `*.` and a host name.

  Only `mx` may repeat: for the other keys the first line counts.

      iex> {:ok, policy} = Sovite.TLS.MTASTS.parse_policy("version: STSv1\\nmode: enforce\\nmx: MX.example.com\\nmax_age: 86400\\n")
      iex> {policy.mode, policy.mx, policy.max_age}
      {:enforce, ["mx.example.com"], 86400}
  """
  @spec parse_policy(binary()) :: {:ok, Policy.t()} | {:error, policy_error()}
  def parse_policy(text) when is_binary(text) do
    if String.valid?(text) do
      text
      |> String.split(["\r\n", "\n"])
      |> Enum.with_index(1)
      |> policy_fields(%{"mx" => []})
      |> build_policy(text)
    else
      {:error, :invalid_encoding}
    end
  end

  defp policy_fields([], fields), do: {:ok, fields}

  defp policy_fields([{line, number} | rest], fields) do
    case Regex.run(
           ~r/\A[ \t]*(?:([A-Za-z0-9][A-Za-z0-9_.-]{0,31})[ \t]*:[ \t]*(.*?))?[ \t]*\z/s,
           line
         ) do
      [_] -> policy_fields(rest, fields)
      [_, "mx", value] -> policy_fields(rest, Map.update!(fields, "mx", &[value | &1]))
      [_, key, value] -> policy_fields(rest, Map.put_new(fields, key, value))
      nil -> {:error, {:invalid_line, number}}
    end
  end

  defp build_policy({:error, _} = error, _text), do: error

  defp build_policy({:ok, fields}, text) do
    with :ok <- version(fields["version"]),
         {:ok, mode} <- mode(fields["mode"]),
         {:ok, max_age} <- max_age(fields["max_age"]),
         {:ok, mx} <- mx(Enum.reverse(fields["mx"]), mode) do
      {:ok, %Policy{mode: mode, mx: mx, max_age: max_age, text: text}}
    end
  end

  defp version(nil), do: {:error, :missing_version}
  defp version("STSv1"), do: :ok
  defp version(value), do: {:error, {:invalid_version, value}}

  defp mode(nil), do: {:error, :missing_mode}

  defp mode(value) do
    case Map.fetch(@modes, value) do
      {:ok, mode} -> {:ok, mode}
      :error -> {:error, {:invalid_mode, value}}
    end
  end

  defp max_age(nil), do: {:error, :missing_max_age}

  defp max_age(value) do
    if Regex.match?(~r/\A[0-9]{1,10}\z/, value),
      do: {:ok, min(String.to_integer(value), @max_age)},
      else: {:error, {:invalid_max_age, value}}
  end

  defp mx([], mode) when mode != :none, do: {:error, :missing_mx}

  defp mx(values, _mode) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      pattern = String.downcase(value, :ascii)

      if mx_pattern?(pattern),
        do: {:cont, {:ok, [pattern | acc]}},
        else: {:halt, {:error, {:invalid_mx, value}}}
    end)
    |> case do
      {:ok, patterns} -> {:ok, Enum.reverse(patterns)}
      error -> error
    end
  end

  defp mx_pattern?("*." <> host), do: Sovite.Validators.hostname?(host)
  defp mx_pattern?(host), do: Sovite.Validators.hostname?(host)

  @doc """
  Returns whether the MX host `host` is allowed by `policy` (RFC 8461
  §4.1).

  Names are compared case-insensitively, ignoring a trailing dot. A
  `*.example.com` pattern matches any name with exactly one more label
  on the left: `mx1.example.com`, but neither `example.com` nor
  `a.b.example.com`.

      iex> policy = %Sovite.TLS.MTASTS.Policy{mode: :enforce, mx: ["*.example.com"], max_age: 86400, text: ""}
      iex> Sovite.TLS.MTASTS.match?(policy, "MX1.example.com.")
      true
      iex> Sovite.TLS.MTASTS.match?(policy, "a.b.example.com")
      false
  """
  @spec match?(Policy.t(), String.t()) :: boolean()
  def match?(%Policy{mx: patterns}, host) when is_binary(host) do
    host = normalize(host)
    Enum.any?(patterns, &pattern_match?(normalize(&1), host))
  end

  defp pattern_match?("*." <> suffix, host) do
    case :binary.split(host, ".") do
      [label, ^suffix] -> label != ""
      _ -> false
    end
  end

  defp pattern_match?(pattern, host), do: pattern == host

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)

  ## Fetching (RFC 8461 §3.3)

  @doc """
  Returns the host that serves the policy for `domain`.

      iex> Sovite.TLS.MTASTS.policy_host("example.com")
      "mta-sts.example.com"
  """
  @spec policy_host(String.t()) :: String.t()
  def policy_host(domain), do: "mta-sts." <> domain

  @doc """
  Returns the URL of the policy for `domain`.

      iex> Sovite.TLS.MTASTS.policy_url("example.com")
      "https://mta-sts.example.com/.well-known/mta-sts.txt"
  """
  @spec policy_url(String.t()) :: String.t()
  def policy_url(domain), do: "https://" <> policy_host(domain) <> "/.well-known/mta-sts.txt"

  @doc """
  Fetches and parses the policy for `domain` (RFC 8461 §3.3).

  Sends `GET /.well-known/mta-sts.txt` over HTTPS to
  `mta-sts.<domain>`. The server's certificate must be valid for that
  name (PKIX, with SNI). Only a `200` response with Content-Type
  `text/plain` is accepted: redirects are not followed. The body may be
  sent with Content-Length, chunked, or until the connection closes.

  ## Options

    * `:timeout` - milliseconds for the whole fetch: connecting, the TLS
      handshake, and reading the response. Defaults to 60 seconds.
    * `:max_size` - the largest body accepted, in bytes. Defaults to
      65536.
    * `:cacerts` - trusted CA certificates (DER). Defaults to the
      system's (`:public_key.cacerts_get/0`).
    * `:port` - the TCP port. Defaults to 443.
    * `:connect_to` - an `{ip, port}` tuple or a host name (charlist) to
      connect to instead of `mta-sts.<domain>`, for tests and proxies.
      SNI and the certificate check still use `mta-sts.<domain>`.

  See `t:fetch_error/0` for the errors.
  """
  @spec fetch(String.t(), keyword()) :: {:ok, Policy.t()} | {:error, fetch_error()}
  def fetch(domain, opts \\ []) when is_binary(domain) do
    opts = Keyword.validate!(opts, @fetch_defaults)
    domain = normalize(domain)

    with true <- Sovite.Validators.domain?(domain) || {:error, :invalid_domain},
         {:ok, body} <- Fetch.get(policy_host(domain), "/.well-known/mta-sts.txt", opts) do
      case parse_policy(body) do
        {:ok, policy} -> {:ok, policy}
        {:error, reason} -> {:error, {:invalid_policy, reason}}
      end
    end
  end

  ## Publishing

  @doc """
  Builds a policy body, with CRLF line endings.

      iex> Sovite.TLS.MTASTS.policy_text(:testing, ["mx.example.com"], 604800)
      "version: STSv1\\r\\nmode: testing\\r\\nmx: mx.example.com\\r\\nmax_age: 604800\\r\\n"
  """
  @spec policy_text(Policy.mode(), [String.t()], non_neg_integer()) :: String.t()
  def policy_text(mode, mx, max_age)
      when mode in [:enforce, :testing, :none] and is_list(mx) and is_integer(max_age) and
             max_age >= 0 do
    ["version: STSv1", "mode: #{mode}"]
    |> Enum.concat(Enum.map(mx, &"mx: #{&1}"))
    |> Enum.concat(["max_age: #{max_age}"])
    |> Enum.map_join(&(&1 <> "\r\n"))
  end

  @doc """
  Returns an id for the policy `text`, for the `id=` field of the
  `_mta-sts` record: the first 20 hex digits of its SHA-256. It changes
  exactly when the policy does, so senders refetch only then.
  """
  @spec policy_id(String.t()) :: String.t()
  def policy_id(text) when is_binary(text) do
    :sha256 |> :crypto.hash(text) |> Base.encode16(case: :lower) |> binary_part(0, 20)
  end
end
