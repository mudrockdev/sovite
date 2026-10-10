defmodule Sovite.TLS.TLSRPT do
  @moduledoc """
  SMTP TLS Reporting (TLS-RPT, RFC 8460): finding where a domain wants
  its reports, building the JSON report, and sending it.

      {:ok, uris} = TLSRPT.discover(resolver, "example.com")
      #=> {:ok, ["mailto:tlsrpt@example.com", "https://reports.example.com/tlsrpt"]}

      json = TLSRPT.report(report)
      gzip = :zlib.gzip(json)
      name = TLSRPT.filename("mx.example.net", "example.com", from, to, id)
      #=> "mx.example.net!example.com!1700000000!1700086400!id.json.gz"

  Each destination gets the gzipped report: a `mailto:` one as the mail
  `message/1` builds, queued by the caller, and an `https:` one with
  `post/3`.

  A report covers one policy domain and one period, usually a UTC day
  (RFC 8460 §4.1). It has one entry per policy that was applied: the
  domain's DANE TLSA records, its MTA-STS policy, or `:no_policy_found`,
  with the number of successful and failed sessions and the failures
  grouped by their result type and hosts.
  """

  alias Sovite.DNS
  alias Sovite.Message.{Date, MessageID}

  @typedoc """
  Why a session failed (RFC 8460 §4.3). `result_type_name/1` gives the
  name used in reports.
  """
  @type result_type ::
          :starttls_not_supported
          | :certificate_host_mismatch
          | :certificate_expired
          | :certificate_not_trusted
          | :validation_failure
          | :tlsa_invalid
          | :dnssec_invalid
          | :dane_required
          | :sts_policy_fetch_error
          | :sts_policy_invalid
          | :sts_webpki_invalid

  @typedoc "The kind of policy a report entry is about (RFC 8460 §4.4)."
  @type policy_type :: :tlsa | :sts | :no_policy_found

  @typedoc """
  A group of failed sessions with the same result and hosts. Every
  member but `result_type` and `count` may be `nil`, and is then left
  out of the report.
  """
  @type failure :: %{
          required(:result_type) => result_type(),
          required(:count) => pos_integer(),
          optional(:sending_mta_ip) => :inet.ip_address() | nil,
          optional(:receiving_mx_hostname) => String.t() | nil,
          optional(:receiving_mx_helo) => String.t() | nil,
          optional(:receiving_ip) => :inet.ip_address() | nil,
          optional(:additional_information) => String.t() | nil,
          optional(:failure_reason_code) => String.t() | nil
        }

  @typedoc """
  One applied policy and its sessions. `string` is the policy as lines:
  the TLSA records in presentation format, or the lines of the MTA-STS
  policy. `mx_host` lists the MX patterns of an MTA-STS policy, or the
  MX host of a TLSA policy. Empty lists are left out of the report.
  """
  @type policy :: %{
          required(:type) => policy_type(),
          required(:domain) => String.t(),
          required(:successful) => non_neg_integer(),
          required(:failed) => non_neg_integer(),
          optional(:string) => [String.t()],
          optional(:mx_host) => [String.t()],
          optional(:failures) => [failure()]
        }

  @typedoc """
  A report. `contact_info` is an address or URI to reach the reporting
  organization; `begin` and `end` bound the reported period.
  """
  @type report :: %{
          required(:organization_name) => String.t(),
          required(:report_id) => String.t(),
          required(:begin) => DateTime.t(),
          required(:end) => DateTime.t(),
          required(:policies) => [policy()],
          optional(:contact_info) => String.t() | nil
        }

  @typedoc "The report mail, see `message/1`."
  @type message_opts :: %{
          required(:from) => String.t(),
          required(:to) => [String.t(), ...],
          required(:domain) => String.t(),
          required(:submitter) => String.t(),
          required(:report_id) => String.t(),
          required(:filename) => String.t(),
          required(:gzip) => binary(),
          required(:hostname) => String.t(),
          optional(:date) => DateTime.t(),
          optional(:message_id) => String.t(),
          optional(:boundary) => String.t()
        }

  @typedoc "Why no report destinations were found."
  @type record_error :: :no_record | :multiple_records | :invalid_record

  @result_types [
    starttls_not_supported: "starttls-not-supported",
    certificate_host_mismatch: "certificate-host-mismatch",
    certificate_expired: "certificate-expired",
    certificate_not_trusted: "certificate-not-trusted",
    validation_failure: "validation-failure",
    tlsa_invalid: "tlsa-invalid",
    dnssec_invalid: "dnssec-invalid",
    dane_required: "dane-required",
    sts_policy_fetch_error: "sts-policy-fetch-error",
    sts_policy_invalid: "sts-policy-invalid",
    sts_webpki_invalid: "sts-webpki-invalid"
  ]

  @policy_types [tlsa: "tlsa", sts: "sts", no_policy_found: "no-policy-found"]

  ## Policy discovery

  @doc """
  Looks up the TLS-RPT record of `domain`, at `_smtp._tls.<domain>`, and
  returns its report destinations. See `parse_record/1`.

  NXDOMAIN and an empty answer are `{:error, :no_record}`; other DNS
  failures are `{:error, {:dns, reason}}`.
  """
  @spec discover(DNS.resolver(), String.t()) ::
          {:ok, [String.t(), ...]} | {:error, record_error() | {:dns, term()}}
  def discover(resolver, domain) do
    case DNS.lookup(resolver, "_smtp._tls." <> String.trim_trailing(domain, "."), :txt) do
      {:ok, txts} -> parse_record(txts)
      {:error, :nxdomain} -> {:error, :no_record}
      {:error, reason} -> {:error, {:dns, reason}}
    end
  end

  @doc """
  Parses the TXT records found at `_smtp._tls.<domain>` (RFC 8460 §3)
  and returns the `rua` URIs a report can be sent to, in order.

  Only records starting with `v=TLSRPTv1` count; the match is
  case-sensitive, as the ABNF's `%s` says. There must be exactly one.
  Fields are separated by `;` with optional whitespace, and unknown
  fields are ignored. Of the `rua` URIs, only `mailto:` and `https:`
  ones are kept; if none is left, the record is invalid.

      iex> Sovite.TLS.TLSRPT.parse_record(["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"])
      {:ok, ["mailto:tlsrpt@example.com"]}
  """
  @spec parse_record([String.t()]) :: {:ok, [String.t(), ...]} | {:error, record_error()}
  def parse_record(txts) do
    case Enum.filter(txts, &String.match?(&1, ~r/\Av=TLSRPTv1[ \t]*(;|\z)/)) do
      [] -> {:error, :no_record}
      [record] -> rua(record)
      _ -> {:error, :multiple_records}
    end
  end

  # The first rua field wins. Field names are case-sensitive too.
  defp rua(record) do
    rua =
      record
      |> String.split(";")
      |> Enum.drop(1)
      |> Enum.find_value(fn field ->
        case field |> String.trim() |> :binary.split("=") do
          ["rua", value] -> value
          _ -> nil
        end
      end)

    uris =
      (rua || "")
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.filter(&usable_uri?/1)

    if uris == [], do: {:error, :invalid_record}, else: {:ok, uris}
  end

  # RFC 8460 §3: only mailto: and https: are defined; others are ignored.
  # URI.new/1 lower-cases the scheme.
  defp usable_uri?(uri) do
    case URI.new(uri) do
      {:ok, %URI{scheme: "mailto", path: path}} -> path not in [nil, ""]
      {:ok, %URI{scheme: "https", host: host}} -> host not in [nil, ""]
      _ -> false
    end
  end

  ## Result and policy types

  @doc "Returns every result type, in RFC 8460 §4.3 order."
  @spec result_types() :: [result_type(), ...]
  def result_types, do: Keyword.keys(@result_types)

  @doc """
  The name of a result type in reports (RFC 8460 §4.3).

      iex> Sovite.TLS.TLSRPT.result_type_name(:certificate_expired)
      "certificate-expired"
  """
  @spec result_type_name(result_type()) :: String.t()
  for {type, name} <- @result_types do
    def result_type_name(unquote(type)), do: unquote(name)
  end

  @doc """
  The name of a policy type in reports (RFC 8460 §4.4).

      iex> Sovite.TLS.TLSRPT.policy_type_name(:no_policy_found)
      "no-policy-found"
  """
  @spec policy_type_name(policy_type()) :: String.t()
  for {type, name} <- @policy_types do
    def policy_type_name(unquote(type)), do: unquote(name)
  end

  ## Report

  @doc """
  Builds the JSON document of a report (RFC 8460 §4.4). Members come in
  the RFC's order, so the output depends only on `report`. Times are
  RFC 3339 in UTC, to the second; IP addresses are in text form.
  `nil` members, empty `policy-string` and `mx-host` lists, and an empty
  `failure-details` list are left out.
  """
  @spec report(report()) :: binary()
  def report(report) do
    IO.iodata_to_binary(
      encode(
        {:object,
         [
           {"organization-name", report.organization_name},
           {"date-range",
            {:object,
             [
               {"start-datetime", datetime(report.begin)},
               {"end-datetime", datetime(report.end)}
             ]}},
           {"contact-info", report[:contact_info]},
           {"report-id", report.report_id},
           {"policies", Enum.map(report.policies, &policy/1)}
         ]}
      )
    )
  end

  defp policy(policy) do
    {:object,
     [
       {"policy",
        {:object,
         [
           {"policy-type", policy_type_name(policy.type)},
           {"policy-string", non_empty(policy[:string])},
           {"policy-domain", policy.domain},
           {"mx-host", non_empty(policy[:mx_host])}
         ]}},
       {"summary",
        {:object,
         [
           {"total-successful-session-count", policy.successful},
           {"total-failure-session-count", policy.failed}
         ]}},
       {"failure-details",
        policy |> Map.get(:failures, []) |> Enum.map(&failure/1) |> non_empty()}
     ]}
  end

  defp failure(failure) do
    {:object,
     [
       {"result-type", result_type_name(failure.result_type)},
       {"sending-mta-ip", ip(failure[:sending_mta_ip])},
       {"receiving-mx-hostname", failure[:receiving_mx_hostname]},
       {"receiving-mx-helo", failure[:receiving_mx_helo]},
       {"receiving-ip", ip(failure[:receiving_ip])},
       {"failed-session-count", failure.count},
       {"additional-information", failure[:additional_information]},
       {"failure-reason-code", failure[:failure_reason_code]}
     ]}
  end

  defp datetime(datetime),
    do: datetime |> DateTime.to_unix() |> DateTime.from_unix!() |> DateTime.to_iso8601()

  defp ip(nil), do: nil
  defp ip(ip), do: ip |> :inet.ntoa() |> to_string()

  defp non_empty(nil), do: nil
  defp non_empty([]), do: nil
  defp non_empty(list), do: list

  # Objects are lists of members so their order is kept; nil members are
  # left out.
  defp encode({:object, members}) do
    members =
      for {name, value} <- members, value != nil, do: [JSON.encode!(name), ":", encode(value)]

    ["{", Enum.intersperse(members, ","), "}"]
  end

  defp encode(list) when is_list(list),
    do: ["[", list |> Enum.map(&encode/1) |> Enum.intersperse(","), "]"]

  defp encode(value), do: JSON.encode!(value)

  @doc """
  The file name of a report (RFC 8460 §5.1):
  `submitter!policy-domain!begin!end[!unique-id].json.gz`, with the
  times as Unix timestamps. The unique ID should be letters and digits;
  `nil` or `""` leaves it out.
  """
  @spec filename(String.t(), String.t(), DateTime.t(), DateTime.t(), String.t() | nil) ::
          String.t()
  def filename(submitter, policy_domain, begin, finish, unique_id \\ nil) do
    parts = [submitter, policy_domain, DateTime.to_unix(begin), DateTime.to_unix(finish)]
    parts = if unique_id in [nil, ""], do: parts, else: parts ++ [unique_id]
    Enum.join(parts, "!") <> ".json.gz"
  end

  ## Mail

  @doc """
  Builds the report mail for `mailto:` destinations (RFC 8460 §5.3): a
  `multipart/report` with `report-type="tlsrpt"`, a short text, and the
  gzipped report as an `application/tlsrpt+gzip` attachment.

    * `:from` - the sender address. `:to` - the destination addresses,
      without `mailto:`.
    * `:domain` - the policy domain, and `:submitter` - the domain of
      the reporting organization; both go in the `Subject:` and the
      `TLS-Report-Domain:` and `TLS-Report-Submitter:` fields.
    * `:report_id`, `:filename`, `:gzip` - the report's ID, file name
      (`filename/5`), and gzipped JSON.
    * `:hostname` - the domain of the new `Message-ID:`.
    * `:date`, `:message_id`, `:boundary` - default to now, a new ID, and
      a random boundary.

  Lines end in CRLF; long header fields are folded, and the attachment
  is base64 in lines of 76 characters.
  """
  @spec message(message_opts()) :: iodata()
  def message(opts) do
    boundary = Map.get_lazy(opts, :boundary, &boundary/0)
    date = Map.get_lazy(opts, :date, &DateTime.utc_now/0)
    message_id = Map.get_lazy(opts, :message_id, fn -> MessageID.generate(opts.hostname) end)
    domain = clean(opts.domain)
    submitter = clean(opts.submitter)

    [
      field("From", ["<#{clean(opts.from)}>"]),
      field("To", opts.to |> Enum.map(&"<#{clean(&1)}>,") |> trim_last_comma()),
      field("Date", [Date.format(date)]),
      field("Message-ID", [clean(message_id)]),
      field("Subject", [
        "Report Domain: #{domain}",
        "Submitter: #{submitter}",
        "Report-ID: <#{clean(opts.report_id)}>"
      ]),
      field("TLS-Report-Domain", [domain]),
      field("TLS-Report-Submitter", [submitter]),
      "MIME-Version: 1.0\r\n",
      field("Content-Type", [
        "multipart/report; report-type=\"tlsrpt\";",
        "boundary=\"#{boundary}\""
      ]),
      "\r\n",
      "This is a multipart message in MIME format.\r\n",
      "\r\n--#{boundary}\r\n",
      "Content-Type: text/plain; charset=us-ascii\r\n",
      "Content-Transfer-Encoding: 7bit\r\n",
      "\r\n",
      "This is an aggregate TLS report for #{domain} from #{submitter}.\r\n",
      "\r\n--#{boundary}\r\n",
      "Content-Type: application/tlsrpt+gzip\r\n",
      field("Content-Disposition", ["attachment;", "filename=\"#{quoted(opts.filename)}\""]),
      "Content-Transfer-Encoding: base64\r\n",
      "\r\n",
      opts.gzip |> Base.encode64() |> lines(76),
      "\r\n--#{boundary}--\r\n"
    ]
  end

  defp trim_last_comma(words),
    do: List.update_at(words, -1, &String.trim_trailing(&1, ","))

  # A header field, folded between `words` where the line would be longer
  # than 78 characters (RFC 5322 §2.1.1).
  defp field(name, [first | rest]) do
    {lines, last} =
      Enum.reduce(rest, {[], "#{name}: #{first}"}, fn word, {lines, line} ->
        if byte_size(line) + 1 + byte_size(word) > 78,
          do: {[line | lines], " " <> word},
          else: {lines, line <> " " <> word}
      end)

    [Enum.intersperse(Enum.reverse([last | lines]), "\r\n"), "\r\n"]
  end

  # Caller text in a header field: printable ASCII only, so it cannot
  # end the field.
  defp clean(value) do
    for <<c <- value>>, into: "", do: if(c in 32..126, do: <<c>>, else: "?")
  end

  defp quoted(value), do: value |> clean() |> String.replace(["\\", "\""], &("\\" <> &1))

  defp lines(data, size), do: data |> chunks(size) |> Enum.intersperse("\r\n")

  defp chunks(data, size) when byte_size(data) > size,
    do: [
      binary_part(data, 0, size) | chunks(binary_part(data, size, byte_size(data) - size), size)
    ]

  defp chunks(data, _size), do: [data]

  defp boundary do
    "=_sovite_" <>
      (15 |> :crypto.strong_rand_bytes() |> Base.encode32(case: :lower, padding: false))
  end

  ## HTTPS

  @doc """
  Sends a gzipped report to an `https:` destination (RFC 8460 §5.2): a
  POST with `Content-Type: application/tlsrpt+gzip`. Any 2xx status is
  success; redirects are not followed.

  ## Options

    * `:timeout` - in milliseconds, for connecting and for the response.
      Defaults to 30 seconds.
    * `:cacerts` - CAs to verify the server against. Defaults to the
      system's.
    * `:allow_http` - also accept plain `http:` URLs, for testing.
      Defaults to `false`.

  ## Errors

    * `:invalid_url` - not an `https:` URL with a host.
    * `{:http_status, status}` - the server answered with a status other
      than 2xx.
    * an `:httpc` error, such as `{:failed_connect, _}` or `:timeout`.
  """
  @spec post(String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def post(url, gzip, opts \\ []) do
    with {:ok, uri} <- post_url(url, opts) do
      timeout = Keyword.get(opts, :timeout, 30_000)

      request =
        {String.to_charlist(url), [{~c"user-agent", ~c"sovite"}], ~c"application/tlsrpt+gzip",
         gzip}

      http_opts =
        [timeout: timeout, connect_timeout: timeout, autoredirect: false] ++ ssl(uri, opts)

      case :httpc.request(:post, request, http_opts, body_format: :binary) do
        {:ok, {{_, status, _}, _headers, _body}} when status in 200..299 -> :ok
        {:ok, {{_, status, _}, _headers, _body}} -> {:error, {:http_status, status}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp post_url(url, opts) do
    schemes = if Keyword.get(opts, :allow_http, false), do: ["https", "http"], else: ["https"]

    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host} = uri} when host not in [nil, ""] ->
        if scheme in schemes, do: {:ok, uri}, else: {:error, :invalid_url}

      _ ->
        {:error, :invalid_url}
    end
  end

  defp ssl(%URI{scheme: "https", host: host}, opts) do
    cacerts = Keyword.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0)
    [ssl: Sovite.TLS.client_options(verify: :peer, hostname: host, cacerts: cacerts)]
  end

  defp ssl(_uri, _opts), do: []
end
