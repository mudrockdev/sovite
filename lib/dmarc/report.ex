defmodule Sovite.DMARC.Report do
  @moduledoc """
  DMARC aggregate reports (RFC 7489 §7.2 and Appendix C, with the
  `<version>` and `<np>` elements of the DMARCbis aggregate reporting
  draft).

      xml = Sovite.DMARC.Report.aggregate(report)
      name = Sovite.DMARC.Report.filename("mx.example.net", "example.com", from, to, id)
      #=> "mx.example.net!example.com!1700000000!1700086400!id.xml.gz"

  The caller gzips the document and sends it to the `rua` destinations
  that `Sovite.DMARC.report_authorized?/3` allows.
  """

  @typedoc "A DKIM result in a report row."
  @type dkim_auth :: %{domain: String.t(), selector: String.t() | nil, result: atom()}

  @typedoc "An SPF result in a report row."
  @type spf_auth :: %{domain: String.t(), scope: :mfrom | :helo, result: atom()}

  @typedoc "Why a receiver applied a disposition other than the policy's."
  @type reason :: %{type: String.t(), comment: String.t() | nil}

  @typedoc "One row: the messages from one source with the same results."
  @type row :: %{
          source_ip: :inet.ip_address(),
          count: non_neg_integer(),
          disposition: :none | :quarantine | :reject,
          dkim: :pass | :fail,
          spf: :pass | :fail,
          reasons: [reason()],
          header_from: String.t(),
          envelope_from: String.t() | nil,
          envelope_to: String.t() | nil,
          dkim_auth: [dkim_auth()],
          spf_auth: [spf_auth()]
        }

  @typedoc "The policy published by the domain, as it was applied."
  @type policy :: %{
          required(:domain) => String.t(),
          required(:adkim) => :relaxed | :strict,
          required(:aspf) => :relaxed | :strict,
          required(:p) => :none | :quarantine | :reject,
          required(:sp) => :none | :quarantine | :reject,
          required(:pct) => 0..100,
          optional(:np) => :none | :quarantine | :reject | nil
        }

  @type report :: %{
          org_name: String.t(),
          email: String.t(),
          extra_contact_info: String.t() | nil,
          report_id: String.t(),
          begin: DateTime.t(),
          end: DateTime.t(),
          policy: policy(),
          records: [row()]
        }

  @doc """
  Builds the XML document of an aggregate report. The output depends
  only on `report`, and every value is escaped.
  """
  @spec aggregate(report()) :: binary()
  def aggregate(report) do
    feedback =
      {"feedback",
       [
         {"version", "1.0"},
         metadata(report),
         policy_published(report.policy)
         | Enum.map(report.records, &record/1)
       ]}

    IO.iodata_to_binary([~s(<?xml version="1.0" encoding="UTF-8"?>\n), render(feedback, 0)])
  end

  defp metadata(report) do
    {"report_metadata",
     [
       {"org_name", report.org_name},
       {"email", report.email},
       optional("extra_contact_info", report[:extra_contact_info]),
       {"report_id", report.report_id},
       {"date_range",
        [
          {"begin", DateTime.to_unix(report.begin)},
          {"end", DateTime.to_unix(report.end)}
        ]}
     ]}
  end

  defp policy_published(policy) do
    {"policy_published",
     [
       {"domain", policy.domain},
       {"adkim", mode(policy.adkim)},
       {"aspf", mode(policy.aspf)},
       {"p", policy.p},
       {"sp", policy.sp},
       optional("np", policy[:np]),
       {"pct", policy.pct}
     ]}
  end

  defp record(record) do
    {"record",
     [
       {"row",
        [
          {"source_ip", record.source_ip |> :inet.ntoa() |> to_string()},
          {"count", record.count},
          {"policy_evaluated",
           [
             {"disposition", record.disposition},
             {"dkim", record.dkim},
             {"spf", record.spf}
             | Enum.map(record.reasons, &reason/1)
           ]}
        ]},
       {"identifiers",
        [
          optional("envelope_to", record[:envelope_to]),
          optional("envelope_from", record[:envelope_from]),
          {"header_from", record.header_from}
        ]},
       {"auth_results", Enum.map(record.dkim_auth, &dkim/1) ++ Enum.map(record.spf_auth, &spf/1)}
     ]}
  end

  defp reason(reason),
    do: {"reason", [{"type", reason.type}, optional("comment", reason[:comment])]}

  defp dkim(auth) do
    {"dkim",
     [
       {"domain", auth.domain},
       optional("selector", auth[:selector]),
       {"result", auth.result}
     ]}
  end

  defp spf(auth),
    do: {"spf", [{"domain", auth.domain}, {"scope", auth.scope}, {"result", auth.result}]}

  defp mode(:relaxed), do: "r"
  defp mode(:strict), do: "s"

  defp optional(_name, nil), do: nil
  defp optional(name, value), do: {name, value}

  # An element is {name, children} or {name, text}; nil children are
  # left out.
  defp render({name, children}, depth) when is_list(children) do
    indent = String.duplicate("  ", depth)

    case Enum.reject(children, &is_nil/1) do
      [] ->
        [indent, "<", name, "/>\n"]

      children ->
        [
          [indent, "<", name, ">\n"],
          Enum.map(children, &render(&1, depth + 1)),
          [indent, "</", name, ">\n"]
        ]
    end
  end

  defp render({name, value}, depth),
    do: [String.duplicate("  ", depth), "<", name, ">", escape(value), "</", name, ">\n"]

  defp escape(value) when is_atom(value) or is_integer(value), do: escape(to_string(value))

  defp escape(value) when is_binary(value) do
    # XML 1.0 has no way to write most control characters.
    value
    |> String.replace(~r/[\x00-\x08\x0b\x0c\x0e-\x1f]/, "")
    |> String.replace(["&", "<", ">", "\"", "'"], fn
      "&" -> "&amp;"
      "<" -> "&lt;"
      ">" -> "&gt;"
      "\"" -> "&quot;"
      "'" -> "&apos;"
    end)
  end

  @doc """
  The file name of an aggregate report (RFC 7489 §7.2.1.1):
  `receiver!policy-domain!begin!end!unique-id.xml.gz`, with the times as
  Unix timestamps. An empty `unique_id` is left out.
  """
  @spec filename(String.t(), String.t(), DateTime.t(), DateTime.t(), String.t()) :: String.t()
  def filename(receiver, policy_domain, begin, finish, unique_id) do
    parts = [receiver, policy_domain, DateTime.to_unix(begin), DateTime.to_unix(finish)]
    parts = if unique_id == "", do: parts, else: parts ++ [unique_id]
    Enum.join(parts, "!") <> ".xml.gz"
  end
end
