defmodule Sovite.Core.Config.TransportRules do
  @moduledoc false
  # Defaults and cross-key checks for [dns], [mta_sts], and [tls_rpt].

  alias Sovite.Core.Config.Error

  @spec defaults(map()) :: map()
  def defaults(values) do
    hostname = values.server.hostname

    values
    |> update_in([:mta_sts, :mx], &if(&1 == [], do: [hostname], else: &1))
    |> update_in([:tls_rpt, :report_org], &(&1 || hostname))
    |> update_in([:tls_rpt, :report_from], &(&1 || "postmaster@" <> hostname))
    |> then(
      &update_in(&1, [:tls_rpt, :contact_info], fn info -> info || &1.tls_rpt.report_from end)
    )
  end

  @spec errors(map()) :: [Error.t() | false]
  def errors(values) do
    tls = values.tls.certificate != [] or values.tls.acme.enabled

    [
      (values.mta_sts.serve and not tls) &&
        %Error{
          path: ["mta_sts", "serve"],
          reason: "needs a TLS certificate ([[tls.certificate]] or [tls.acme])"
        },
      # RFC 8461 §3.2: at most a year.
      values.mta_sts.max_age > 31_557_600_000 &&
        %Error{path: ["mta_sts", "max_age"], reason: "must be at most 365.25 days"}
    ]
  end
end
