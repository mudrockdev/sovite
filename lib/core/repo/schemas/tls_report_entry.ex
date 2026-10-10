defmodule Sovite.Core.Repo.Schemas.TLSReportEntry do
  @moduledoc """
  The TLS outcome of one outgoing SMTP session to a domain's MX host,
  kept until the next TLS-RPT report (RFC 8460) for the domain
  (`Sovite.Core.TLSReports`).
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @result_types [
    :starttls_not_supported,
    :certificate_host_mismatch,
    :certificate_expired,
    :certificate_not_trusted,
    :validation_failure,
    :tlsa_invalid,
    :dnssec_invalid,
    :dane_required,
    :sts_policy_fetch_error,
    :sts_policy_invalid,
    :sts_webpki_invalid
  ]

  schema "tls_report_entries" do
    field(:policy_domain, :string)
    field(:policy_type, Ecto.Enum, values: [:tlsa, :sts, :no_policy_found])
    field(:policy, :string)
    field(:mx_host, :string)
    field(:receiving_ip, :string)
    field(:receiving_helo, :string)
    field(:sending_ip, :string)
    field(:result_type, Ecto.Enum, values: @result_types)
    field(:failure_reason, :string)
    timestamps(type: :utc_datetime, updated_at: false)
  end

  @fields [
    :policy_domain,
    :policy_type,
    :policy,
    :mx_host,
    :receiving_ip,
    :receiving_helo,
    :sending_ip,
    :result_type,
    :failure_reason
  ]

  @doc false
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @fields)
    |> validate_required([:policy_domain, :policy_type, :mx_host, :receiving_ip])
    |> validate_length(:policy_domain, max: 253)
    |> validate_length(:mx_host, max: 253)
    # Text from remote servers: keep it within the columns.
    |> update_change(:receiving_helo, &String.slice(&1, 0, 253))
    |> update_change(:failure_reason, &String.slice(&1, 0, 255))
  end
end
