defmodule Sovite.Core.PolicyService do
  @moduledoc """
  `check_policy_service ADDRESS` in the restriction chains: asks a
  Postfix policy server (https://www.postfix.org/SMTPD_POLICY_README.html)
  such as postgrey or policyd-spf, with `Sovite.Policy.Client`.

  `ADDRESS` is `inet:host:port`, `unix:/path`, or `spawn:/path/to/program
  args...`, for programs that speak the protocol on their standard input
  and output, as Postfix's spawn(8) runs policyd-spf. Each request uses
  a new connection.

  The request has the attributes Postfix sends; `protocol_state` is the
  stage (`CONNECT`, `EHLO`, `MAIL`, `RCPT`, `DATA`, `END-OF-MESSAGE`).
  The reply's action counts like an access rule (access(5)):

  | Action | Effect |
  |---|---|
  | `OK` | Accept, ending the list. |
  | `DUNNO`, `DEFER_IF_REJECT` | Go on with the next check. |
  | `REJECT [text]`, `DEFER [text]`, `DEFER_IF_PERMIT [text]` | `554 5.7.1`, `450 4.7.1`, `450 4.7.1`. |
  | `4NN`/`5NN [x.y.z] text` | That reply. |
  | `HOLD [text]`, `DISCARD [text]` | Hold or drop the message. |
  | `WARN text`, `INFO text` | Log, and go on. |
  | `PREPEND name: value` | Add the header field at the top of the message. |
  | `REDIRECT address` | Deliver the message to `address` only. |
  | `BCC address` | Also deliver it to `address`. |
  | `FILTER transport:nexthop` | Send it to that content filter (see `smtp.content_filter`). |

  When the server cannot be reached, does not answer within
  `policy.timeout`, or sends something else, `policy.default_action`
  applies (`451 4.3.5 Server configuration problem` by default), and the
  error is reported with `[:sovite, :policy, :client, :error]`.
  """

  alias Sovite.Policy
  alias Sovite.Policy.Client
  alias Sovite.SMTP.Reply

  @version Mix.Project.config()[:version]

  @typedoc "What a check adds to the message, besides a decision."
  @type effect ::
          {:prepend, String.t()}
          | {:redirect, String.t()}
          | {:bcc, String.t()}
          | {:filter, String.t()}

  @typedoc "A decision, as `Sovite.Core.Restrictions` checks make them."
  @type decision ::
          :continue
          | :permit
          | {:reject, Reply.t()}
          | {:hold, String.t()}
          | {:discard, String.t()}
          | {:effect, effect()}

  @doc "Whether `address` is a policy server address."
  @spec valid_address?(String.t()) :: boolean()
  def valid_address?(address), do: match?({:ok, _}, Client.parse_address(address))

  @doc """
  Asks the server at `address` about `stage`. `context` is the
  restriction context: it has `:policy` (`%{timeout, default_action}`,
  the action already parsed) and `:policy_request`, a function that
  returns the attributes of the session.
  """
  @spec check(String.t(), atom(), map()) :: decision()
  def check(address, stage, context) do
    {:ok, server} = Client.parse_address(address)
    settings = context.policy

    attributes =
      context
      |> session_attributes()
      |> Map.merge(%{
        "protocol_state" => protocol_state(stage, context),
        "sender" => context.sender,
        "recipient" => context.recipient
      })

    action =
      with {:ok, text} <- Client.check(server, attributes, timeout: settings.timeout),
           {:ok, action} <- Policy.parse_action(text) do
        action
      else
        _error -> settings.default_action
      end

    decide(action, stage, address)
  end

  defp session_attributes(%{policy_request: request}) when is_function(request, 0),
    do: request.()

  defp session_attributes(context) do
    %{"client_address" => context.client_ip, "helo_name" => context.helo}
  end

  defp protocol_state(:connect, _context), do: "CONNECT"
  defp protocol_state(:helo, context), do: if(context[:esmtp], do: "EHLO", else: "HELO")
  defp protocol_state(:mail, _context), do: "MAIL"
  defp protocol_state(:rcpt, _context), do: "RCPT"
  defp protocol_state(:data, _context), do: "DATA"
  defp protocol_state(:end_of_data, _context), do: "END-OF-MESSAGE"

  defp decide(:ok, _stage, _address), do: :permit
  defp decide(:dunno, _stage, _address), do: :continue
  defp decide({:defer_if_reject, _text}, _stage, _address), do: :continue

  defp decide({:reject, text}, _stage, _address),
    do: {:reject, Reply.new(554, "5.7.1", text || "Access denied")}

  defp decide({kind, text}, _stage, _address) when kind in [:defer, :defer_if_permit],
    do: {:reject, Reply.new(450, "4.7.1", text || "Try again later")}

  defp decide({:reply, code, enhanced, text}, _stage, _address) do
    default = if code >= 500, do: "5.7.1", else: "4.7.1"
    {:reject, Reply.new(code, enhanced || default, text || "Access denied")}
  end

  defp decide({:hold, text}, _stage, _address), do: {:hold, text || "held"}
  defp decide({:discard, text}, _stage, _address), do: {:discard, text || "discarded"}

  defp decide({kind, text}, stage, address) when kind in [:warn, :info] do
    :telemetry.execute([:sovite, :restrictions, :warn], %{}, %{
      stage: stage,
      check: "check_policy_service #{address}",
      text: text || ""
    })

    :continue
  end

  defp decide({kind, value}, _stage, _address) when kind in [:prepend, :redirect, :bcc, :filter],
    do: {:effect, {kind, value}}

  @doc """
  The session part of a request, from what the SMTP handler knows.
  Values that are not known are left out.
  """
  @spec request(map()) :: %{String.t() => term()}
  def request(info) do
    connection = info.connection
    tls = info.tls
    {client_name, reverse_name} = names(info.client_dns)

    %{
      "protocol_name" => protocol_name(info),
      "helo_name" => info.helo,
      "queue_id" => info.queue_id,
      "instance" => info.instance,
      "recipient_count" => info.recipient_count,
      "client_address" => connection.remote_ip,
      "client_port" => Map.get(connection, :remote_port),
      "client_name" => client_name,
      "reverse_client_name" => reverse_name,
      "server_address" => Map.get(connection, :local_ip),
      "server_port" => Map.get(connection, :local_port),
      "sasl_method" => info.identity && info.mechanism,
      "sasl_username" => info.identity,
      "size" => info.size,
      "encryption_protocol" => tls && tls.protocol,
      "encryption_cipher" => tls && tls.cipher,
      "encryption_keysize" => tls && tls[:bits],
      "mail_version" => "Sovite #{@version}"
    }
    |> Map.reject(fn {_name, value} -> value == nil end)
  end

  defp protocol_name(%{lmtp: true}), do: "LMTP"
  defp protocol_name(%{esmtp: true}), do: "ESMTP"
  defp protocol_name(_info), do: "SMTP"

  defp names({:ok, name}), do: {name, name}
  defp names({:unconfirmed, [name | _]}), do: {"unknown", name}
  defp names(_client_dns), do: {"unknown", "unknown"}
end
