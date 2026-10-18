defmodule Sovite.Queue.Envelope do
  @moduledoc """
  The envelope of a queued message: who sent it, to whom, and how it
  arrived.

  `sender` is `""` for the null reverse-path (`MAIL FROM:<>`).
  `srs_sender`, when set, is the sender to use instead when the message
  is forwarded to another domain: an SRS address (see `Sovite.SRS`).

  `requiretls` is set when the client sent `REQUIRETLS` (RFC 8689): the
  message may only be relayed over TLS verified with DANE or MTA-STS,
  to servers that support `REQUIRETLS` too.

  `smtputf8` is set when the client sent `SMTPUTF8` (RFC 6531): the
  message may have internationalized addresses and UTF-8 header fields
  (RFC 6532), and needs a next hop that supports `SMTPUTF8` too when it
  does.

  `auth_user` is the login of the client that submitted the message, if
  it authenticated, so delivery failures can be traced back to it.

  `content_filter`, when set, is where every recipient's copy goes
  instead (a transport, such as `smtp:[127.0.0.1]:10024`): an
  after-queue content filter, which sends the message back once it has
  checked it.

  `notification` is set on delivery status notifications Sovite
  generates itself: `:failure`, `:delay`, `:success`, or `:double_bounce`
  (a failed notification reported to the postmaster). A failed
  `:double_bounce` is never reported again, so notifications cannot loop.

  The DSN parameters (RFC 3461): `ret` and `envid` from `MAIL`, and in
  `dsn` the `NOTIFY` and `ORCPT` of recipients, by address (also for
  the aliases in `expanded`). `expanded` lists aliases that expanded to
  several recipients and asked for `NOTIFY=SUCCESS`: they get an
  "expanded" notification.

  `priority` is the `MT-PRIORITY` (RFC 6710), 0 by default. `hold` is a
  `FUTURERELEASE` request (RFC 4865): the message is not delivered
  before its release time. `deliver_by` is a `DELIVERBY` request (RFC
  2852): the deadline, and whether to return the message (`:return`) or
  notify the sender (`:notify`) when it passes. `rrvs` has the `RRVS`
  of recipients (RFC 7293), for the next hop to check.

  `tenant` names the customer the message belongs to, on servers that
  host several. `forwarded_from` is set on a message another node of a
  cluster handed over for delivery: the name of that node.
  """

  alias Sovite.SMTP.{DSNParams, Params}

  @enforce_keys [:queue_id, :sender, :recipients]
  defstruct [
    :queue_id,
    :sender,
    :srs_sender,
    :recipients,
    :received_at,
    :session_id,
    :remote_ip,
    :helo,
    :protocol,
    :body_type,
    :notification,
    :auth_user,
    :content_filter,
    :ret,
    :envid,
    :hold,
    :deliver_by,
    :tenant,
    :forwarded_from,
    requiretls: false,
    smtputf8: false,
    dsn: %{},
    expanded: [],
    priority: 0,
    rrvs: %{}
  ]

  @typedoc "A `DELIVERBY` request."
  @type deliver_by :: %{deadline: DateTime.t(), mode: :return | :notify, trace: boolean()}

  @typedoc "The DSN parameters of one recipient."
  @type recipient_dsn :: %{notify: DSNParams.notify() | nil, orcpt: DSNParams.orcpt() | nil}

  @type t :: %__MODULE__{
          queue_id: String.t(),
          sender: String.t(),
          srs_sender: String.t() | nil,
          recipients: [String.t(), ...],
          received_at: DateTime.t() | nil,
          session_id: String.t() | nil,
          remote_ip: :inet.ip_address() | nil,
          helo: String.t() | nil,
          protocol: String.t() | nil,
          body_type: :"7bit" | :"8bitmime" | :binarymime | nil,
          notification: :failure | :delay | :success | :double_bounce | nil,
          auth_user: String.t() | nil,
          content_filter: String.t() | nil,
          requiretls: boolean(),
          smtputf8: boolean(),
          ret: DSNParams.ret() | nil,
          envid: String.t() | nil,
          dsn: %{String.t() => recipient_dsn()},
          expanded: [String.t()],
          priority: -9..9,
          hold: Params.hold() | nil,
          deliver_by: deliver_by() | nil,
          rrvs: %{String.t() => Params.rrvs()},
          tenant: String.t() | nil,
          forwarded_from: String.t() | nil
        }

  @doc "When the message may be delivered: its `hold`'s release time, or `nil` without one."
  @spec release_time(t()) :: DateTime.t() | nil
  def release_time(%__MODULE__{hold: nil}), do: nil

  def release_time(%__MODULE__{hold: hold} = envelope),
    do: Params.release_time(hold, envelope.received_at || DateTime.utc_now())

  @doc false
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = envelope) do
    %{
      "queue_id" => envelope.queue_id,
      "sender" => envelope.sender,
      "srs_sender" => envelope.srs_sender,
      "recipients" => envelope.recipients,
      "received_at" => envelope.received_at && DateTime.to_iso8601(envelope.received_at),
      "session_id" => envelope.session_id,
      "remote_ip" => envelope.remote_ip && envelope.remote_ip |> :inet.ntoa() |> to_string(),
      "helo" => envelope.helo,
      "protocol" => envelope.protocol,
      "body_type" => envelope.body_type && Atom.to_string(envelope.body_type),
      "notification" => envelope.notification && Atom.to_string(envelope.notification),
      "auth_user" => envelope.auth_user,
      "content_filter" => envelope.content_filter,
      "requiretls" => envelope.requiretls,
      "smtputf8" => envelope.smtputf8,
      "ret" => envelope.ret && Atom.to_string(envelope.ret),
      "envid" => envelope.envid,
      "dsn" => Map.new(envelope.dsn, fn {address, dsn} -> {address, dsn_to_map(dsn)} end),
      "expanded" => envelope.expanded,
      "priority" => envelope.priority,
      "hold" => envelope.hold && Params.format_hold(envelope.hold),
      "deliver_by" => envelope.deliver_by && deliver_by_to_map(envelope.deliver_by),
      "rrvs" =>
        Map.new(envelope.rrvs, fn {address, rrvs} -> {address, Params.encode_rrvs(rrvs)} end),
      "tenant" => envelope.tenant,
      "forwarded_from" => envelope.forwarded_from
    }
  end

  defp deliver_by_to_map(by) do
    %{
      "deadline" => DateTime.to_iso8601(by.deadline),
      "mode" => Atom.to_string(by.mode),
      "trace" => by.trace
    }
  end

  defp dsn_to_map(dsn) do
    %{
      "notify" => dsn.notify && DSNParams.encode_notify(dsn.notify),
      "orcpt" => with({type, address} <- dsn.orcpt, do: type <> ";" <> address)
    }
  end

  @doc false
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_envelope}
  def from_map(%{"queue_id" => id, "sender" => sender, "recipients" => [_ | _] = rcpts} = map)
      when is_binary(id) and is_binary(sender) do
    with true <- Enum.all?(rcpts, &is_binary/1),
         true <- is_nil(map["srs_sender"]) or is_binary(map["srs_sender"]),
         true <- map["requiretls"] in [nil, true, false],
         true <- map["smtputf8"] in [nil, true, false],
         true <- is_nil(map["auth_user"]) or is_binary(map["auth_user"]),
         true <- is_nil(map["content_filter"]) or is_binary(map["content_filter"]),
         true <- is_nil(map["envid"]) or is_binary(map["envid"]),
         true <- is_nil(map["tenant"]) or is_binary(map["tenant"]),
         true <- is_nil(map["forwarded_from"]) or is_binary(map["forwarded_from"]),
         {:ok, ret} <- optional(map["ret"], &parse_ret/1),
         {:ok, dsn} <- parse_dsn(Map.get(map, "dsn", %{})),
         expanded = Map.get(map, "expanded", []),
         true <- is_list(expanded) and Enum.all?(expanded, &is_binary/1),
         priority = Map.get(map, "priority", 0),
         true <- priority in -9..9,
         {:ok, hold} <- optional(map["hold"], &parse_hold/1),
         {:ok, deliver_by} <- parse_deliver_by(map["deliver_by"]),
         {:ok, rrvs} <- parse_rrvs(Map.get(map, "rrvs", %{})),
         {:ok, received_at} <- optional(map["received_at"], &parse_time/1),
         {:ok, remote_ip} <- optional(map["remote_ip"], &parse_ip/1),
         {:ok, body_type} <- optional(map["body_type"], &parse_body_type/1),
         {:ok, notification} <- optional(map["notification"], &parse_notification/1) do
      {:ok,
       %__MODULE__{
         queue_id: id,
         sender: sender,
         srs_sender: map["srs_sender"],
         recipients: rcpts,
         received_at: received_at,
         session_id: map["session_id"],
         remote_ip: remote_ip,
         helo: map["helo"],
         protocol: map["protocol"],
         body_type: body_type,
         notification: notification,
         auth_user: map["auth_user"],
         content_filter: map["content_filter"],
         requiretls: map["requiretls"] == true,
         smtputf8: map["smtputf8"] == true,
         ret: ret,
         envid: map["envid"],
         dsn: dsn,
         expanded: expanded,
         priority: priority,
         hold: hold,
         deliver_by: deliver_by,
         rrvs: rrvs,
         tenant: map["tenant"],
         forwarded_from: map["forwarded_from"]
       }}
    else
      _ -> {:error, :invalid_envelope}
    end
  end

  def from_map(_map), do: {:error, :invalid_envelope}

  defp optional(nil, _parse), do: {:ok, nil}
  defp optional(value, parse) when is_binary(value), do: parse.(value)
  defp optional(_value, _parse), do: :error

  defp parse_time(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> {:ok, time}
      {:error, _} -> :error
    end
  end

  defp parse_ip(value) do
    case :inet.parse_strict_address(String.to_charlist(value)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  # Fixed table: never create atoms from file contents.
  defp parse_body_type("7bit"), do: {:ok, :"7bit"}
  defp parse_body_type("8bitmime"), do: {:ok, :"8bitmime"}
  defp parse_body_type("binarymime"), do: {:ok, :binarymime}
  defp parse_body_type(_), do: :error

  defp parse_notification("failure"), do: {:ok, :failure}
  defp parse_notification("delay"), do: {:ok, :delay}
  defp parse_notification("success"), do: {:ok, :success}
  defp parse_notification("double_bounce"), do: {:ok, :double_bounce}
  defp parse_notification(_), do: :error

  defp parse_ret("full"), do: {:ok, :full}
  defp parse_ret("hdrs"), do: {:ok, :hdrs}
  defp parse_ret(_), do: :error

  defp parse_dsn(map) when is_map(map) do
    Enum.reduce_while(map, {:ok, %{}}, fn
      {address, %{} = dsn}, {:ok, acc} when is_binary(address) ->
        with {:ok, notify} <- optional(dsn["notify"], &DSNParams.parse_notify/1),
             {:ok, orcpt} <- optional(dsn["orcpt"], &parse_orcpt/1) do
          {:cont, {:ok, Map.put(acc, address, %{notify: notify, orcpt: orcpt})}}
        else
          _ -> {:halt, :error}
        end

      _other, _acc ->
        {:halt, :error}
    end)
  end

  defp parse_dsn(_value), do: :error

  defp parse_hold("for;" <> seconds), do: Params.parse_holdfor(seconds) |> tagged(:for)
  defp parse_hold("until;" <> time), do: Params.parse_holduntil(time) |> tagged(:until)
  defp parse_hold(_value), do: :error

  defp tagged({:ok, value}, tag), do: {:ok, {tag, value}}
  defp tagged(:error, _tag), do: :error

  defp parse_deliver_by(nil), do: {:ok, nil}

  defp parse_deliver_by(%{"deadline" => deadline, "mode" => mode, "trace" => trace})
       when mode in ["return", "notify"] and is_boolean(trace) do
    with {:ok, deadline} <- optional(deadline, &parse_time/1) do
      {:ok,
       %{deadline: deadline, mode: if(mode == "return", do: :return, else: :notify), trace: trace}}
    end
  end

  defp parse_deliver_by(_value), do: :error

  defp parse_rrvs(map) when is_map(map) do
    Enum.reduce_while(map, {:ok, %{}}, fn
      {address, value}, {:ok, acc} when is_binary(address) and is_binary(value) ->
        case Params.parse_rrvs(value) do
          {:ok, rrvs} -> {:cont, {:ok, Map.put(acc, address, rrvs)}}
          :error -> {:halt, :error}
        end

      _other, _acc ->
        {:halt, :error}
    end)
  end

  defp parse_rrvs(_value), do: :error

  defp parse_orcpt(value) do
    case :binary.split(value, ";") do
      [type, address] when type != "" -> {:ok, {type, address}}
      _ -> :error
    end
  end
end
