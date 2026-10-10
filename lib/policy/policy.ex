defmodule Sovite.Policy do
  @moduledoc """
  The Postfix SMTP access policy delegation protocol
  (<https://www.postfix.org/SMTPD_POLICY_README.html>), for asking policy
  servers such as policyd-spf and postgrey what to do with an SMTP
  client, and for writing such servers in Elixir.

  A request is a block of `name=value` lines, each ended by a newline,
  followed by an empty line. The reply is a block of the same form with
  an `action` attribute, whose value is anything allowed in a Postfix
  access(5) table, such as `DUNNO` or `REJECT go away`. One connection
  can carry any number of requests, one after the other.

      request=smtpd_access_policy
      protocol_state=RCPT
      client_address=192.0.2.7
      sender=alice@example.com
      recipient=bob@example.net

      action=DEFER_IF_PERMIT Greylisted, try again later

  This module encodes and decodes the blocks. `Sovite.Policy.Client`
  asks a policy server, `Sovite.Policy.Server` runs one, and
  `Sovite.Policy.Action` turns actions into terms and back.

  ## Attributes

  Requests take a map or a list of attributes: names are strings or atoms
  (so a keyword list works), values are strings, integers, IP address
  tuples, or `nil` for an empty value. `postfix_attributes/0` lists the
  names Postfix sends; any other valid name can be sent too.
  """

  alias Sovite.Policy.{Action, Codec}

  @postfix_attributes ~w(
    request protocol_state protocol_name helo_name queue_id sender recipient
    recipient_count client_address client_name reverse_client_name instance
    sasl_method sasl_username sasl_sender size ccert_subject ccert_issuer
    ccert_fingerprint ccert_pubkey_fingerprint encryption_protocol
    encryption_cipher encryption_keysize etrn_domain stress client_port
    policy_context server_address server_port compatibility_level mail_version
  )

  @typedoc """
  The attributes Postfix sends to a policy server, as of Postfix 3.8:

    * `request` - always `smtpd_access_policy`.
    * `protocol_state` - the SMTP command: `CONNECT`, `EHLO`, `HELO`,
      `MAIL`, `RCPT`, `DATA`, `END-OF-MESSAGE`, `VRFY`, or `ETRN`.
    * `protocol_name` - `SMTP`, `ESMTP`, or `LMTP`.
    * `helo_name`, `queue_id`, `sender`, `recipient`, `recipient_count`.
    * `client_address`, `client_name` (verified, or `unknown`),
      `reverse_client_name` (unverified), `client_port`.
    * `server_address`, `server_port` - where the client connected to.
    * `instance` - the same for every request of one message.
    * `sasl_method`, `sasl_username`, `sasl_sender`.
    * `size` - from `MAIL FROM ... SIZE=`, or the actual size at
      `END-OF-MESSAGE`.
    * `ccert_subject`, `ccert_issuer`, `ccert_fingerprint`,
      `ccert_pubkey_fingerprint` - the client certificate.
    * `encryption_protocol`, `encryption_cipher`, `encryption_keysize`.
    * `etrn_domain`, `stress` (`yes` under stress), `policy_context`,
      `compatibility_level`, `mail_version`.
  """
  @type postfix_attribute ::
          :request
          | :protocol_state
          | :protocol_name
          | :helo_name
          | :queue_id
          | :sender
          | :recipient
          | :recipient_count
          | :client_address
          | :client_name
          | :reverse_client_name
          | :instance
          | :sasl_method
          | :sasl_username
          | :sasl_sender
          | :size
          | :ccert_subject
          | :ccert_issuer
          | :ccert_fingerprint
          | :ccert_pubkey_fingerprint
          | :encryption_protocol
          | :encryption_cipher
          | :encryption_keysize
          | :etrn_domain
          | :stress
          | :client_port
          | :policy_context
          | :server_address
          | :server_port
          | :compatibility_level
          | :mail_version

  @typedoc "An attribute name: one of `postfix_attribute()`, or any other valid name."
  @type name :: postfix_attribute() | atom() | String.t()

  @typedoc "An attribute value. `nil` is sent as an empty value."
  @type value :: String.t() | integer() | :inet.ip_address() | nil

  @typedoc "Request attributes, as a map or a list such as a keyword list."
  @type attributes :: %{optional(name()) => value()} | [{name(), value()}]

  @typedoc "Decoded attributes."
  @type decoded :: %{optional(String.t()) => String.t()}

  @doc """
  The names of the attributes Postfix sends, see `t:postfix_attribute/0`.

      iex> "client_address" in Sovite.Policy.postfix_attributes()
      true
  """
  @spec postfix_attributes() :: [String.t()]
  def postfix_attributes, do: @postfix_attributes

  @doc """
  Encodes a request: the attributes, then an empty line.

  `request=smtpd_access_policy` is added unless `attrs` has a `request`.
  Carriage returns and newlines in values are replaced by spaces.
  Attributes whose name is not valid (letters, digits, `_`, `-`, and `.`,
  not starting with `-` or `.`) are left out. When a name is given more
  than once, the last value is sent, in the place of the last one.

      iex> Sovite.Policy.encode_request(sender: "a@example.com", size: 120) |> IO.iodata_to_binary()
      "request=smtpd_access_policy\\nsender=a@example.com\\nsize=120\\n\\n"
  """
  @spec encode_request(attributes()) :: iodata()
  def encode_request(attrs) do
    pairs = normalize(attrs)

    pairs =
      if List.keymember?(pairs, "request", 0),
        do: pairs,
        else: [{"request", "smtpd_access_policy"} | pairs]

    encode_block(pairs)
  end

  @doc """
  Encodes a reply with `action`: a string as is (newlines replaced by
  spaces), or a term, see `Sovite.Policy.Action.encode/1`.

      iex> Sovite.Policy.encode_reply({:reject, "no"}) |> IO.iodata_to_binary()
      "action=REJECT no\\n\\n"
  """
  @spec encode_reply(String.t() | Action.t()) :: iodata()
  def encode_reply(action) when is_binary(action), do: encode_block([{"action", action}])
  def encode_reply(action), do: encode_block([{"action", Action.encode(action)}])

  defp encode_block(pairs) do
    [Enum.map(pairs, fn {name, value} -> [name, ?=, sanitize(value), ?\n] end), ?\n]
  end

  defp normalize(attrs) do
    attrs
    |> Enum.flat_map(fn {name, value} ->
      name = to_name(name)
      if Codec.valid_name?(name), do: [{name, to_value(value)}], else: []
    end)
    # The last occurrence of a name wins, and keeps its place.
    |> Enum.reverse()
    |> Enum.uniq_by(&elem(&1, 0))
    |> Enum.reverse()
  end

  defp to_name(name) when is_atom(name), do: Atom.to_string(name)
  defp to_name(name) when is_binary(name), do: name

  defp to_value(nil), do: ""
  defp to_value(value) when is_binary(value), do: value
  defp to_value(value) when is_integer(value), do: Integer.to_string(value)
  defp to_value(value) when is_tuple(value), do: value |> :inet.ntoa() |> List.to_string()

  defp sanitize(value), do: String.replace(value, ["\r", "\n"], " ")

  @doc """
  Decodes the first block in `data`: the attributes up to the first empty
  line, and what follows it. A line may end with `\\r\\n`. When a name
  comes more than once, the last value wins.

  Returns `{:error, :incomplete}` when `data` has no empty line yet, and
  `{:error, :malformed}` for a line that is not `name=value` with a
  valid name.

      iex> Sovite.Policy.decode("action=DUNNO\\nfoo=a=b\\n\\nrest")
      {:ok, %{"action" => "DUNNO", "foo" => "a=b"}, "rest"}
  """
  @spec decode(binary()) ::
          {:ok, decoded(), rest :: binary()} | {:error, :incomplete | :malformed}
  def decode(data) when is_binary(data) do
    limits = %{max_line: :infinity, max_attributes: :infinity, max_size: :infinity}

    case Codec.read(Codec.new(), data, limits) do
      {:ok, attrs, reader} -> {:ok, attrs, Codec.buffer(reader)}
      {:more, _reader} -> {:error, :incomplete}
      {:error, :malformed} -> {:error, :malformed}
    end
  end

  @doc "Parses an action, see `Sovite.Policy.Action.parse/1`."
  @spec parse_action(String.t()) :: {:ok, Action.t()} | {:error, :invalid_action}
  defdelegate parse_action(action), to: Action, as: :parse

  @doc "Encodes an action, see `Sovite.Policy.Action.encode/1`."
  @spec encode_action(Action.t()) :: String.t()
  defdelegate encode_action(action), to: Action, as: :encode
end
