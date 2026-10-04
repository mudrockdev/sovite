defmodule Sovite.SMTP.Server.Handler do
  @moduledoc """
  Behaviour for the application side of an SMTP server: policy decisions
  and what happens to received messages.

  `Sovite.SMTP.Server.Session` handles the protocol (syntax, command
  order, limits, dot-stuffing) and calls the handler only with
  well-formed input. Addresses have been checked with
  `Sovite.Validators.split_mailbox/1`, except that a recipient may be
  `"Postmaster"` without a domain (RFC 5321 §4.5.1, any case).

  Most callbacks return one of:

    * `{:ok, state}` - accept, with the standard reply.
    * `{:reply, reply, state}` - send `reply` instead. A 2xx/3xx reply
      accepts, 4xx/5xx rejects.
    * `{:close, reply, state}` - send `reply` and close the connection.
  """

  alias Sovite.SMTP.Reply
  alias Sovite.SMTP.Server.Session

  @type state :: term()
  @type result :: {:ok, state()} | {:reply, Reply.t(), state()} | {:close, Reply.t(), state()}

  @doc """
  Called when the connection opens, before the greeting. Return
  `{:close, reply, state}` to refuse the client (typically with `554`).
  """
  @callback init(Session.connection(), opts :: term()) ::
              {:ok, state()} | {:close, Reply.t(), state()}

  @doc "`EHLO` or `HELO`. The name is a valid domain or address literal."
  @callback handle_helo(:ehlo | :helo, name :: String.t(), state()) :: result()

  @doc "`MAIL FROM`. `sender` is `\"\"` for the null reverse-path."
  @callback handle_mail(sender :: String.t(), Session.mail_params(), state()) :: result()

  @doc "`RCPT TO`, after the session checked the recipient limit."
  @callback handle_rcpt(recipient :: String.t(), state()) :: result()

  @doc "`DATA`, when the transaction has at least one recipient. Accept to get `354`."
  @callback handle_data(Session.transaction(), state()) :: result()

  @doc """
  Decoded message content, in order. Returning a reply aborts the message:
  the rest of the data is read and discarded, the reply is sent after the
  final dot, and `handle_data_end/2` is not called.
  """
  @callback handle_data_chunk(iodata(), state()) :: {:ok, state()} | {:reply, Reply.t(), state()}

  @doc "The final dot. Accept only once the message is safely stored."
  @callback handle_data_end(Session.transaction(), state()) :: result()

  @doc """
  The message was abandoned by the session: `:too_large`, `:bare_lf`,
  `:bare_cr`, `:timeout`, or `:closed` (the connection ended).
  """
  @callback handle_data_abort(reason :: atom(), state()) :: state()

  @doc "`RSET`, or a new `EHLO`/`HELO` that resets the transaction."
  @callback handle_rset(state()) :: state()

  @doc "`VRFY`, only when enabled. Without this callback the reply is `252`."
  @callback handle_vrfy(argument :: String.t(), state()) :: result()

  @doc """
  The connection is now encrypted (after `STARTTLS`). The session has
  been reset: forget the `EHLO` name and anything else learned before.
  """
  @callback handle_tls(Sovite.TLS.info(), state()) :: state()

  @doc """
  SASL mechanisms to offer in the `EHLO` reply, upper-case, for example
  `["PLAIN", "SCRAM-SHA-256"]`. Called only when the session offers
  `AUTH`, and on every `EHLO` and `AUTH`, so the list may depend on the
  state. Without this callback, no mechanism is offered.
  """
  @callback auth_mechanisms(state()) :: [String.t()]

  @typedoc """
  A step of the SASL exchange:

    * `{:ok, identity, state}` - authenticated as `identity`: `235`.
    * `{:challenge, data, state}` - send `data` (raw bytes; the session
      encodes it) with `334` and wait for the client's response.
    * `{:error, reply, state}` - the exchange failed: send `reply`.
      Use `535 5.7.8` for bad credentials (counted towards
      `:max_auth_failures`), `454 4.7.0` for a temporary failure.
    * `{:close, reply, state}` - send `reply` and close the connection.
  """
  @type auth_result ::
          {:ok, identity :: String.t(), state()}
          | {:challenge, binary(), state()}
          | {:error, Reply.t(), state()}
          | {:close, Reply.t(), state()}

  @doc """
  `AUTH` with an offered mechanism. `initial_response` is the decoded
  initial response, `""` when the client sent `=`, and `nil` when it sent
  none.
  """
  @callback handle_auth(mechanism :: String.t(), initial_response :: binary() | nil, state()) ::
              auth_result()

  @doc "The client's (decoded) response to a challenge."
  @callback handle_auth_response(response :: binary(), state()) :: auth_result()

  @doc """
  The exchange ended without a result: the client cancelled with `*`,
  sent an invalid response, or the session ended.
  """
  @callback handle_auth_abort(state()) :: state()

  @doc "The session ended."
  @callback terminate(reason :: term(), state()) :: any()

  @optional_callbacks handle_rset: 1,
                      handle_vrfy: 2,
                      handle_tls: 2,
                      auth_mechanisms: 1,
                      handle_auth: 3,
                      handle_auth_response: 2,
                      handle_auth_abort: 1,
                      terminate: 2
end
