defmodule Sovite.SMTP.Server do
  @moduledoc """
  An SMTP server: a `Sovite.Listener` whose connections run
  `Sovite.SMTP.Server.Session`.

  Supports `PIPELINING`, `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`,
  `STARTTLS`, `AUTH`, and `REQUIRETLS`. What happens to messages is decided by a
  `Sovite.SMTP.Server.Handler`:

      children = [
        {Sovite.SMTP.Server,
         port: 2525,
         hostname: "mx.example.com",
         handler: {MyHandler, []},
         max_connections_per_ip: 10}
      ]

  ## Options

  Listener options (see `Sovite.Listener`): `:port`, `:ip`, `:id`,
  `:name`, `:acceptors`, `:max_connections`, `:max_connections_per_ip`.

  TLS options:

    * `:tls` - `:ssl` server options (see `Sovite.TLS.server_options/1`),
      or a zero-arity function that returns them (or `nil`) for each new
      connection, such as one calling `Sovite.TLS.CertStore.server_options/1`.
      Without it, or when it returns `nil`, TLS is not offered.
    * `:implicit_tls` - start TLS on connect, before the greeting (port
      465, RFC 8314). Defaults to `false`: `STARTTLS` is offered instead.
    * `:tls_handshake_timeout` - milliseconds. Defaults to 60 seconds.

  All other options are session options, see `Sovite.SMTP.Server.Session`.
  `:hostname` and `:handler` are required.

  A connection refused by a limit gets `421 4.7.0` before it is closed,
  except with implicit TLS.
  """

  @listener_keys [:port, :ip, :id, :name, :acceptors, :max_connections, :max_connections_per_ip]
  @connection_keys [:tls, :implicit_tls, :tls_handshake_timeout]

  @doc false
  def child_spec(opts), do: opts |> listener_opts() |> Sovite.Listener.child_spec()

  @doc "Starts the server."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts), do: opts |> listener_opts() |> Sovite.Listener.start_link()

  defp listener_opts(opts) do
    {listener, rest} = Keyword.split(opts, @listener_keys)
    {connection, session} = Keyword.split(rest, @connection_keys)

    Keyword.merge(listener,
      handler: Sovite.SMTP.Server.Connection,
      handler_opts: [session: session] ++ connection
    )
  end
end
