defmodule Sovite.SMTP.Server do
  @moduledoc """
  An SMTP server: a `Sovite.Listener` whose connections run
  `Sovite.SMTP.Server.Session`.

  Supports `PIPELINING`, `SIZE`, `8BITMIME`, and `ENHANCEDSTATUSCODES`.
  What happens to messages is decided by a `Sovite.SMTP.Server.Handler`:

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

  All other options are session options, see `Sovite.SMTP.Server.Session`.
  `:hostname` and `:handler` are required.

  A connection refused by a limit gets `421 4.7.0` before it is closed.
  """

  @listener_keys [:port, :ip, :id, :name, :acceptors, :max_connections, :max_connections_per_ip]

  @doc false
  def child_spec(opts), do: opts |> listener_opts() |> Sovite.Listener.child_spec()

  @doc "Starts the server."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts), do: opts |> listener_opts() |> Sovite.Listener.start_link()

  defp listener_opts(opts) do
    {listener, session} = Keyword.split(opts, @listener_keys)

    Keyword.merge(listener,
      handler: Sovite.SMTP.Server.Connection,
      handler_opts: [session: session]
    )
  end
end
