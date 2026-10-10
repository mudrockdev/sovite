defmodule Sovite.Policy.Handler do
  @moduledoc """
  Behaviour for a policy server written in Elixir, run by
  `Sovite.Policy.Server`.

      defmodule Greylist do
        @behaviour Sovite.Policy.Handler

        @impl true
        def init(_connection, opts), do: {:ok, opts}

        @impl true
        def handle_request(%{"protocol_state" => "RCPT"} = attrs, state) do
          if known?(attrs), do: {:dunno, state}, else: {{:defer_if_permit, "Greylisted"}, state}
        end

        def handle_request(_attrs, state), do: {:dunno, state}
      end

  Each connection runs in its own process, with its own state: `init/2`
  is called when it opens, then `handle_request/2` for each request.
  """

  @typedoc "About the connection, as in `t:Sovite.Listener.connection_info/0`, without the socket."
  @type connection :: %{
          listener: String.t(),
          remote_ip: :inet.ip_address(),
          remote_port: :inet.port_number(),
          local_ip: :inet.ip_address(),
          local_port: :inet.port_number()
        }

  @type state :: term()

  @doc "Called when a connection opens. `opts` is the second element of the `:handler` option."
  @callback init(connection(), opts :: term()) :: {:ok, state()}

  @doc """
  Called for each request, with its attributes. Postfix sends those of
  `t:Sovite.Policy.postfix_attribute/0`; a name sent more than once has
  its last value.

  Return the action: a string, sent as is, or a term encoded with
  `Sovite.Policy.Action.encode/1`. `{:ok, state}` is the action `OK`:
  use `{:dunno, state}` for no decision. Return `{:close, state}` to
  close the connection without a reply, which Postfix treats as a
  temporary failure of the policy server.
  """
  @callback handle_request(Sovite.Policy.decoded(), state()) ::
              {String.t() | Sovite.Policy.Action.t(), state()} | {:close, state()}
end
