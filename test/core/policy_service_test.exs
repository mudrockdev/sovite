defmodule Sovite.Core.PolicyServiceTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{PolicyService, Restrictions}
  alias Sovite.SMTP.Reply
  alias Sovite.Test.TelemetryForwarder

  defmodule Scripted do
    @moduledoc false
    # Answers with the action in the sender's local part: "+" for a
    # space, "=" for "@".
    @behaviour Sovite.Policy.Handler

    @impl true
    def init(_connection, test), do: {:ok, test}

    @impl true
    def handle_request(attributes, test) do
      send(test, {:request, attributes})
      [action | _] = String.split(attributes["sender"] || "dunno@x", "@")
      {action |> String.replace("+", " ") |> String.replace("=", "@"), test}
    end
  end

  setup do
    server =
      start_supervised!(
        {Sovite.Policy.Server, ip: {127, 0, 0, 1}, port: 0, handler: {Scripted, self()}}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    %{check: "check_policy_service inet:127.0.0.1:#{port}"}
  end

  defp context(sender, extra \\ %{}) do
    Map.merge(
      %{
        client_ip: {192, 0, 2, 1},
        helo: "client.example",
        sender: sender,
        recipient: "bob@example.com",
        esmtp: true,
        policy: %{timeout: 5_000, default_action: :dunno}
      },
      extra
    )
  end

  test "maps every action", %{check: check} do
    TelemetryForwarder.attach([[:sovite, :restrictions, :warn]])
    run = &Restrictions.check([check, "reject"], :rcpt, context(&1))

    assert run.("ok@x") == {:ok, []}
    assert {{:reject, %Reply{code: 554}}, []} = run.("dunno@x")
    assert {{:reject, %Reply{code: 554}}, []} = run.("defer_if_reject+later@x")

    assert {{:reject, %Reply{code: 450, enhanced: "4.7.1", lines: ["Try again later"]}}, []} =
             run.("defer@x")

    assert {{:reject, %Reply{code: 421, enhanced: "4.7.1", lines: ["busy"]}}, []} =
             run.("421+busy@x")

    assert {{:reject, %Reply{code: 553, enhanced: "5.7.9", lines: ["nope"]}}, []} =
             run.("553+5.7.9+nope@x")

    assert {{:discard, "discarded"}, []} = run.("discard@x")
    assert {{:reject, _}, []} = run.("warn+look@x")
    assert_received {:telemetry, _, _, %{stage: :rcpt, text: "look"}}
    assert {{:reject, _}, []} = run.("info@x")

    assert Restrictions.check([check], :rcpt, context("hold@x")) == {{:hold, "held"}, []}

    assert Restrictions.check([check, check], :rcpt, context("bcc+archive=example.com@x")) ==
             {:ok, [{:bcc, "archive@example.com"}, {:bcc, "archive@example.com"}]}
  end

  test "sends the stage and the session's attributes", %{check: check} do
    request = fn -> %{"client_address" => {192, 0, 2, 1}, "queue_id" => "Q1"} end

    for {stage, state} <- [
          connect: "CONNECT",
          helo: "EHLO",
          mail: "MAIL",
          rcpt: "RCPT",
          data: "DATA",
          end_of_data: "END-OF-MESSAGE"
        ] do
      Restrictions.check([check], stage, context(nil, %{policy_request: request}))
      assert_received {:request, %{"protocol_state" => ^state, "queue_id" => "Q1"}}
    end

    Restrictions.check([check], :helo, context(nil, %{esmtp: false}))
    assert_received {:request, %{"protocol_state" => "HELO", "client_address" => "192.0.2.1"}}
  end

  test "an invalid reply or a failure gets the default action", %{check: check} do
    assert {{:reject, %Reply{code: 451}}, []} =
             Restrictions.check(
               ["check_policy_service inet:127.0.0.1:1"],
               :rcpt,
               context("ok@x", %{
                 policy: %{timeout: 1_000, default_action: {:reply, 451, "4.3.5", "down"}}
               })
             )

    assert Restrictions.check([check], :rcpt, context("nonsense+action@x")) == {:ok, []}
  end

  test "builds the session attributes" do
    connection = %{
      remote_ip: {192, 0, 2, 1},
      remote_port: 4711,
      local_ip: {198, 51, 100, 1},
      local_port: 25
    }

    attributes =
      PolicyService.request(%{
        connection: connection,
        tls: %{protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", bits: 128, sni: nil},
        client_dns: {:unconfirmed, ["ptr.example"]},
        helo: "client.example",
        esmtp: true,
        lmtp: false,
        queue_id: nil,
        instance: "S1.1",
        recipient_count: 0,
        identity: "alice",
        mechanism: "PLAIN",
        size: 100
      })

    assert %{
             "protocol_name" => "ESMTP",
             "client_name" => "unknown",
             "reverse_client_name" => "ptr.example",
             "client_port" => 4711,
             "server_address" => {198, 51, 100, 1},
             "sasl_method" => "PLAIN",
             "sasl_username" => "alice",
             "encryption_protocol" => "TLSv1.3",
             "encryption_keysize" => 128
           } = attributes

    refute Map.has_key?(attributes, "queue_id")

    assert %{"protocol_name" => "LMTP", "client_name" => "mx.example"} =
             PolicyService.request(%{
               connection: %{remote_ip: {192, 0, 2, 1}},
               tls: nil,
               client_dns: {:ok, "mx.example"},
               helo: nil,
               esmtp: true,
               lmtp: true,
               queue_id: nil,
               instance: "S1.0",
               recipient_count: 0,
               identity: nil,
               mechanism: nil,
               size: nil
             })

    assert %{"protocol_name" => "SMTP", "client_name" => "unknown"} =
             PolicyService.request(%{
               connection: %{remote_ip: {192, 0, 2, 1}},
               tls: nil,
               client_dns: nil,
               helo: nil,
               esmtp: false,
               lmtp: false,
               queue_id: nil,
               instance: "S1.0",
               recipient_count: 0,
               identity: nil,
               mechanism: nil,
               size: nil
             })
  end

  test "restriction names" do
    assert Restrictions.parse("check_policy_service unix:/run/postgrey.sock") ==
             {:ok, "check_policy_service unix:/run/postgrey.sock"}

    assert {:error, _} = Restrictions.parse("check_policy_service")
    assert {:error, _} = Restrictions.parse("check_policy_service tcp:1")
    assert {:error, _} = Restrictions.parse("check_policy_servicex inet:a:1")
    assert Restrictions.allowed?("check_policy_service inet:127.0.0.1:1", :connect)
  end
end
