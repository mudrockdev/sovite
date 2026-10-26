defmodule Sovite.Core.CLI.Cluster do
  @moduledoc false
  # The sovitectl commands for clusters (Sovite.Core.Cluster) and IP
  # pools (Sovite.Core.MTA.IPPools). They act on the running server, through
  # the admin API (Sovite.Core.CLI.API).

  import Sovite.Core.CLI.Helpers

  alias Sovite.Core.CLI.API
  alias Sovite.Core.Config

  @commands ~w(cluster ip-pool)

  @usage """
    cluster status                   Show the cluster's nodes, as the running server sees them
    cluster join NODE                Join the cluster NODE (name@host:port) is in
    cluster leave                    Hand the queue to the other nodes, and leave the cluster
    cluster config push FILE         Send FILE to every node as the shared configuration
    ip-pool status                   Show the IP pools: messages sent today from each address,
                                     and today's limits
  """

  def commands, do: @commands
  def usage, do: @usage

  def run(["cluster", "status"], path),
    do: with_config(path, &cluster_status(API.request(&1, :get, "/api/cluster")))

  def run(["cluster", "join", node], path) do
    with_config(path, fn config ->
      config
      |> API.request(:post, "/api/cluster/join", %{peer: node})
      |> api_result(fn _body -> "joining #{node}" end)
    end)
  end

  def run(["cluster", "leave"], path) do
    with_config(path, fn config ->
      config
      |> API.request(:post, "/api/cluster/leave")
      |> api_result(fn body ->
        "left the cluster: #{body["handed_over"]} messages handed over, " <>
          "#{body["failed"]} could not be (they are still queued here). Stop this node now."
      end)
    end)
  end

  def run(["cluster", "config", "push", file], path) do
    case File.read(file) do
      {:ok, content} ->
        with_config(
          path,
          &push_result(API.request(&1, :post, "/api/cluster/config", %{content: content}), file)
        )

      {:error, reason} ->
        fail("cannot read #{file}: #{:file.format_error(reason)}")
    end
  end

  def run(["ip-pool", "status"], path),
    do: with_config(path, &pool_status(API.request(&1, :get, "/api/ip_pools")))

  def run(_argv, _path), do: :usage

  defp cluster_status({:ok, 200, %{"enabled" => false}}),
    do: done("the cluster is not enabled ([cluster] enabled = false)")

  defp cluster_status({:ok, 200, status}) do
    shared =
      case status["shared_config"] do
        %{"version" => version, "origin" => origin} -> "version #{version}, from #{origin}"
        _ -> "none"
      end

    IO.puts("Node:           #{status["node"]}")
    IO.puts("Shared config:  #{shared}\n")
    IO.puts(String.pad_trailing("-Node-", 32) <> String.pad_trailing("-State-", 8) <> "-Details-")

    for member <- status["members"] do
      IO.puts(
        String.pad_trailing(member["node"], 32) <>
          String.pad_trailing(member["status"], 8) <> details(member)
      )
    end

    print_copies(status["queue"] || %{})
  end

  defp cluster_status(other), do: api_result(other, nil)

  defp print_copies(queue) do
    copies = queue["copies"] || %{}
    taken = queue["taken_over"] || %{}

    if copies != %{} or taken != %{}, do: IO.puts("")
    for {node, count} <- copies, do: IO.puts("Copies of #{node}'s messages: #{count}")
    for {node, count} <- taken, count > 0, do: IO.puts("Taken over from #{node}: #{count}")
    0
  end

  defp details(%{"status" => "self"}), do: ""

  defp details(member) do
    [
      member["hostname"],
      member["version"] && "sovite #{member["version"]}",
      member["parts"] && Enum.join(member["parts"], "+"),
      member["queue"] && queue(member["queue"]),
      member["since"] && "since #{member["since"]}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(", ")
  end

  defp queue(counts),
    do: counts |> Enum.sort() |> Enum.map_join(" ", fn {queue, count} -> "#{queue}=#{count}" end)

  defp push_result({:ok, 200, %{"version" => version}}, file),
    do: done("sent #{file} to the cluster as version #{version}")

  defp push_result({:ok, 422, %{"errors" => errors}}, file) do
    for error <- errors, do: IO.puts(:stderr, "#{file}: #{error}")
    fail("the shared configuration was not sent")
  end

  defp push_result(other, _file), do: api_result(other, nil)

  defp pool_status({:ok, 200, %{"pools" => []}}), do: done("no IP pools ([[ip_pool]])")

  defp pool_status({:ok, 200, %{"pools" => pools}}) do
    for pool <- pools do
      overflow = if pool["overflow"], do: " (overflow: #{pool["overflow"]})", else: ""
      IO.puts("#{pool["name"]}#{overflow}")

      Enum.each(pool["addresses"], &print_address/1)
    end

    0
  end

  defp pool_status(other), do: api_result(other, nil)

  defp print_address(address) do
    limit = if address["limit_today"], do: "/#{address["limit_today"]}", else: ""
    node = if address["node"], do: "  on #{address["node"]}", else: ""

    IO.puts(
      "  " <>
        String.pad_trailing(address["address"], 40) <>
        String.pad_leading("#{address["sent_today"]}#{limit}", 16) <> node
    )
  end

  defp api_result({:ok, 200, body}, message) when is_function(message), do: done(message.(body))
  defp api_result({:ok, _status, %{"error" => error}}, _message), do: fail(error)
  defp api_result({:ok, status, _body}, _message), do: fail("the admin API returned #{status}")
  defp api_result({:error, text}, _message), do: fail(text)

  defp with_config(path, fun) do
    case Config.load(path) do
      {:ok, config} ->
        fun.(config)

      {:error, errors} ->
        print_config_errors(path, errors)
        1
    end
  end
end
