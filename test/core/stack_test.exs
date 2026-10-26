defmodule Sovite.Core.StackTest do
  # Where the parts run, and the mailbox part's interface on one node
  # (see Sovite.Core.ClusterTest for the cluster).
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, Stack}

  @moduletag :tmp_dir

  defp stack(toml) do
    {:ok, config} = Config.parse(toml)
    config
  end

  test "a part runs here, or nowhere outside a cluster" do
    config = stack("[stack]\nfilter = false\n")
    stack = Stack.new(config)

    assert Stack.where(stack, :mta, "a@example.com") == :local
    assert Stack.where(stack, :filter, "a@example.com") == :none
    assert Config.part?(config, :mailbox)
    # Not in a cluster: no other node runs anything.
    assert Stack.nodes(:filter) == []
  end

  test "the mailbox part stores mail for the MTA, or the mail waits", %{tmp_dir: dir} do
    config =
      stack(
        ~s([maildir]\nmailbox = "#{dir}/{domain}/{user}"\n[routing]\nextension_delimiter = "+"\n)
      )

    opts = Stack.Mailbox.opts(config)

    assert [{"Bob+x@example.com", "2.0.0", "delivered to maildir " <> folder}] =
             Stack.Mailbox.deliver(opts, "a@example.net", ["Bob+x@example.com"], [
               "Subject: hi\r\n\r\nbody\r\n"
             ])

    assert folder == "#{dir}/example.com/bob"
    [file] = Path.wildcard("#{folder}/new/*")

    assert File.read!(file) ==
             "Return-Path: <a@example.net>\r\nDelivered-To: Bob+x@example.com\r\nSubject: hi\r\n\r\nbody\r\n"

    # Without the mailbox part on this node, and no cluster.
    opts = %{opts | stack: %{opts.stack | local: %{opts.stack.local | mailbox: false}}}

    assert [{"c@example.com", "4.3.0", "no node runs the mailbox part ([stack] mailbox)"}] =
             Stack.Mailbox.deliver(opts, "", ["c@example.com"], ["x"])

    # Not configured.
    opts = Stack.Mailbox.opts(stack(""))

    assert [{_, "4.3.5", "mailbox delivery is not configured: set maildir.mailbox"}] =
             Stack.Mailbox.deliver(opts, "", ["c@example.com"], ["x"])
  end
end
