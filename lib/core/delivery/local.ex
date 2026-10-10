defmodule Sovite.Core.Delivery.Local do
  @moduledoc false
  # Final delivery on this machine for Sovite.Core.Delivery: Maildir (the
  # local and mailbox transports) and pipe commands. Each recipient is
  # delivered on its own, with Return-Path: and Delivered-To: at the top.

  alias Sovite.Core.{Delivery, Routing}
  alias Sovite.Core.Delivery.Transaction
  alias Sovite.Maildir
  alias Sovite.Message.Trace
  alias Sovite.Pipe
  alias Sovite.Queue.Spool

  # sysexits.h codes, as Postfix's pipe(8) maps them.
  @sysexits %{
    64 => {"5.3.0", "command line usage error"},
    65 => {"5.6.0", "data format error"},
    66 => {"5.3.0", "cannot open input"},
    67 => {"5.1.1", "user unknown"},
    68 => {"5.1.2", "host name unknown"},
    69 => {"5.3.0", "service unavailable"},
    70 => {"5.3.0", "internal software error"},
    71 => {"4.3.0", "system error"},
    72 => {"5.3.0", "critical OS file missing"},
    73 => {"5.2.0", "cannot create output file"},
    74 => {"5.3.0", "input/output error"},
    75 => {"4.3.0", "temporary failure"},
    76 => {"5.5.0", "remote error in protocol"},
    77 => {"5.7.1", "permission denied"},
    78 => {"5.3.5", "configuration error"}
  }

  @spec deliver(Delivery.job(), Delivery.opts()) :: [Delivery.result()]
  def deliver(%{destination: destination} = job, opts),
    do: Enum.map(job.recipients, &recipient(destination, job, &1, opts))

  defp recipient(%{transport: transport}, job, rcpt, opts) when transport in [:local, :mailbox] do
    case opts.maildir[transport] do
      nil ->
        result(rcpt, "4.3.5", "#{transport} delivery is not configured: set maildir.#{transport}")

      template ->
        maildir(job, rcpt, template, opts)
    end
  end

  defp recipient(%{transport: :pipe, name: name}, job, rcpt, opts) do
    case Map.fetch(opts.pipes, name) do
      {:ok, pipe} -> pipe(job, rcpt, name, pipe, opts)
      :error -> result(rcpt, "4.3.5", "pipe #{name} is not configured")
    end
  end

  ## Maildir

  defp maildir(job, rcpt, template, opts) do
    case maildir_path(template, rcpt, opts.delimiter) do
      {:ok, dir} ->
        data = Stream.concat([trace(job.sender, rcpt)], message(job))

        case Maildir.deliver(dir, data, hostname: opts.hostname) do
          {:ok, _file} ->
            result(rcpt, "2.0.0", "delivered to maildir #{dir}")

          {:error, reason} ->
            result(
              rcpt,
              file_status(reason),
              "cannot deliver to maildir #{dir}: #{file_error(reason)}"
            )
        end

      :error ->
        result(rcpt, "5.1.3", "#{rcpt} cannot be used as a mailbox name")
    end
  end

  @doc false
  # The folder for `rcpt`: {user} is the lower-cased local part without
  # its extension, {domain} the domain, {address} both.
  def maildir_path(template, rcpt, delimiter) do
    {user, _extension, domain} = parts(rcpt, delimiter)
    values = %{"user" => user, "domain" => domain, "address" => "#{user}@#{domain}"}

    if Enum.all?(Map.values(values), &path_safe?/1),
      do:
        {:ok,
         Regex.replace(~r/\{(user|domain|address)\}/, template, fn _, key -> values[key] end)},
      else: :error
  end

  defp path_safe?(value),
    do: value not in ["", ".", ".."] and not String.contains?(value, ["/", <<0>>])

  defp file_status(:enospc), do: "4.3.1"
  defp file_status(:edquot), do: "4.2.2"
  defp file_status(_reason), do: "4.3.0"

  defp file_error({:read, exception}), do: Exception.message(exception)
  defp file_error(reason), do: reason |> :file.format_error() |> to_string()

  ## Pipe

  defp pipe(job, rcpt, name, pipe, opts) do
    {user, extension, domain} = parts(rcpt, opts.delimiter)

    values = %{
      "sender" => job.sender,
      "recipient" => rcpt,
      "user" => user,
      "extension" => extension,
      "domain" => domain,
      "queue_id" => job.queue_id
    }

    command = (pipe.sandbox || []) ++ Enum.map(pipe.command, &substitute(&1, values))
    env = Map.merge(pipe.env, Map.new(values, fn {key, value} -> {String.upcase(key), value} end))
    trace = if pipe.trace_headers, do: [trace(job.sender, rcpt)], else: []

    input =
      Path.join(opts.tmp_dir, "sovite-pipe-#{job.queue_id}-#{System.unique_integer([:positive])}")

    case write_input(input, Stream.concat(trace, message(job))) do
      :ok ->
        try do
          Pipe.run(command, input, env: env, directory: pipe.directory, timeout: pipe.timeout)
          |> pipe_result(rcpt, name)
        after
          File.rm(input)
        end

      {:error, reason} ->
        result(rcpt, "4.3.0", "cannot write message for pipe #{name}: #{file_error(reason)}")
    end
  end

  defp substitute(arg, values),
    do:
      Regex.replace(~r/\{(sender|recipient|user|extension|domain|queue_id)\}/, arg, fn _, key ->
        values[key]
      end)

  defp write_input(path, data) do
    with {:ok, fd} <- :file.open(path, [:write, :exclusive, :raw, :binary]) do
      result =
        try do
          with :ok <- File.chmod(path, 0o600) do
            Enum.reduce_while(data, :ok, fn chunk, :ok ->
              case :file.write(fd, chunk) do
                :ok -> {:cont, :ok}
                error -> {:halt, error}
              end
            end)
          end
        rescue
          error -> {:error, {:read, error}}
        after
          :file.close(fd)
        end

      with {:error, _} <- result, do: File.rm(path)
      result
    end
  end

  defp pipe_result({:ok, 0, _output}, rcpt, name),
    do: result(rcpt, "2.0.0", "delivered via pipe #{name}")

  defp pipe_result({:ok, status, output}, rcpt, name) when status > 128,
    do:
      result(
        rcpt,
        "4.3.0",
        "command #{name} was killed by signal #{status - 128}" <> output_text(output)
      )

  defp pipe_result({:ok, status, output}, rcpt, name) do
    {code, meaning} = Map.get(@sysexits, status, {"5.3.0", "unknown error"})

    result(
      rcpt,
      code,
      "command #{name} failed with status #{status} (#{meaning})" <> output_text(output)
    )
  end

  defp pipe_result({:error, :timeout, output}, rcpt, name),
    do:
      result(rcpt, "4.3.0", "command #{name} ran too long and was killed" <> output_text(output))

  defp pipe_result({:error, reason}, rcpt, name),
    do: result(rcpt, "4.3.5", "cannot run command #{name}: #{file_error(reason)}")

  # The first line of the output, printable ASCII only, for the bounce.
  defp output_text(output) do
    line =
      output
      |> String.split(["\r\n", "\n"], parts: 2)
      |> hd()
      |> String.replace(~r/[^\x20-\x7e]/, "")
      |> String.trim()
      |> String.slice(0, 200)

    if line == "", do: "", else: ": " <> line
  end

  ## Shared

  defp parts(rcpt, delimiter) do
    {local, domain} = Routing.split(String.downcase(rcpt))
    {user, extension} = Routing.extension(delimiter, local)
    extension = if extension, do: String.slice(extension, 1..-1//1), else: ""
    {user, extension, domain}
  end

  defp trace(sender, rcpt), do: Trace.return_path(sender) <> Trace.delivered_to(rcpt)

  defp message(job),
    do: Spool.stream_message(job.path, job.message_offset, job.message_size, job.prefix)

  defp result(rcpt, <<class, _::binary>> = status, text) do
    outcome =
      case class do
        ?2 -> :delivered
        ?4 -> :deferred
        ?5 -> :failed
      end

    {rcpt, outcome, Transaction.details(status, text, nil, false)}
  end
end
