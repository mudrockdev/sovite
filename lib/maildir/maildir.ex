defmodule Sovite.Maildir do
  @moduledoc """
  Delivers messages into Maildir folders (https://cr.yp.to/proto/maildir.html).

      {:ok, path} = Sovite.Maildir.deliver("/var/vmail/example.com/alice", chunks)

  The message is written to a unique file in `tmp/`, flushed to disk,
  and then renamed into `new/`, so a reader never sees a partial message
  and a crash leaves at most a stray file in `tmp/`. The folder and its
  `cur/`, `new/`, and `tmp/` subdirectories are created as needed, with
  mode `0700`; message files get mode `0600`.

  File names are `<seconds>.M<microseconds>P<pid>Q<counter>.<host>,S=<size>`,
  with the size extension Dovecot and Courier read.
  """

  @typedoc "Why a delivery failed: a file error, or an exception raised while reading `data`."
  @type error :: File.posix() | {:read, Exception.t()}

  @doc """
  Writes `data` (an enumerable of iodata) as a new message in the
  Maildir at `dir`.

  ## Options

    * `:hostname` - the host part of the file name. Defaults to this
      machine's name.
  """
  @spec deliver(Path.t(), Enumerable.t(), keyword()) :: {:ok, Path.t()} | {:error, error()}
  def deliver(dir, data, opts \\ []) do
    name = unique_name(Keyword.get_lazy(opts, :hostname, &hostname/0))
    tmp = Path.join([dir, "tmp", name])

    with :ok <- create(dir),
         {:ok, size} <- write(tmp, data) do
      new = Path.join([dir, "new", "#{name},S=#{size}"])

      case :file.rename(tmp, new) do
        :ok ->
          {:ok, new}

        {:error, reason} ->
          _ = File.rm(tmp)
          {:error, reason}
      end
    end
  end

  @doc "Creates the Maildir at `dir`, if it does not exist yet."
  @spec create(Path.t()) :: :ok | {:error, File.posix()}
  def create(dir) do
    Enum.reduce_while([dir | Enum.map(~w(cur new tmp), &Path.join(dir, &1))], :ok, fn path, :ok ->
      case make_dir(path) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp make_dir(path) do
    case File.mkdir(path) do
      :ok -> File.chmod(path, 0o700)
      {:error, :eexist} -> :ok
      {:error, :enoent} -> with :ok <- File.mkdir_p(Path.dirname(path)), do: make_dir(path)
      error -> error
    end
  end

  defp write(path, data) do
    with {:ok, fd} <- :file.open(path, [:write, :exclusive, :raw, :binary]) do
      result =
        try do
          with :ok <- File.chmod(path, 0o600),
               {:ok, size} <- write_chunks(fd, data),
               :ok <- :file.sync(fd),
               do: {:ok, size}
        rescue
          error -> {:error, {:read, error}}
        after
          :file.close(fd)
        end

      with {:error, _} <- result, do: File.rm(path)
      result
    end
  end

  defp write_chunks(fd, data) do
    Enum.reduce_while(data, {:ok, 0}, fn chunk, {:ok, size} ->
      case :file.write(fd, chunk) do
        :ok -> {:cont, {:ok, size + IO.iodata_length(chunk)}}
        error -> {:halt, error}
      end
    end)
  end

  defp unique_name(hostname) do
    now = System.os_time(:microsecond)
    seconds = div(now, 1_000_000)
    micro = rem(now, 1_000_000)
    counter = :erlang.unique_integer([:positive, :monotonic])
    host = hostname |> String.replace("/", "\\057") |> String.replace(":", "\\072")
    "#{seconds}.M#{micro}P#{System.pid()}Q#{counter}.#{host}"
  end

  defp hostname, do: :net_adm.localhost() |> List.to_string()
end
