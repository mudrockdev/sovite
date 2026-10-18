defmodule Sovite.Core.Cluster.SharedConfig do
  @moduledoc """
  The configuration the nodes of a cluster share: a TOML file, the same
  on every node, under each node's own config file.

      [cluster]
      shared_config = "/var/lib/sovite/cluster.toml"

  `sovitectl cluster config push FILE` (or `POST /api/cluster/config`)
  sends a new version to every node. Each node checks it together with
  its own file (`Sovite.Core.Config.load_with_shared/2`), stores it, and
  reloads; a node whose own settings do not work with it keeps the
  version it has, and logs why. The settings of a node's own file win
  over the shared ones (see `Sovite.Core.Config.load/1`), so each node
  keeps its own `[server] hostname`, listeners, `[cluster]` table, and
  so on, and the shared file holds the rest: domains, routing,
  restrictions, limits, tenants, and IP pools.

  Each version has a number, one more than the newest the pushing node
  knew, and the name of that node. A newer version replaces an older
  one; of two with the same number, the one from the node whose name
  sorts last wins. A node that comes back, or joins, gets the newest
  version from the nodes it meets.

  The file starts with a comment that holds the version:

      # sovite shared config: version 3, from mx1@10.0.0.1, 2026-10-18T20:00:00Z
  """

  alias Sovite.Core.Config

  @header ~r/\A# sovite shared config: version (\d+), from (\S+), \S+\n/

  @type t :: %{version: non_neg_integer(), origin: String.t(), content: String.t()}

  @doc "The version stored at `path`, or `nil` when there is none."
  @spec read(Path.t() | nil) :: t() | nil
  def read(nil), do: nil

  def read(path) do
    case File.read(path) do
      {:ok, text} -> parse(text)
      {:error, _reason} -> nil
    end
  end

  defp parse(text) do
    case Regex.run(@header, text) do
      [header, version, origin] ->
        %{
          version: String.to_integer(version),
          origin: origin,
          content: binary_part(text, byte_size(header), byte_size(text) - byte_size(header))
        }

      # A file written by hand: version 0.
      nil ->
        %{version: 0, origin: "", content: text}
    end
  end

  @doc "Stores `shared` at `path`, replacing the file at once."
  @spec write(Path.t(), t()) :: :ok | {:error, File.posix()}
  def write(path, shared) do
    header =
      "# sovite shared config: version #{shared.version}, from #{shared.origin}, " <>
        "#{DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()}\n"

    tmp = path <> ".tmp"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(tmp, [header, shared.content]),
         :ok <- File.chmod(tmp, 0o640) do
      File.rename(tmp, path)
    end
  end

  @doc "Whether `a` is newer than `b` (or `b` is `nil`)."
  @spec newer?(t() | map(), t() | map() | nil) :: boolean()
  def newer?(_a, nil), do: true
  def newer?(a, b), do: {a.version, a.origin} > {b.version, b.origin}

  @doc """
  Whether the server running with config file `config_path` can take
  `content` as its shared configuration. Returns `:ok` or the reasons.
  """
  @spec check(Path.t() | nil, String.t()) :: :ok | {:error, [String.t()]}
  def check(nil, _content), do: {:error, ["the server was started without a config file"]}

  def check(config_path, content) do
    case Config.load_with_shared(config_path, content) do
      {:ok, _config} -> :ok
      {:error, errors} -> {:error, Enum.map(errors, &Exception.message/1)}
    end
  end
end
