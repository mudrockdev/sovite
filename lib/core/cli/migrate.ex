defmodule Sovite.Core.CLI.Migrate do
  @moduledoc false
  # sovitectl migrate postfix: converts a Postfix configuration with
  # Sovite.Core.Postfix.Migration and writes sovite.toml, import.sh, and
  # report.txt.

  import Sovite.Core.CLI.Helpers

  alias Sovite.Core.Config
  alias Sovite.Core.Postfix.Migration

  @commands ~w(migrate)

  @usage """
    migrate postfix [DIR] [--output OUT] [--root ROOT] [--force]
                                     Convert the Postfix configuration in DIR (default: /etc/postfix)
                                     into OUT/sovite.toml, OUT/import.sh (the lookup tables), and
                                     OUT/report.txt (default OUT: .). ROOT: read the files Postfix
                                     names, such as /etc/aliases, under ROOT instead of /.
                                     --force overwrites existing files.
  """

  # Files are written with these modes: the config and the script can
  # hold passwords.
  @files [{"sovite.toml", 0o600}, {"import.sh", 0o600}, {"report.txt", 0o644}]

  @doc "The commands this module handles."
  def commands, do: @commands

  @doc "Usage lines for the help text."
  def usage, do: @usage

  @doc "Runs a command. Returns the exit status, or `:usage`."
  def run(["migrate", "postfix" | args], _config_path) do
    case OptionParser.parse(args, strict: [output: :string, root: :string, force: :boolean]) do
      {opts, [], []} -> migrate(Keyword.get(opts, :root, "/") |> default_dir(), opts)
      {opts, [dir], []} -> migrate(dir, opts)
      _ -> :usage
    end
  end

  def run(_argv, _config_path), do: :usage

  defp default_dir(root), do: Path.join(root, "etc/postfix")

  defp migrate(dir, opts) do
    root = Path.expand(Keyword.get(opts, :root, "/"))
    dir = Path.expand(dir)
    output = Path.expand(Keyword.get(opts, :output, "."))
    postfix_dir = postfix_path(dir, root)
    read = &read(&1, root, postfix_dir)

    with {:ok, main_cf} <- read_main(dir),
         :ok <- check_output(output, Keyword.get(opts, :force, false)) do
      master_cf =
        case File.read(Path.join(dir, "master.cf")) do
          {:ok, contents} -> contents
          {:error, _} -> nil
        end

      result =
        Migration.migrate(main_cf, master_cf,
          read: read,
          defaults: %{"myhostname" => Config.system_hostname(), "config_directory" => postfix_dir},
          source: postfix_dir
        )

      write(output, result)
    end
  end

  # Where `dir` is for Postfix: its path under `root`.
  defp postfix_path(dir, "/"), do: dir

  defp postfix_path(dir, root) do
    case Path.relative_to(dir, root) do
      ^dir -> dir
      relative -> "/" <> relative
    end
  end

  defp read(path, root, postfix_dir) do
    path = if Path.type(path) == :absolute, do: path, else: Path.join(postfix_dir, path)
    File.read(Path.join(root, path))
  end

  defp read_main(dir) do
    path = Path.join(dir, "main.cf")

    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> fail("cannot read #{path}: #{:file.format_error(reason)}")
    end
  end

  defp check_output(output, force) do
    existing = for {name, _mode} <- @files, File.exists?(Path.join(output, name)), do: name

    if not force and existing != [] do
      fail(
        "#{Enum.join(existing, ", ")} already exist#{if length(existing) == 1, do: "s"} in #{output}: use --force to overwrite"
      )
    else
      case File.mkdir_p(output) do
        :ok -> :ok
        {:error, reason} -> fail("cannot create #{output}: #{:file.format_error(reason)}")
      end
    end
  end

  defp write(output, result) do
    contents = %{
      "sovite.toml" => result.config,
      "import.sh" => result.script,
      "report.txt" => result.report
    }

    written =
      Enum.reduce_while(@files, :ok, fn {name, mode}, :ok ->
        path = Path.join(output, name)

        # Set the mode before the contents go in.
        with :ok <- File.write(path, ""),
             :ok <- File.chmod(path, mode),
             :ok <- File.write(path, Map.fetch!(contents, name)) do
          {:cont, :ok}
        else
          {:error, reason} -> {:halt, {:error, path, reason}}
        end
      end)

    case written do
      :ok ->
        IO.write(result.report)
        attention = Enum.count(result.entries, &(&1.level == :attention))

        done(
          "Wrote #{Path.join(output, "sovite.toml")}, import.sh, and report.txt: #{attention} items need attention."
        )

      {:error, path, reason} ->
        fail("cannot write #{path}: #{:file.format_error(reason)}")
    end
  end
end
