defmodule Sovite.Dev.ReleaseBuild do
  @moduledoc false
  # Runs packaging/Containerfile.release for a target with podman (or
  # docker buildx), and exports the single binary and its packages to
  # ./release. For `mix build.release.x86` and `mix build.release.aarch64`.

  @containerfile "packaging/Containerfile.release"
  @output "release"

  def run(target, args) do
    {opts, _rest} = OptionParser.parse!(args, strict: [engine: :string, no_cache: :boolean])
    engine = engine(opts[:engine])
    version = Mix.Project.config()[:version]

    Mix.shell().info("Building Sovite #{version} for linux-#{target} with #{engine}")
    File.mkdir_p!(@output)

    build_args =
      ["-f", @containerfile, "--build-arg", "TARGET=#{target}"] ++
        if(opts[:no_cache], do: ["--no-cache"], else: []) ++
        ["--output", "type=local,dest=#{@output}", "."]

    command =
      if engine == "docker", do: ["buildx", "build" | build_args], else: ["build" | build_args]

    case System.cmd(engine, command, into: IO.stream(), stderr_to_stdout: true) do
      {_, 0} -> report(version, target)
      {_, status} -> Mix.raise("the build failed (#{engine} exited with #{status})")
    end
  end

  defp engine(nil) do
    cond do
      System.find_executable("podman") -> "podman"
      System.find_executable("docker") -> "docker"
      true -> Mix.raise("podman or docker is needed to build releases")
    end
  end

  defp engine(engine) when engine in ["podman", "docker"] do
    System.find_executable(engine) || Mix.raise("#{engine} is not installed")
    engine
  end

  defp engine(engine), do: Mix.raise("--engine must be podman or docker, not #{inspect(engine)}")

  defp report(version, target) do
    deb = if target == "x86_64", do: "amd64", else: "arm64"

    files =
      for name <- [
            "sovite-#{version}-linux-#{target}",
            "sovite_#{version}_#{deb}.deb",
            "sovite-#{version}-1.#{target}.rpm",
            "sovite-#{version}-linux-#{target}.sha256"
          ],
          path = Path.join(@output, name),
          File.exists?(path),
          do: "  #{path}  (#{div(File.stat!(path).size, 1024)} KB)"

    Mix.shell().info(Enum.join(["", "Built into ./#{@output}:" | files], "\n"))
  end
end
