defmodule Mix.Tasks.Build.Release.X86 do
  @shortdoc "Builds the single binary and .deb/.rpm packages for x86_64"

  @moduledoc """
  Builds Sovite as a single executable for Linux on x86_64, and its
  `.deb` and `.rpm` packages, into `./release`, with the version in
  `mix.exs`:

      mix build.release.x86
      mix build.release.x86 --engine docker --no-cache

  The build runs in a container (`packaging/Containerfile.release`), with
  podman, or docker with buildx (`--engine` picks one), so it needs
  neither Zig nor nfpm on this machine, and works on x86_64 and aarch64
  hosts alike. See `mix build.release.aarch64` and
  `Sovite.Core.Standalone`.

  Output:

    * `sovite-VERSION-linux-x86_64`: the executable. Run it as it is; it
      unpacks itself on its first run.
    * `sovite_VERSION_amd64.deb` and `sovite-VERSION-1.x86_64.rpm`.
    * `sovite-VERSION-linux-x86_64.sha256`: their SHA-256 sums.
  """

  use Mix.Task

  alias Sovite.Dev.ReleaseBuild

  @impl Mix.Task
  def run(args), do: ReleaseBuild.run("x86_64", args)
end
