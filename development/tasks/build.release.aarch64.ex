defmodule Mix.Tasks.Build.Release.Aarch64 do
  @shortdoc "Builds the single binary and .deb/.rpm packages for aarch64"

  @moduledoc """
  Builds Sovite as a single executable for Linux on aarch64 (ARM64), and
  its `.deb` and `.rpm` packages, into `./release`, with the version in
  `mix.exs`:

      mix build.release.aarch64
      mix build.release.aarch64 --engine docker --no-cache

  Works on x86_64 hosts too: Burrito cross-builds it. See
  `mix build.release.x86` for the details.

  Output: `sovite-VERSION-linux-aarch64`, `sovite_VERSION_arm64.deb`,
  `sovite-VERSION-1.aarch64.rpm`, and `sovite-VERSION-linux-aarch64.sha256`.
  """

  use Mix.Task

  alias Sovite.Dev.ReleaseBuild

  @impl Mix.Task
  def run(args), do: ReleaseBuild.run("aarch64", args)
end
