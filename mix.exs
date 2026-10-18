defmodule Sovite.MixProject do
  use Mix.Project

  def project do
    [
      app: :sovite,
      version: "0.6.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: [:partisan_otp | Mix.compilers()],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases(),
      dialyzer: dialyzer(),
      test_coverage: [summary: [threshold: 85], ignore_modules: [~r/^Sovite\.Test\./]],
      description: "A modern, secure Mail Transfer Agent written in Elixir/OTP.",
      package: package(),
      source_url: "https://github.com/mudrockdev/sovite",
      docs: docs()
    ]
  end

  def application do
    [
      mod: {Sovite, []},
      extra_applications: [:logger, :crypto, :public_key, :ssl, :inets, :eldap]
    ]
  end

  def cli do
    [preferred_envs: [lint: :test]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  # `mix dev` and `mix dev.mta`, kept out of the package.
  defp elixirc_paths(:dev), do: ["lib", "development/tasks"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      licenses: ["AGPL-3.0"],
      links: %{"GitHub" => "https://github.com/mudrockdev/sovite"},
      files: ~w(lib mix.exs README.md LICENSE*)
    ]
  end

  defp deps do
    [
      # Partisan asks for ~> 1.1.0; 1.4 has the same API.
      {:telemetry, "~> 1.4", override: true},
      {:plug_cowboy, "~> 2.7"},
      # Started only with [cluster] enabled (Sovite.Cluster.start/1): on
      # its own it would accept unauthenticated peers.
      {:partisan, "~> 6.3", runtime: false},
      {:toml, "~> 0.7.0"},
      {:ecto_sql, "~> 3.14"},
      {:ecto_sqlite3, "~> 0.25.0"},
      {:postgrex, "~> 0.22.4", optional: true},
      {:myxql, "~> 0.9.0", optional: true},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.4", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      # Fetches deps and enables the git pre-commit hook (lint + Dialyzer).
      setup: ["deps.get"],
      lint: [
        "format",
        "compile --warnings-as-errors --force",
        "credo --strict",
        "xref graph --format cycles --fail-above 0",
        "dialyzer"
      ]
    ]
  end

  defp releases do
    [
      sovite: [
        include_executables_for: [:unix],
        applications: [sovite: :permanent, partisan: :load],
        # Also _build/prod/sovite-VERSION.tar.gz, for scripts/package.sh.
        steps: [:assemble, :tar]
      ]
    ]
  end

  defp dialyzer do
    [
      plt_local_path: "priv/plts",
      plt_core_path: "priv/plts",
      plt_add_apps: [:mix, :ex_unit, :iex, :partisan]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "ROADMAP.md",
        "STRUCTURE.md",
        "docs/configuration.md",
        "docs/logging.md",
        "docs/operations.md",
        "docs/security.md",
        "SECURITY.md"
      ],
      groups_for_modules: [
        Validators: [~r/^Sovite\.Validators/],
        IDNA: [~r/^Sovite\.IDNA/],
        Net: [~r/^Sovite\.Net/],
        Message: [~r/^Sovite\.Message/],
        DNS: [~r/^Sovite\.DNS/],
        LDAP: [~r/^Sovite\.LDAP/],
        SASL: [~r/^Sovite\.SASL/],
        "Proxy protocol": [~r/^Sovite\.ProxyProtocol/],
        Queue: [~r/^Sovite\.Queue/],
        Listener: [~r/^Sovite\.Listener/],
        SMTP: [~r/^Sovite\.SMTP/],
        TLS: [~r/^Sovite\.TLS/],
        Milter: [~r/^Sovite\.Milter/],
        Policy: [~r/^Sovite\.Policy/],
        Abuse: [~r/^Sovite\.Abuse/],
        "Email authentication": [
          ~r/^Sovite\.SPF/,
          ~r/^Sovite\.DKIM/,
          ~r/^Sovite\.DMARC/,
          ~r/^Sovite\.ARC/,
          ~r/^Sovite\.AuthResults/,
          ~r/^Sovite\.SRS/
        ],
        "Local delivery": [~r/^Sovite\.Maildir/, ~r/^Sovite\.Pipe/],
        DSN: [~r/^Sovite\.DSN/],
        Metrics: [~r/^Sovite\.Metrics/],
        Tracing: [~r/^Sovite\.Tracing/],
        Systemd: [~r/^Sovite\.Systemd/],
        Core: [~r/^Sovite\.Core/, Sovite]
      ]
    ]
  end
end

defmodule Mix.Tasks.Compile.PartisanOtp do
  @moduledoc false
  # Partisan makes its OTP behaviours (partisan_gen_server and the like)
  # from OTP's own modules in a rebar3 hook, which Mix's rebar3 build of
  # dependencies skips. This makes them, once, into Partisan's ebin.

  use Mix.Task.Compiler

  @impl Mix.Task.Compiler
  def run(_args) do
    ebin = Path.join(Mix.Project.build_path(), "lib/partisan/ebin")

    if File.exists?(Path.join(ebin, "partisan_gen_server.beam")) do
      {:noop, []}
    else
      case :partisan_gen_transform.generate_all(String.to_charlist(ebin)) do
        :ok -> {:ok, []}
        {:error, errors} -> Mix.raise("cannot make Partisan's OTP modules: #{inspect(errors)}")
      end
    end
  end
end
