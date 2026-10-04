defmodule Sovite.MixProject do
  use Mix.Project

  def project do
    [
      app: :sovite,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
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
      {:telemetry, "~> 1.4"},
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
      setup: ["deps.get", "cmd git config core.hooksPath .githooks"],
      lint: [
        "format --check-formatted",
        "compile --warnings-as-errors --force",
        "credo --strict",
        "xref graph --format cycles --fail-above 0"
      ]
    ]
  end

  defp releases do
    [
      sovite: [
        include_executables_for: [:unix],
        applications: [sovite: :permanent]
      ]
    ]
  end

  defp dialyzer do
    [
      plt_local_path: "priv/plts",
      plt_core_path: "priv/plts",
      plt_add_apps: [:mix, :ex_unit]
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
        "docs/security.md",
        "SECURITY.md"
      ],
      groups_for_modules: [
        Validators: [~r/^Sovite\.Validators/],
        Net: [~r/^Sovite\.Net/],
        Message: [~r/^Sovite\.Message/],
        DNS: [~r/^Sovite\.DNS/],
        LDAP: [~r/^Sovite\.LDAP/],
        SASL: [~r/^Sovite\.SASL/],
        Queue: [~r/^Sovite\.Queue/],
        Listener: [~r/^Sovite\.Listener/],
        SMTP: [~r/^Sovite\.SMTP/],
        TLS: [~r/^Sovite\.TLS/],
        Abuse: [~r/^Sovite\.Abuse/],
        "Local delivery": [~r/^Sovite\.Maildir/, ~r/^Sovite\.Pipe/],
        DSN: [~r/^Sovite\.DSN/],
        Core: [~r/^Sovite\.Core/, Sovite]
      ]
    ]
  end
end
