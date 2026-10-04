defmodule Sovite.MixProject do
  use Mix.Project

  def project do
    [
      app: :sovite,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "A modern, secure Mail Transfer Agent written in Elixir/OTP.",
      package: package(),
      source_url: "https://github.com/mudrockdev/sovite",
      docs: [main: "readme", extras: ["README.md"]]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp package do
    [
      licenses: ["AGPL-3.0"],
      links: %{"GitHub" => "https://github.com/mudrockdev/sovite"},
      files: ~w(lib mix.exs README.md LICENSE*)
    ]
  end

  defp deps do
    [{:ex_doc, "~> 0.34", only: :dev, runtime: false}]
  end
end
