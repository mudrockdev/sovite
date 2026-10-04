defmodule Sovite.DNS do
  @moduledoc """
  DNS lookups through a pluggable `Sovite.DNS.Resolver`.
  """

  alias Sovite.DNS.Resolver

  @typedoc "A resolver module and the options passed to it on every lookup."
  @type resolver :: {module(), keyword()}

  @doc "Returns the default resolver: `Sovite.DNS.InetRes` with no options."
  @spec default_resolver() :: resolver()
  def default_resolver, do: {Sovite.DNS.InetRes, []}

  @doc """
  Looks up records of `type` for `name` with the given `resolver`.

  See `Sovite.DNS.Resolver` for the data each record type returns.
  """
  @spec lookup(resolver(), String.t(), Resolver.record_type()) ::
          {:ok, [Resolver.record_data()]} | {:error, Resolver.error()}
  def lookup({module, opts}, name, type) when is_binary(name) do
    module.lookup(name, type, opts)
  end
end
