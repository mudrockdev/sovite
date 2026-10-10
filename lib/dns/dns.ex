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

  @doc """
  Looks up records and whether DNSSEC authenticated them. Resolvers
  without `c:Sovite.DNS.Resolver.lookup_secure/3` never authenticate.
  """
  @spec lookup_secure(resolver(), String.t(), Resolver.record_type()) ::
          {:ok, [Resolver.record_data()], boolean()} | {:error, Resolver.error()}
  def lookup_secure({module, opts}, name, type) when is_binary(name) do
    Code.ensure_loaded(module)

    if function_exported?(module, :lookup_secure, 3) do
      module.lookup_secure(name, type, opts)
    else
      with {:ok, records} <- module.lookup(name, type, opts), do: {:ok, records, false}
    end
  end

  @doc """
  Returns whether `resolver` validates DNSSEC, by asking for the root
  zone's NS records, which are signed: a validating resolver that is
  trusted authenticates them. DANE (RFC 7672) needs one.
  """
  @spec validating?(resolver()) :: {:ok, boolean()} | {:error, Resolver.error()}
  def validating?(resolver) do
    with {:ok, _records, authenticated} <- lookup_secure(resolver, ".", :ns),
         do: {:ok, authenticated}
  end
end
