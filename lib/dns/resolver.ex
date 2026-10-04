defmodule Sovite.DNS.Resolver do
  @moduledoc """
  Behaviour for DNS resolvers.

  Every component that needs DNS takes a resolver as a `{module, opts}`
  tuple, so callers can swap in a caching resolver, a DNSSEC-validating
  one, or a fake in tests. `Sovite.DNS.InetRes` is the default.

  ## Record data

  Each record type returns its data in this shape:

  | Type     | Data |
  |----------|------|
  | `:a`     | `:inet.ip4_address()` |
  | `:aaaa`  | `:inet.ip6_address()` |
  | `:mx`    | `{preference :: non_neg_integer(), exchange :: String.t()}` |
  | `:txt`   | `String.t()`, with the record's character strings joined |
  | `:ptr`   | `String.t()` |
  | `:cname` | `String.t()` |
  | `:tlsa`  | `{usage, selector, matching_type, data :: binary()}` (RFC 6698) |

  Domain names are returned without a trailing dot.

  ## Results

  An existing name with no records of the requested type (NODATA) returns
  `{:ok, []}`. A name that does not exist returns `{:error, :nxdomain}`.
  Callers often need to tell these apart, for example for implicit MX
  (RFC 5321 §5.1) or SPF `void` lookups (RFC 7208 §4.6.4).

  ## Authenticated data

  DANE (RFC 7672) may only trust records that DNSSEC has validated.
  Resolvers that can tell implement `lookup_secure/3`, which also says
  whether the answer was authenticated. `Sovite.DNS.lookup_secure/3`
  treats resolvers without it as never authenticated.
  """

  @type record_type :: :a | :aaaa | :mx | :txt | :ptr | :cname | :tlsa
  @type record_data ::
          :inet.ip_address()
          | {non_neg_integer(), String.t()}
          | String.t()
          | {byte(), byte(), byte(), binary()}
  @type error :: :nxdomain | :servfail | :timeout | :refused | :invalid_name | :other

  @callback lookup(name :: String.t(), type :: record_type(), opts :: keyword()) ::
              {:ok, [record_data()]} | {:error, error()}

  @doc """
  Like `c:lookup/3`, and also returns whether the answer was
  authenticated by DNSSEC.
  """
  @callback lookup_secure(name :: String.t(), type :: record_type(), opts :: keyword()) ::
              {:ok, [record_data()], authenticated :: boolean()} | {:error, error()}

  @optional_callbacks lookup_secure: 3
end
