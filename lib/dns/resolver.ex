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

  Domain names are returned without a trailing dot.

  ## Results

  An existing name with no records of the requested type (NODATA) returns
  `{:ok, []}`. A name that does not exist returns `{:error, :nxdomain}`.
  Callers often need to tell these apart, for example for implicit MX
  (RFC 5321 §5.1) or SPF `void` lookups (RFC 7208 §4.6.4).
  """

  @type record_type :: :a | :aaaa | :mx | :txt | :ptr | :cname
  @type record_data ::
          :inet.ip_address() | {non_neg_integer(), String.t()} | String.t()
  @type error :: :nxdomain | :servfail | :timeout | :refused | :invalid_name | :other

  @callback lookup(name :: String.t(), type :: record_type(), opts :: keyword()) ::
              {:ok, [record_data()]} | {:error, error()}
end
