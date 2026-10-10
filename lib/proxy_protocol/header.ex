defmodule Sovite.ProxyProtocol.Header do
  @moduledoc """
  A parsed PROXY protocol header, see `Sovite.ProxyProtocol`.

    * `:version` - `1` or `2`.
    * `:command` - `:proxy`, or `:local` for a connection the proxy made
      itself, such as a health check. A `:local` header carries no
      addresses: the receiver uses the real connection endpoints.
    * `:transport` - `:tcp4`, `:tcp6`, `:udp4`, `:udp6`, `:unix`,
      `:unix_dgram` (UNIX stream and datagram sockets), or `:unspec`
      (version 1 `UNKNOWN`, version 2 `AF_UNSPEC`, and every `:local`
      header).
    * `:source`, `:destination` - `{ip, port}`, or `{:local, path}` for
      UNIX sockets. `nil` with `:unspec`.
    * `:tlvs` - version 2 TLVs as `{type, value}`, in the order received,
      unknown types included. This is what `Sovite.ProxyProtocol.encode_v2/1`
      sends. Build well-known ones with `Sovite.ProxyProtocol.tlv/2`.

  The well-known TLVs among `:tlvs`, decoded (`nil` when absent):

    * `:alpn` - `PP2_TYPE_ALPN`, the negotiated application protocol,
      such as `"h2"`.
    * `:authority` - `PP2_TYPE_AUTHORITY`, the host name the client
      asked for, usually the TLS SNI.
    * `:unique_id` - `PP2_TYPE_UNIQUE_ID`, an opaque connection ID of up
      to 128 bytes.
    * `:ssl` - `PP2_TYPE_SSL`, see `t:ssl/0`.
    * `:netns` - `PP2_TYPE_NETNS`, the network namespace name.

  `PP2_TYPE_CRC32C` is checked by `Sovite.ProxyProtocol.parse/2` and
  `PP2_TYPE_NOOP` is padding; both stay in `:tlvs` only.
  """

  @typedoc "A transport protocol and address family."
  @type transport :: :tcp4 | :tcp6 | :udp4 | :udp6 | :unix | :unix_dgram | :unspec

  @typedoc "An endpoint: an IP address and port, or a UNIX socket path."
  @type address :: {:inet.ip_address(), :inet.port_number()} | {:local, binary()}

  @typedoc "A version 2 TLV."
  @type tlv :: {type :: 0..255, value :: binary()}

  @typedoc """
  What a TLS-terminating proxy knew about the client connection
  (`PP2_TYPE_SSL`):

    * `:client` - which of `PP2_CLIENT_SSL` (`:ssl`, the client used
      TLS), `PP2_CLIENT_CERT_CONN` (`:cert_conn`, it sent a certificate
      on this connection), and `PP2_CLIENT_CERT_SESS` (`:cert_sess`, it
      sent one in this TLS session) are set.
    * `:verify` - `0` if the client certificate was presented and
      verified, nonzero otherwise.
    * `:version`, `:cn`, `:cipher`, `:sig_alg`, `:key_alg` - the
      `PP2_SUBTYPE_SSL_*` sub-TLVs: TLS version (`"TLSv1.3"`), client
      certificate common name, cipher, certificate signature and key
      algorithms. `nil` when absent.
    * `:tlvs` - all sub-TLVs, in the order received.
  """
  @type ssl :: %{
          client: [:ssl | :cert_conn | :cert_sess],
          verify: non_neg_integer(),
          version: String.t() | nil,
          cn: String.t() | nil,
          cipher: String.t() | nil,
          sig_alg: String.t() | nil,
          key_alg: String.t() | nil,
          tlvs: [tlv()]
        }

  @type t :: %__MODULE__{
          version: 1 | 2,
          command: :proxy | :local,
          transport: transport(),
          source: address() | nil,
          destination: address() | nil,
          tlvs: [tlv()],
          alpn: binary() | nil,
          authority: String.t() | nil,
          unique_id: binary() | nil,
          ssl: ssl() | nil,
          netns: String.t() | nil
        }

  defstruct version: 2,
            command: :proxy,
            transport: :unspec,
            source: nil,
            destination: nil,
            tlvs: [],
            alpn: nil,
            authority: nil,
            unique_id: nil,
            ssl: nil,
            netns: nil
end
