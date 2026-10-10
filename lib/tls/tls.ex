defmodule Sovite.TLS do
  @moduledoc """
  TLS settings for mail servers and clients, following BCP 195 (RFC 9325).

  Only TLS 1.2 and 1.3 are enabled (RFC 8996). With TLS 1.2, only
  forward-secret AEAD cipher suites are allowed: ECDHE key exchange with
  AES-GCM or ChaCha20-Poly1305. TLS 1.3 suites are all AEAD. The server
  picks the cipher, and renegotiation started by the client is refused.

  These functions return option lists for `:ssl`. Certificates come from
  a `Sovite.TLS.CertStore`, or are given directly.

  Other parts of the TLS component:

    * `Sovite.TLS.Certificate` - loads certificate chains and keys.
    * `Sovite.TLS.CertStore` - certificates by name, with SNI and reload.
    * `Sovite.TLS.DANE` - DANE TLSA verification for SMTP (RFC 7672).
    * `Sovite.TLS.MTASTS` - MTA-STS policies (RFC 8461): discovery,
      fetching, MX matching, and `Sovite.TLS.MTASTS.Server` to serve
      them.
    * `Sovite.TLS.TLSRPT` - TLS reporting (RFC 8460): report
      destinations, the JSON report, and its delivery.
    * `Sovite.TLS.ACME` - obtains certificates from an ACME CA (RFC 8555).
  """

  @tls12_suites [
    ~c"ECDHE-ECDSA-AES128-GCM-SHA256",
    ~c"ECDHE-RSA-AES128-GCM-SHA256",
    ~c"ECDHE-ECDSA-AES256-GCM-SHA384",
    ~c"ECDHE-RSA-AES256-GCM-SHA384",
    ~c"ECDHE-ECDSA-CHACHA20-POLY1305",
    ~c"ECDHE-RSA-CHACHA20-POLY1305"
  ]

  @tls13_suites [
    ~c"TLS_AES_128_GCM_SHA256",
    ~c"TLS_AES_256_GCM_SHA384",
    ~c"TLS_CHACHA20_POLY1305_SHA256"
  ]

  @typedoc "Lowest TLS version to accept."
  @type min_version :: :"tlsv1.2" | :"tlsv1.3"

  @typedoc "What a handshake negotiated, for logs and `Received:` headers."
  @type info :: %{
          protocol: String.t(),
          cipher: String.t(),
          bits: pos_integer() | nil,
          sni: String.t() | nil
        }

  @doc """
  Returns the TLS versions from `min_version` up, newest first.

      iex> Sovite.TLS.versions(:"tlsv1.2")
      [:"tlsv1.3", :"tlsv1.2"]
  """
  @spec versions(min_version()) :: [:"tlsv1.3" | :"tlsv1.2", ...]
  def versions(:"tlsv1.2"), do: [:"tlsv1.3", :"tlsv1.2"]
  def versions(:"tlsv1.3"), do: [:"tlsv1.3"]

  @doc """
  Returns the default cipher suites for `min_version`, in order of
  preference, as OpenSSL names (TLS 1.2) and IANA names (TLS 1.3).
  """
  @spec default_ciphers(min_version()) :: [String.t()]
  def default_ciphers(:"tlsv1.3"), do: Enum.map(@tls13_suites, &List.to_string/1)

  def default_ciphers(:"tlsv1.2"),
    do: Enum.map(@tls13_suites ++ @tls12_suites, &List.to_string/1)

  @doc """
  Converts cipher suite names to `:ssl` suites. Accepts OpenSSL names
  (`"ECDHE-RSA-AES128-GCM-SHA256"`) and IANA names
  (`"TLS_AES_128_GCM_SHA256"`). Returns `{:error, {:unknown_cipher, name}}`
  for a name this system does not support, and `{:error, {:weak_cipher,
  name}}` for one without forward secrecy or an AEAD cipher.
  """
  @spec ciphers([String.t()]) :: {:ok, [:ssl.erl_cipher_suite()]} | {:error, term()}
  def ciphers(names) do
    Enum.reduce_while(names, {:ok, []}, fn name, {:ok, acc} ->
      case cipher(name) do
        {:ok, suite} -> {:cont, {:ok, [suite | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, suites} -> {:ok, Enum.reverse(suites)}
      error -> error
    end
  end

  defp cipher(name) do
    charlist = String.to_charlist(name)

    suite =
      try do
        :ssl.str_to_suite(charlist)
      rescue
        _ -> {:error, :unknown}
      end

    cond do
      not is_map(suite) or suite not in all_suites() -> {:error, {:unknown_cipher, name}}
      not strong?(suite) -> {:error, {:weak_cipher, name}}
      true -> {:ok, suite}
    end
  end

  defp all_suites do
    :ssl.cipher_suites(:all, :"tlsv1.3") ++ :ssl.cipher_suites(:all, :"tlsv1.2")
  end

  # TLS 1.3 suites have key_exchange :any; all of them are AEAD.
  defp strong?(%{key_exchange: kex, cipher: cipher}) do
    kex in [:any, :ecdhe_ecdsa, :ecdhe_rsa] and
      cipher in [:aes_128_gcm, :aes_256_gcm, :chacha20_poly1305]
  end

  @doc """
  Returns `:ssl` server options.

  ## Options

    * `:certs_keys` - the default certificates, as for `:ssl`: a list of
      `%{cert: [der], key: {type, der}}`. Required.
    * `:sni_fun` - picks certificates by server name, see `:ssl`.
    * `:min_version` - `:"tlsv1.2"` (default) or `:"tlsv1.3"`.
    * `:ciphers` - cipher suite names, see `ciphers/1`. Defaults to
      `default_ciphers/1`.
  """
  @spec server_options(keyword()) :: [:ssl.tls_server_option()]
  def server_options(opts) do
    min_version = Keyword.get(opts, :min_version, :"tlsv1.2")

    [
      certs_keys: Keyword.fetch!(opts, :certs_keys),
      versions: versions(min_version),
      ciphers: suites!(opts[:ciphers] || default_ciphers(min_version)),
      honor_cipher_order: true,
      secure_renegotiate: true,
      client_renegotiation: false,
      reuse_sessions: true,
      # Components emit telemetry; :ssl must not log handshake alerts.
      log_level: :none
    ] ++ if(opts[:sni_fun], do: [sni_fun: opts[:sni_fun]], else: [])
  end

  @doc """
  Returns `:ssl` client options.

  ## Options

    * `:verify` - `:none` (default) to encrypt without checking the
      certificate, or `:peer` to check it against `:cacerts` and
      `:hostname`.
    * `:hostname` - the server's name, sent with SNI and checked with
      `verify: :peer`. Leave it out for address literals.
    * `:cacerts` - trusted CA certificates (DER). Defaults to the system's
      (`:public_key.cacerts_get/0`).
    * `:min_version` - as in `server_options/1`.
    * `:ciphers` - as in `server_options/1`.
  """
  @spec client_options(keyword()) :: [:ssl.tls_client_option()]
  def client_options(opts) do
    min_version = Keyword.get(opts, :min_version, :"tlsv1.2")
    hostname = opts[:hostname] && String.to_charlist(opts[:hostname])

    base = [
      versions: versions(min_version),
      ciphers: suites!(opts[:ciphers] || default_ciphers(min_version)),
      log_level: :none,
      server_name_indication: hostname || :disable
    ]

    case Keyword.get(opts, :verify, :none) do
      :none ->
        [verify: :verify_none] ++ base

      :peer ->
        [
          verify: :verify_peer,
          cacerts: Keyword.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0),
          depth: 10,
          customize_hostname_check: [
            match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
          ]
        ] ++ base
    end
  end

  @doc """
  Makes `ssl` client options report the certificate problems the
  handshake finds. Each one is sent to `pid` as `{:tls_verify, ref,
  reason}`: an `:ssl` bad-certificate reason such as `:unknown_ca`,
  `:cert_expired`, or `:hostname_check_failed`, or the `:fail` reason of
  the options' own `verify_fun` (such as `:dane_mismatch` from
  `Sovite.TLS.DANE`).

  With `enforce: false` the problems do not stop the handshake: they are
  only reported. That is MTA-STS testing mode (RFC 8461 §5), and what
  TLS-RPT (RFC 8460) collects. Options without `verify: :verify_peer`
  are returned unchanged.
  """
  @spec report_verify([:ssl.tls_client_option()], {pid(), reference()}, keyword()) ::
          [:ssl.tls_client_option()]
  def report_verify(ssl, {pid, ref}, opts \\ []) do
    if Keyword.get(ssl, :verify) == :verify_peer do
      enforce = Keyword.get(opts, :enforce, true)
      {fun, user_state} = Keyword.get(ssl, :verify_fun, {&default_verify/3, []})
      reporting = &reported(fun.(&1, &2, &3), &3, {pid, ref}, enforce)
      Keyword.put(ssl, :verify_fun, {reporting, user_state})
    else
      ssl
    end
  end

  defp reported({:fail, reason}, state, {pid, ref}, enforce) do
    send(pid, {:tls_verify, ref, reason})
    if enforce, do: {:fail, reason}, else: {:valid, state}
  end

  defp reported(result, _state, _report_to, _enforce), do: result

  # What :ssl does without a verify_fun.
  defp default_verify(_cert, {:bad_cert, reason}, _state), do: {:fail, reason}
  defp default_verify(_cert, {:extension, _}, state), do: {:unknown, state}
  defp default_verify(_cert, _valid_or_valid_peer, state), do: {:valid, state}

  defp suites!(names) do
    case ciphers(names) do
      {:ok, suites} -> suites
      {:error, reason} -> raise ArgumentError, "invalid cipher list: #{inspect(reason)}"
    end
  end

  @doc """
  Returns what the handshake on `socket` negotiated.

  `protocol` is `"TLSv1.3"` or `"TLSv1.2"`, and `cipher` the IANA suite
  name. `sni` is the name the client asked for, on servers.
  """
  @spec info(:ssl.sslsocket()) :: {:ok, info()} | {:error, term()}
  def info(socket) do
    with {:ok, props} <-
           :ssl.connection_information(socket, [:protocol, :selected_cipher_suite, :sni_hostname]) do
      suite = Keyword.get(props, :selected_cipher_suite)

      {:ok,
       %{
         protocol: props |> Keyword.get(:protocol) |> protocol_name(),
         cipher: suite |> :ssl.suite_to_str() |> List.to_string(),
         bits: bits(suite),
         sni: props |> Keyword.get(:sni_hostname) |> sni()
       }}
    end
  end

  defp protocol_name(:"tlsv1.3"), do: "TLSv1.3"
  defp protocol_name(:"tlsv1.2"), do: "TLSv1.2"
  defp protocol_name(other), do: to_string(other)

  defp bits(%{cipher: :aes_128_gcm}), do: 128
  defp bits(%{cipher: cipher}) when cipher in [:aes_256_gcm, :chacha20_poly1305], do: 256
  defp bits(_suite), do: nil

  defp sni(name) when is_list(name), do: List.to_string(name)
  defp sni(_), do: nil

  @doc """
  Formats `info` the way `Received:` headers and logs show it.

      iex> Sovite.TLS.describe(%{protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", bits: 256, sni: nil})
      "TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)"
  """
  @spec describe(info()) :: String.t()
  def describe(%{protocol: protocol, cipher: cipher} = info) do
    bits = if info[:bits], do: " (#{info.bits}/#{info.bits} bits)", else: ""
    "#{protocol} with cipher #{cipher}#{bits}"
  end

  @doc "Formats an `:ssl` error reason as text."
  @spec format_error(term()) :: String.t()
  def format_error({:tls_alert, {_alert, description}}), do: to_string(description)
  def format_error({:options, option}), do: "invalid TLS option #{inspect(option)}"
  def format_error(:timeout), do: "timeout"
  def format_error(:closed), do: "connection closed"
  def format_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  def format_error(reason), do: inspect(reason)
end
