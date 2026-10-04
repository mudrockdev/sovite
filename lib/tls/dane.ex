defmodule Sovite.TLS.DANE do
  @moduledoc """
  DANE certificate verification for SMTP (RFC 6698, RFC 7671, RFC 7672).

  A TLSA record is `{usage, selector, matching_type, data}`:

    * usage `3` (DANE-EE) - the server's own certificate or key. Its
      name, dates, and issuer are not checked (RFC 7672 §3.1.1).
    * usage `2` (DANE-TA) - a CA certificate or key in the chain the
      server sends; the chain from it must be valid for the server's
      name.
    * usages `0` and `1` (PKIX-TA, PKIX-EE) are not used for SMTP (RFC
      7672 §3.1.3) and are ignored.
    * selector `0` matches the whole certificate, `1` its public key.
    * matching type `0` is the exact data, `1` SHA-256, `2` SHA-512.

  Only records from a DNSSEC-authenticated answer may be used: see
  `Sovite.DNS.lookup_secure/3`.
  """

  @type tlsa :: {usage :: byte(), selector :: byte(), matching_type :: byte(), data :: binary()}

  @doc """
  Keeps the records usable for SMTP: DANE-TA and DANE-EE, with a known
  selector and matching type, and data of the right length. If none is
  left, DANE does not apply and the client falls back to opportunistic
  TLS (RFC 7672 §2.2).
  """
  @spec usable([tlsa()]) :: [tlsa()]
  def usable(records) do
    Enum.filter(records, fn
      {usage, selector, 1, <<_::binary-32>>} when usage in [2, 3] and selector in [0, 1] -> true
      {usage, selector, 2, <<_::binary-64>>} when usage in [2, 3] and selector in [0, 1] -> true
      {usage, selector, 0, data} when usage in [2, 3] and selector in [0, 1] -> data != ""
      _ -> false
    end)
  end

  @doc "Returns whether the DER certificate `cert` matches `record`."
  @spec matches?(binary(), tlsa()) :: boolean()
  def matches?(cert, {_usage, selector, matching, data}) do
    case select(cert, selector) do
      nil -> false
      selected -> Sovite.SASL.secure_compare(digest(selected, matching), data)
    end
  end

  defp select(cert, 0), do: cert

  defp select(cert, 1) do
    {:Certificate, tbs, _alg, _sig} = :public_key.pkix_decode_cert(cert, :plain)
    :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7))
  rescue
    _ -> nil
  end

  defp digest(data, 0), do: data
  defp digest(data, 1), do: :crypto.hash(:sha256, data)
  defp digest(data, 2), do: :crypto.hash(:sha512, data)

  @doc """
  Returns `:ssl` client options that accept a server only if its
  certificate chain matches one of `records` (already filtered with
  `usable/1`). `hostname` is the name the chain must be valid for with
  DANE-TA, normally the MX host name. `tls` is passed to
  `Sovite.TLS.client_options/1` (`:min_version`, `:ciphers`).
  """
  @spec client_options([tlsa(), ...], String.t(), keyword()) :: [:ssl.tls_client_option()]
  def client_options(records, hostname, tls \\ []) do
    {ta, ee} = Enum.split_with(records, &(elem(&1, 0) == 2))
    base = Sovite.TLS.client_options(Keyword.merge(tls, verify: :none, hostname: hostname))

    Keyword.merge(base,
      verify: :verify_peer,
      cacerts: [],
      depth: 10,
      partial_chain: &trust_anchor(&1, ta),
      verify_fun: {&verify/3, %{ee: ee, provisional: false}}
    )
  end

  # A certificate in the chain matching a DANE-TA record becomes the
  # trust anchor for path validation.
  defp trust_anchor(chain, ta) do
    case Enum.find(chain, fn cert -> Enum.any?(ta, &matches?(cert, &1)) end) do
      nil -> :unknown_ca
      cert -> {:trusted_ca, cert}
    end
  end

  # Called for each certificate in the path, root first, then the peer.
  defp verify(_cert, {:extension, _}, state), do: {:unknown, state}
  defp verify(_cert, :valid, state), do: {:valid, state}

  # The chain validated. From a DANE-TA anchor that is enough; after a
  # provisional "unknown CA" only a DANE-EE match is.
  defp verify(_cert, :valid_peer, %{provisional: false} = state), do: {:valid, state}

  defp verify(cert, :valid_peer, state) do
    if ee_match?(cert, state), do: {:valid, state}, else: {:fail, :dane_mismatch}
  end

  defp verify(cert, {:bad_cert, reason}, state) do
    cond do
      ee_match?(cert, state) -> {:valid, state}
      reason == :unknown_ca and state.ee != [] -> {:valid, %{state | provisional: true}}
      true -> {:fail, reason}
    end
  end

  defp ee_match?(cert, %{ee: ee}) when ee != [] do
    der = :public_key.pkix_encode(:OTPCertificate, cert, :otp)
    Enum.any?(ee, &matches?(der, &1))
  end

  defp ee_match?(_cert, _state), do: false
end
