defmodule Sovite.Core.CLI.DNS do
  @moduledoc false
  # sovitectl commands for the DNS records a domain needs, and for DKIM
  # keys.

  import Sovite.Core.CLI.Helpers

  alias Sovite.Core.Config
  alias Sovite.DKIM.SigningKey
  alias Sovite.TLS.{Certificate, MTASTS}

  @usage """
    dns records DOMAIN               Print the SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and TLSA records DOMAIN needs
    dns check                        Check that the DNS resolver validates DNSSEC, as DANE needs
    dkim generate DOMAIN SELECTOR FILE [TYPE]
                                     Write a new DKIM private key to FILE and print its DNS record.
                                     TYPE: rsa (2048 bits, default), rsa:BITS, or ed25519
  """

  # TXT character strings hold at most 255 bytes (RFC 1035 §3.3).
  @max_string 255

  def usage, do: @usage
  def commands, do: ["dns", "dkim"]

  def run(["dns", "records", domain], path) do
    case Config.load(path) do
      {:ok, config} -> records(config, String.downcase(domain))
      {:error, errors} -> print_errors(path, errors)
    end
  end

  def run(["dns", "check"], path) do
    case Config.load(path) do
      {:ok, config} -> check(Config.resolver(config))
      {:error, errors} -> print_errors(path, errors)
    end
  end

  def run(["dkim", "generate", domain, selector, file | type], _path) do
    with {:ok, type, bits} <- key_type(type),
         true <- Sovite.Validators.domain?(domain) || fail("invalid domain #{domain}"),
         true <- selector?(selector) || fail("invalid selector #{selector}") do
      generate(String.downcase(domain), selector, file, type, bits)
    else
      :error -> :usage
      status -> status
    end
  end

  def run(_argv, _path), do: :usage

  defp check(resolver) do
    case Sovite.DNS.validating?(resolver) do
      {:ok, true} ->
        IO.puts("The DNS resolver validates DNSSEC: DANE can be used.")
        0

      {:ok, false} ->
        IO.puts(
          "The DNS resolver does not validate DNSSEC, or is not on this host, so its\n" <>
            "answers are not trusted: DANE will not be used. Run a validating resolver\n" <>
            "such as Unbound on 127.0.0.1, and set [dns] nameservers if it is not the\n" <>
            "system's."
        )

        1

      {:error, reason} ->
        fail("cannot query the DNS resolver: #{reason}")
    end
  end

  defp print_errors(path, errors) do
    print_config_errors(path, errors)
    1
  end

  defp key_type([]), do: {:ok, :rsa, 2048}
  defp key_type(["rsa"]), do: {:ok, :rsa, 2048}
  defp key_type(["ed25519"]), do: {:ok, :ed25519, nil}

  defp key_type(["rsa:" <> bits]) do
    case Integer.parse(bits) do
      {bits, ""} when bits in 1024..8192 -> {:ok, :rsa, bits}
      _ -> :error
    end
  end

  defp key_type(_), do: :error

  defp selector?(selector),
    do:
      selector =~
        ~r/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\z/

  defp generate(domain, selector, file, type, bits) do
    pem = SigningKey.generate(type, bits || 2048)

    # The key is created private: never readable by others, not even briefly.
    with :ok <- create_private(file, pem),
         {:ok, key} <- SigningKey.from_pem(pem, domain, selector) do
      IO.puts("wrote #{file}\n")
      IO.puts("Publish this record:\n")
      print_record(SigningKey.dns_name(key), SigningKey.dns_record(key))

      IO.puts("""

      Then add the key to the config file:

        [[dkim.key]]
        domain = "#{domain}"
        selector = "#{selector}"
        file = "#{Path.expand(file)}"
      """)

      0
    else
      {:error, reason} when is_atom(reason) ->
        fail("cannot write #{file}: #{:file.format_error(reason)}")

      {:error, reason} ->
        fail(reason)
    end
  end

  defp create_private(file, data) do
    with {:ok, fd} <- :file.open(file, [:write, :exclusive, :raw, :binary]) do
      try do
        with :ok <- File.chmod(file, 0o600), do: :file.write(fd, data)
      after
        :file.close(fd)
      end
    end
  end

  defp records(config, domain) do
    hostname = config.server.hostname
    keys = Enum.filter(config.dkim.key, &(&1.domain == domain))

    IO.puts("; DNS records for #{domain}, sending and receiving through #{hostname}\n")

    IO.puts("; Mail exchanger")
    IO.puts("#{domain}. IN MX 10 #{hostname}.\n")

    IO.puts("; SPF (RFC 7208): the hosts that send mail for #{domain}")

    if config.delivery.relayhost,
      do:
        IO.puts(
          "; Mail goes out through #{config.delivery.relayhost.host}: include its SPF record too."
        )

    print_record(domain, spf(config))
    IO.puts("")

    IO.puts("; DKIM (RFC 6376): one record per key")
    dkim_records(keys, domain)

    IO.puts("; DMARC (RFC 7489): start with p=none, and move to quarantine and then")
    IO.puts("; reject once the aggregate reports show all your mail passes")
    print_record("_dmarc." <> domain, "v=DMARC1; p=none; rua=mailto:postmaster@#{domain}")
    IO.puts("")

    mta_sts(config, domain)
    IO.puts("; TLS-RPT (RFC 8460): where other servers report TLS problems")
    print_record("_smtp._tls." <> domain, "v=TLSRPTv1; rua=mailto:postmaster@#{domain}")
    tlsa(config)
    0
  end

  # The id is derived from the policy, so it changes exactly when the
  # policy does.
  defp mta_sts(config, domain) do
    mta_sts = config.mta_sts
    policy = MTASTS.policy_text(mta_sts.mode, mta_sts.mx, div(mta_sts.max_age, 1000))

    IO.puts("; MTA-STS (RFC 8461): the policy below, at #{MTASTS.policy_url(domain)}")

    if mta_sts.serve,
      do:
        IO.puts(
          "; Sovite serves it (mta_sts.serve): point mta-sts.#{domain} here, and add it to the certificate"
        ),
      else: IO.puts("; Serve it with a web server, or turn on mta_sts.serve")

    print_record("_mta-sts." <> domain, "v=STSv1; id=#{MTASTS.policy_id(policy)}")
    for line <- String.split(policy, "\r\n", trim: true), do: IO.puts(";   " <> line)
    IO.puts("")
  end

  # DANE-EE records for this server's own certificates (RFC 7672 §3.1.1).
  defp tlsa(config) do
    hostname = config.server.hostname

    records =
      for %{cert_file: cert, key_file: key} <- config.tls.certificate,
          {:ok, certificate} <- [Certificate.load(cert, key)],
          Certificate.matches?(certificate, hostname),
          do: spki_sha256(hd(certificate.chain))

    if records != [] do
      IO.puts("")
      IO.puts("; DANE (RFC 7672), in the zone of #{hostname}, only if it is signed with DNSSEC.")
      IO.puts("; Publish the record of a new key before using it.")

      for hash <- Enum.uniq(records),
          do: IO.puts("_25._tcp.#{hostname}. IN TLSA 3 1 1 #{Base.encode16(hash, case: :lower)}")
    end
  end

  defp spki_sha256(der) do
    {:Certificate, tbs, _alg, _sig} = :public_key.pkix_decode_cert(der, :plain)
    :crypto.hash(:sha256, :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7)))
  end

  defp spf(config) do
    addresses =
      Enum.map(config.delivery.source_address, fn
        {_, _, _, _} = ip -> "ip4:#{:inet.ntoa(ip)}"
        ip -> "ip6:#{:inet.ntoa(ip)}"
      end)

    Enum.join(["v=spf1", "a:#{config.server.hostname}" | addresses] ++ ["-all"], " ")
  end

  defp dkim_records([], domain) do
    IO.puts("; No [[dkim.key]] for #{domain}. Make one with:")
    IO.puts(";   sovitectl dkim generate #{domain} SELECTOR /etc/sovite/dkim/#{domain}.pem\n")
  end

  defp dkim_records(keys, _domain) do
    for key <- keys do
      if not key.sign,
        do:
          IO.puts(
            "; #{key.selector} does not sign: keep it published while mail signed with it may still be checked"
          )

      case key.signing_key do
        nil ->
          IO.puts("; #{key.selector}: cannot read #{key.file}")

        signing_key ->
          print_record(SigningKey.dns_name(signing_key), SigningKey.dns_record(signing_key))
      end
    end

    IO.puts("")
  end

  # Long values are split into several character strings, which
  # resolvers join again.
  defp print_record(name, value) do
    strings =
      value
      |> chunks()
      |> Enum.map_join(" ", &~s("#{&1}"))

    IO.puts("#{name}. IN TXT #{strings}")
  end

  defp chunks(value) when byte_size(value) > @max_string,
    do: [
      binary_part(value, 0, @max_string)
      | chunks(binary_part(value, @max_string, byte_size(value) - @max_string))
    ]

  defp chunks(value), do: [value]
end
