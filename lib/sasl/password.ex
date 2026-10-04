defmodule Sovite.SASL.Password do
  @moduledoc """
  Stored password hashes: creating them and checking passwords against
  them.

  Formats, compatible with Dovecot and `crypt(3)`:

    * `{SCRAM-SHA-256}iterations,salt,stored_key,server_key` (parts in
      base64) - the default. Works with `PLAIN`, `LOGIN`, and
      `SCRAM-SHA-256`.
    * `$6$[rounds=N$]salt$hash` (SHA512-CRYPT), also with a
      `{SHA512-CRYPT}` prefix.
    * `$5$[rounds=N$]salt$hash` (SHA256-CRYPT), also with a
      `{SHA256-CRYPT}` prefix.
    * `{PLAIN}password` - the password itself. Not recommended.

  Crypt hashes only work with `PLAIN` and `LOGIN`, since `SCRAM-SHA-256`
  needs values derived from the password in its own way.
  """

  alias Sovite.SASL

  @typedoc "Values a server needs for `SCRAM-SHA-256`, see `Sovite.SASL.ScramSHA256`."
  @type scram :: %{
          salt: binary(),
          iterations: pos_integer(),
          stored_key: binary(),
          server_key: binary()
        }

  @scram_iterations 4096
  @crypt_rounds 5000
  @itoa64 ~c"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  @doc """
  Hashes `password` for storage.

  Schemes: `:scram_sha256` (default; option `:iterations`, default
  4096), `:sha512_crypt`, and `:sha256_crypt` (option `:rounds`, default
  5000).
  """
  @spec hash(String.t(), :scram_sha256 | :sha512_crypt | :sha256_crypt, keyword()) ::
          String.t()
  def hash(password, scheme \\ :scram_sha256, opts \\ [])

  def hash(password, :scram_sha256, opts) do
    iterations = Keyword.get(opts, :iterations, @scram_iterations)
    scram = scram(password, :crypto.strong_rand_bytes(16), iterations)

    "{SCRAM-SHA-256}" <>
      Enum.join(
        [
          Integer.to_string(iterations),
          Base.encode64(scram.salt),
          Base.encode64(scram.stored_key),
          Base.encode64(scram.server_key)
        ],
        ","
      )
  end

  def hash(password, scheme, opts) when scheme in [:sha512_crypt, :sha256_crypt] do
    rounds = Keyword.get(opts, :rounds, @crypt_rounds)
    salt = for _ <- 1..16, into: "", do: <<Enum.random(@itoa64)>>
    {id, alg} = if scheme == :sha512_crypt, do: {"6", :sha512}, else: {"5", :sha256}
    rounds_part = if rounds == @crypt_rounds, do: "", else: "rounds=#{rounds}$"
    "$#{id}$#{rounds_part}#{salt}$" <> sha_crypt(password, salt, rounds, alg)
  end

  @doc """
  Checks `password` against a stored `hash`. Returns `{:error,
  :unsupported}` for a format this module does not know.
  """
  @spec verify(String.t(), String.t()) :: :ok | {:error, :mismatch | :unsupported}
  def verify(hash, password) do
    case parse(hash) do
      {:scram, stored} ->
        computed = scram(password, stored.salt, stored.iterations)
        result(SASL.secure_compare(computed.stored_key, stored.stored_key))

      {:crypt, alg, rounds, salt, expected} ->
        result(SASL.secure_compare(sha_crypt(password, salt, rounds, alg), expected))

      {:plain, stored} ->
        result(
          SASL.secure_compare(:crypto.hash(:sha256, password), :crypto.hash(:sha256, stored))
        )

      :error ->
        {:error, :unsupported}
    end
  end

  defp result(true), do: :ok
  defp result(false), do: {:error, :mismatch}

  @doc """
  Spends about as long as `verify/2` on a typical hash, then fails. Use it
  for unknown users, so response times do not reveal which users exist.
  """
  @spec dummy_verify(String.t()) :: {:error, :mismatch}
  def dummy_verify(password) do
    _ = scram(password, "sovite-dummy-salt", @scram_iterations)
    {:error, :mismatch}
  end

  @doc """
  Returns `SCRAM-SHA-256` values from a stored hash, if it has them:
  `{SCRAM-SHA-256}` hashes, and `{PLAIN}` ones (derived with a salt
  fixed per password, so the exchange is repeatable).
  """
  @spec scram_credentials(String.t()) :: {:ok, scram()} | :error
  def scram_credentials(hash) do
    case parse(hash) do
      {:scram, stored} ->
        {:ok, stored}

      {:plain, password} ->
        {:ok, scram(password, :crypto.hash(:sha256, "sovite" <> password), @scram_iterations)}

      _ ->
        :error
    end
  end

  @doc "Returns whether `hash` is in a known format."
  @spec supported?(String.t()) :: boolean()
  def supported?(hash), do: parse(hash) != :error

  @doc """
  Derives `SCRAM-SHA-256` values from a password (RFC 5802 §3). The
  password is prepared with `Sovite.SASL.saslprep/1` when possible.
  """
  @spec scram(String.t(), binary(), pos_integer()) :: scram()
  def scram(password, salt, iterations) do
    password =
      case SASL.saslprep(password) do
        {:ok, prepared} -> prepared
        :error -> password
      end

    salted = :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, 32)
    client_key = :crypto.mac(:hmac, :sha256, salted, "Client Key")

    %{
      salt: salt,
      iterations: iterations,
      stored_key: :crypto.hash(:sha256, client_key),
      server_key: :crypto.mac(:hmac, :sha256, salted, "Server Key")
    }
  end

  ## Parsing

  defp parse("{SCRAM-SHA-256}" <> rest) do
    with [iterations, salt, stored, server] <- String.split(rest, ","),
         {iterations, ""} when iterations in 1..10_000_000 <- Integer.parse(iterations),
         {:ok, salt} <- Base.decode64(salt),
         {:ok, <<_::binary-32>> = stored} <- Base.decode64(stored),
         {:ok, <<_::binary-32>> = server} <- Base.decode64(server) do
      {:scram, %{salt: salt, iterations: iterations, stored_key: stored, server_key: server}}
    else
      _ -> :error
    end
  end

  defp parse("{SHA512-CRYPT}" <> rest), do: parse_crypt(rest)
  defp parse("{SHA256-CRYPT}" <> rest), do: parse_crypt(rest)
  defp parse("{PLAIN}" <> password), do: {:plain, password}
  defp parse("$" <> _ = hash), do: parse_crypt(hash)
  defp parse(_hash), do: :error

  defp parse_crypt(hash) do
    with [_, id, rest] <- Regex.run(~r/\A\$([56])\$(.*)\z/s, hash),
         {:ok, rounds, rest} <- crypt_rounds(rest),
         [salt, expected] <- String.split(rest, "$"),
         true <- byte_size(salt) <= 16 do
      alg = if id == "6", do: :sha512, else: :sha256
      {:crypt, alg, rounds, salt, expected}
    else
      _ -> :error
    end
  end

  defp crypt_rounds("rounds=" <> rest) do
    with [digits, rest] <- String.split(rest, "$", parts: 2),
         {rounds, ""} <- Integer.parse(digits) do
      {:ok, rounds |> max(1000) |> min(999_999_999), rest}
    else
      _ -> :error
    end
  end

  defp crypt_rounds(rest), do: {:ok, @crypt_rounds, rest}

  ## SHA-crypt (https://www.akkadia.org/drepper/SHA-crypt.txt)

  defp sha_crypt(password, salt, rounds, alg) do
    size = if alg == :sha512, do: 64, else: 32
    h = &:crypto.hash(alg, &1)
    plen = byte_size(password)

    b = h.([password, salt, password])
    a = [password, salt, repeat(b, plen)]

    a =
      Enum.reduce(bits(plen), a, fn
        1, acc -> [acc, b]
        0, acc -> [acc, password]
      end)

    digest_a = h.(a)
    p_seq = repeat(h.(List.duplicate(password, plen)), plen)
    s_seq = repeat(h.(List.duplicate(salt, 16 + :binary.at(digest_a, 0))), byte_size(salt))

    c =
      Enum.reduce(0..(rounds - 1)//1, digest_a, fn i, c ->
        h.([
          if(rem(i, 2) == 1, do: p_seq, else: c),
          if(rem(i, 3) != 0, do: s_seq, else: []),
          if(rem(i, 7) != 0, do: p_seq, else: []),
          if(rem(i, 2) == 1, do: c, else: p_seq)
        ])
      end)

    encode(c, size)
  end

  # `block` repeated and cut to `length` bytes.
  defp repeat(block, length) do
    block
    |> List.duplicate(div(length, byte_size(block)) + 1)
    |> IO.iodata_to_binary()
    |> binary_part(0, length)
  end

  # The bits of `n`, least significant first.
  defp bits(0), do: []
  defp bits(n), do: [Bitwise.band(n, 1) | bits(Bitwise.bsr(n, 1))]

  defp encode(c, 64) do
    groups =
      for k <- 0..20 do
        case rem(k, 3) do
          0 -> {k, k + 21, k + 42}
          1 -> {k + 21, k + 42, k}
          2 -> {k + 42, k, k + 21}
        end
      end

    IO.iodata_to_binary([Enum.map(groups, &b64(c, &1, 4)), b64(c, {nil, nil, 63}, 2)])
  end

  defp encode(c, 32) do
    groups =
      for k <- 0..9 do
        case rem(k, 3) do
          0 -> {k, k + 10, k + 20}
          1 -> {k + 20, k, k + 10}
          2 -> {k + 10, k + 20, k}
        end
      end

    IO.iodata_to_binary([Enum.map(groups, &b64(c, &1, 4)), b64(c, {nil, 31, 30}, 3)])
  end

  defp b64(c, {i2, i1, i0}, n) do
    w = Bitwise.bsl(byte(c, i2), 16) + Bitwise.bsl(byte(c, i1), 8) + byte(c, i0)

    for i <- 0..(n - 1),
        do: Enum.at(@itoa64, w |> Bitwise.bsr(6 * i) |> Bitwise.band(63))
  end

  defp byte(_c, nil), do: 0
  defp byte(c, i), do: :binary.at(c, i)
end
